/*
Copyright (c) 2026 Red Hat Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License.
*/

package authz

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/osac-project/osac/fulfillment-service/internal/auth"
	"github.com/osac-project/osac/fulfillment-service/internal/authz/catalog"
	"github.com/osac-project/osac/fulfillment-service/internal/collections"
	"github.com/osac-project/osac/fulfillment-service/internal/database/dao"
	privatev1 "github.com/osac-project/osac/proto/gen/osac/private/v1"
)

const pageSize int32 = 100

// Subject identifies one authenticated RoleBinding subject and its verified tenants.
type Subject struct {
	Username         string
	ServiceAccountID string
	Tenants          collections.Set[string]
}

// BindingGrant records the binding and Role that supplied a tenant's methods.
type BindingGrant struct {
	BindingID     string
	BindingTenant string
	RoleID        string
	RoleName      string
	RoleTenant    string
	Rules         []*privatev1.PermissionRule
}

// Grants contains expanded methods for one tenant and their provenance.
type Grants struct {
	Tenant   string
	Methods  []string
	Bindings []BindingGrant
}

// Resolver reads bindings and referenced objects from the database. It is not an authorization evaluator.
type Resolver struct {
	store   Store
	catalog *catalog.Catalog
}

// Store supplies current rows to the resolver. GetRole must use the Role ID.
type Store interface {
	ListBindings(context.Context, string, int32, int32) ([]*privatev1.RoleBinding, error)
	GetRole(context.Context, string) (*privatev1.Role, error)
	GetUser(context.Context, string) (*privatev1.User, error)
	GetUserByName(context.Context, string, string) (*privatev1.User, error)
}

type DAOStore struct {
	Bindings *dao.GenericDAO[*privatev1.RoleBinding]
	Roles    *dao.GenericDAO[*privatev1.Role]
	Users    *dao.GenericDAO[*privatev1.User]
}

func (s DAOStore) ListBindings(ctx context.Context, tenant string, offset, limit int32) ([]*privatev1.RoleBinding, error) {
	filter := fmt.Sprintf("this.metadata.tenant == %q && this.metadata.deletion_timestamp == null", tenant)
	response, err := s.Bindings.List().SetFilter(filter).SetLimit(limit).SetOffset(offset).Do(ctx)
	if err != nil {
		return nil, err
	}
	return response.GetItems(), nil
}

func (s DAOStore) GetRole(ctx context.Context, id string) (*privatev1.Role, error) {
	response, err := s.Roles.Get().SetId(id).Do(ctx)
	if err != nil {
		return nil, err
	}
	return response.GetObject(), nil
}

func (s DAOStore) GetUser(ctx context.Context, id string) (*privatev1.User, error) {
	response, err := s.Users.Get().SetId(id).Do(ctx)
	if err != nil {
		return nil, err
	}
	return response.GetObject(), nil
}

func (s DAOStore) GetUserByName(ctx context.Context, tenant, name string) (*privatev1.User, error) {
	filter := fmt.Sprintf("this.metadata.tenant == %q && this.metadata.name == %q && this.metadata.deletion_timestamp == null",
		tenant, name)
	response, err := s.Users.List().SetFilter(filter).SetLimit(1).Do(ctx)
	if err != nil {
		return nil, err
	}
	if len(response.GetItems()) == 0 {
		return nil, &dao.ErrNotFound{IDs: []string{name}}
	}
	return response.GetItems()[0], nil
}

func NewResolver(store Store, permissionCatalog *catalog.Catalog) (*Resolver, error) {
	if store == nil || permissionCatalog == nil {
		return nil, errors.New("store and catalog are required")
	}
	return &Resolver{store: store, catalog: permissionCatalog}, nil
}

// Resolve computes grants for one verified subject in one tenant. Any database or catalog error discards the result.
func (r *Resolver) Resolve(ctx context.Context, tenant string, subject Subject) (*Grants, error) {
	if tenant == "" || !subject.Tenants.Contains(tenant) {
		return nil, errors.New("requested tenant must belong to the authenticated subject")
	}
	if (subject.Username == "") == (subject.ServiceAccountID == "") {
		return nil, errors.New("exactly one subject identifier is required")
	}
	result := &Grants{Tenant: tenant}
	methodsSet := make(map[string]struct{})
	roleMethods := make(map[string][]string)
	roles := make(map[string]*privatev1.Role)
	users := make(map[string]*privatev1.User)
	usersByName := make(map[string]*privatev1.User)

	// DAO visibility needs a subject even when resolution precedes the API authorization decision.
	// Additonally, project metadata does not scope grants: read all projects of the verified tenant.
	// The internal read-only context uses managed-service-account visibility for that tenant.
	name := subject.Username
	if name == "" {
		name = subject.ServiceAccountID
	}
	readCtx := auth.ContextWithSubject(ctx, &auth.Subject{
		User: name, Tenants: collections.NewSet(tenant), ManagedServiceAccount: true,
	})
	for offset := int32(0); ; offset += pageSize {
		page, err := r.store.ListBindings(readCtx, tenant, offset, pageSize)
		if err != nil {
			return nil, err
		}
		for _, binding := range page {
			if binding.GetMetadata().GetTenant() != tenant || binding.GetMetadata().GetDeletionTimestamp() != nil {
				continue
			}
			matches, err := r.matches(readCtx, binding, subject, users, usersByName)
			if err != nil {
				return nil, err
			}
			if !matches || binding.GetSpec().GetRole().GetId() == "" {
				continue
			}
			roleID := binding.GetSpec().GetRole().GetId()
			role, seen := roles[roleID]
			if !seen {
				role, err = r.store.GetRole(readCtx, roleID)
				if err != nil {
					if _, missing := errors.AsType[*dao.ErrNotFound](err); !missing {
						return nil, err
					}
					role = nil
				}
				roles[roleID] = role
			}
			if role == nil || role.GetMetadata().GetDeletionTimestamp() != nil {
				continue
			}
			roleTenant := role.GetMetadata().GetTenant()
			if roleTenant != tenant && roleTenant != auth.SharedTenant {
				continue
			}
			methods, expanded := roleMethods[roleID]
			if !expanded {
				for _, rule := range role.GetSpec().GetPermissions() {
					part, err := r.catalog.Expand(rule.GetService(), rule.GetMethods())
					if err != nil {
						return nil, fmt.Errorf("expand Role %q: %w", roleID, err)
					}
					methods = append(methods, part...)
				}
				roleMethods[roleID] = methods
			}
			for _, method := range methods {
				methodsSet[method] = struct{}{}
			}
			result.Bindings = append(result.Bindings, BindingGrant{
				BindingID: binding.GetId(), BindingTenant: tenant, RoleID: roleID,
				RoleName: role.GetMetadata().GetName(), RoleTenant: role.GetMetadata().GetTenant(),
				Rules: role.GetSpec().GetPermissions(),
			})
		}
		if len(page) < int(pageSize) {
			break
		}
	}
	result.Methods = slices.Sorted(maps.Keys(methodsSet))
	return result, nil
}

func (r *Resolver) matches(ctx context.Context, binding *privatev1.RoleBinding, subject Subject,
	users, usersByName map[string]*privatev1.User) (bool, error) {
	if subject.ServiceAccountID != "" {
		for _, ref := range binding.GetSpec().GetServiceAccounts() {
			if ref.GetId() == subject.ServiceAccountID {
				return true, nil
			}
		}
		return false, nil
	}
	tenant := binding.GetMetadata().GetTenant()
	for _, ref := range binding.GetSpec().GetUsers() {
		if (ref.GetTenant() != "" && ref.GetTenant() != tenant) || (ref.GetShared() && tenant != auth.SharedTenant) {
			continue
		}
		user, err := r.userForReference(ctx, tenant, ref, users, usersByName)
		if err != nil {
			return false, err
		}
		if user != nil && user.GetMetadata().GetTenant() == tenant &&
			user.GetMetadata().GetDeletionTimestamp() == nil && user.GetSpec().GetUsername() == subject.Username &&
			(ref.GetName() == "" || ref.GetName() == user.GetMetadata().GetName()) {
			return true, nil
		}
	}
	return false, nil
}

func (r *Resolver) userForReference(ctx context.Context, tenant string, ref *privatev1.UserReference,
	users, usersByName map[string]*privatev1.User) (*privatev1.User, error) {
	if ref.GetId() == "" && ref.GetName() == "" {
		return nil, nil
	}
	cache := users
	key := ref.GetId()
	lookup := func() (*privatev1.User, error) { return r.store.GetUser(ctx, key) }
	if key == "" {
		cache = usersByName
		key = ref.GetName()
		lookup = func() (*privatev1.User, error) { return r.store.GetUserByName(ctx, tenant, key) }
	}
	if user, known := cache[key]; known {
		return user, nil
	}
	user, err := lookup()
	if err != nil {
		if _, missing := errors.AsType[*dao.ErrNotFound](err); !missing {
			return nil, err
		}
	}
	cache[key] = user
	return user, nil
}
