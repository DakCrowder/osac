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
	"github.com/osac-project/osac/fulfillment-service/internal/database/dao"
	privatev1 "github.com/osac-project/osac/proto/gen/osac/private/v1"
)

const pageSize int32 = 100

// Subject identifies exactly one kind of RoleBinding subject.
type Subject struct {
	Username         string
	ServiceAccountID string
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

// Grants contains expanded methods keyed by binding tenant and their provenance.
type Grants struct {
	MethodsByTenant map[string][]string
	Bindings        []BindingGrant
}

// Resolver reads bindings and referenced objects from the database. It is not an authorization evaluator.
type Resolver struct {
	store   Store
	catalog *catalog.Catalog
}

// Store supplies current rows to the resolver. GetRole must use the Role ID.
type Store interface {
	ListBindings(context.Context, int32, int32) ([]*privatev1.RoleBinding, error)
	GetRole(context.Context, string) (*privatev1.Role, error)
	GetUser(context.Context, string) (*privatev1.User, error)
}

type DAOStore struct {
	Bindings *dao.GenericDAO[*privatev1.RoleBinding]
	Roles    *dao.GenericDAO[*privatev1.Role]
	Users    *dao.GenericDAO[*privatev1.User]
}

func (s DAOStore) ListBindings(ctx context.Context, offset, limit int32) ([]*privatev1.RoleBinding, error) {
	response, err := s.Bindings.List().SetLimit(limit).SetOffset(offset).Do(ctx)
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

func NewResolver(store Store, permissionCatalog *catalog.Catalog) (*Resolver, error) {
	if store == nil || permissionCatalog == nil {
		return nil, errors.New("store and catalog are required")
	}
	return &Resolver{store: store, catalog: permissionCatalog}, nil
}

// Resolve computes grants from current rows. Any database or catalog error discards the entire result.
func (r *Resolver) Resolve(ctx context.Context, subject Subject) (*Grants, error) {
	if (subject.Username == "") == (subject.ServiceAccountID == "") {
		return nil, errors.New("exactly one subject identifier is required")
	}
	result := &Grants{MethodsByTenant: make(map[string][]string)}
	methodSets := make(map[string]map[string]struct{})
	roleMethods := make(map[string][]string)
	roles := make(map[string]*privatev1.Role)
	usernames := make(map[string]string)
	for offset := int32(0); ; offset += pageSize {
		page, err := r.store.ListBindings(ctx, offset, pageSize)
		if err != nil {
			return nil, err
		}
		for _, binding := range page {
			matches, err := r.matches(ctx, binding, subject, usernames)
			if err != nil {
				return nil, err
			}
			if !matches || binding.GetSpec().GetRole().GetId() == "" {
				continue
			}
			roleID := binding.GetSpec().GetRole().GetId()
			role, seen := roles[roleID]
			if !seen {
				role, err = r.store.GetRole(ctx, roleID)
				if err != nil {
					if _, missing := errors.AsType[*dao.ErrNotFound](err); !missing {
						return nil, err
					}
					role = nil
				}
				roles[roleID] = role
			}
			if role == nil {
				continue
			}
			tenant := binding.GetMetadata().GetTenant()
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
			if methodSets[tenant] == nil {
				methodSets[tenant] = make(map[string]struct{})
			}
			for _, method := range methods {
				methodSets[tenant][method] = struct{}{}
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
	for tenant, methods := range methodSets {
		result.MethodsByTenant[tenant] = slices.Sorted(maps.Keys(methods))
	}
	return result, nil
}

func (r *Resolver) matches(ctx context.Context, binding *privatev1.RoleBinding, subject Subject,
	usernames map[string]string) (bool, error) {
	if subject.ServiceAccountID != "" {
		for _, ref := range binding.GetSpec().GetServiceAccounts() {
			if ref.GetId() == subject.ServiceAccountID {
				return true, nil
			}
		}
		return false, nil
	}
	for _, ref := range binding.GetSpec().GetUsers() {
		if ref.GetId() == "" && ref.GetName() == subject.Username {
			return true, nil
		}
		if ref.GetId() == "" {
			continue
		}
		username, known := usernames[ref.GetId()]
		if !known {
			response, err := r.store.GetUser(ctx, ref.GetId())
			if err != nil {
				if _, missing := errors.AsType[*dao.ErrNotFound](err); !missing {
					return false, err
				}
			} else {
				username = response.GetSpec().GetUsername()
			}
			usernames[ref.GetId()] = username
		}
		if username == subject.Username {
			return true, nil
		}
	}
	return false, nil
}
