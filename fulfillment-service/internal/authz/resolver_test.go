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
	"slices"
	"testing"

	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/osac-project/osac/fulfillment-service/internal/authz/catalog"
	"github.com/osac-project/osac/fulfillment-service/internal/collections"
	"github.com/osac-project/osac/fulfillment-service/internal/database/dao"
	privatev1 "github.com/osac-project/osac/proto/gen/osac/private/v1"
)

type stubStore struct {
	bindings   []*privatev1.RoleBinding
	roles      map[string]*privatev1.Role
	users      map[string]*privatev1.User
	roleIDs    []string
	listErr    error
	roleErr    error
	failRoleID string
	userErr    error
}

func (s *stubStore) ListBindings(_ context.Context, _ string, offset, limit int32) ([]*privatev1.RoleBinding, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	if offset >= int32(len(s.bindings)) {
		return nil, nil
	}
	end := min(offset+limit, int32(len(s.bindings)))
	return s.bindings[offset:end], nil
}

func (s *stubStore) GetRole(_ context.Context, id string) (*privatev1.Role, error) {
	s.roleIDs = append(s.roleIDs, id)
	if s.roleErr != nil && (s.failRoleID == "" || s.failRoleID == id) {
		return nil, s.roleErr
	}
	if role := s.roles[id]; role != nil {
		return role, nil
	}
	return nil, &dao.ErrNotFound{IDs: []string{id}}
}

func (s *stubStore) GetUser(_ context.Context, id string) (*privatev1.User, error) {
	if s.userErr != nil {
		return nil, s.userErr
	}
	if user := s.users[id]; user != nil {
		return user, nil
	}
	return nil, &dao.ErrNotFound{IDs: []string{id}}
}

func (s *stubStore) GetUserByName(_ context.Context, tenant, name string) (*privatev1.User, error) {
	if s.userErr != nil {
		return nil, s.userErr
	}
	for _, user := range s.users {
		if user.GetMetadata().GetTenant() == tenant && user.GetMetadata().GetName() == name &&
			user.GetMetadata().GetDeletionTimestamp() == nil {
			return user, nil
		}
	}
	return nil, &dao.ErrNotFound{IDs: []string{name}}
}

func testRole(id, name, service string, methods ...string) *privatev1.Role {
	return privatev1.Role_builder{Id: id,
		Metadata: privatev1.Metadata_builder{Name: name, Tenant: "shared"}.Build(),
		Spec: privatev1.RoleSpec_builder{Permissions: []*privatev1.PermissionRule{
			privatev1.PermissionRule_builder{Service: service, Methods: methods}.Build(),
		}}.Build(),
	}.Build()
}

func testBinding(id, tenant, roleID string, users []*privatev1.UserReference,
	accounts []*privatev1.ServiceAccountReference) *privatev1.RoleBinding {
	return privatev1.RoleBinding_builder{Id: id,
		Metadata: privatev1.Metadata_builder{Tenant: tenant}.Build(),
		Spec: privatev1.RoleBindingSpec_builder{
			Role:  privatev1.RoleReference_builder{Id: roleID, Name: "misleading-name"}.Build(),
			Users: users, ServiceAccounts: accounts,
		}.Build(),
	}.Build()
}

func TestResolveGrants(t *testing.T) {
	permissionCatalog, err := catalog.Build(protoregistry.GlobalFiles)
	if err != nil {
		t.Fatal(err)
	}
	store := &stubStore{roles: map[string]*privatev1.Role{
		"read": testRole("read", "reader", "osac.public.clusters", "get"),
		"all":  testRole("all", "creator", "osac.public.clusters", "*"),
	}, users: map[string]*privatev1.User{
		"user-id": privatev1.User_builder{
			Metadata: privatev1.Metadata_builder{Name: "alice", Tenant: "tenant-a"}.Build(),
			Spec:     privatev1.UserSpec_builder{Username: "alice"}.Build(),
		}.Build(),
	}}
	ref := []*privatev1.UserReference{privatev1.UserReference_builder{Id: "user-id"}.Build()}
	store.bindings = []*privatev1.RoleBinding{
		testBinding("b1", "tenant-a", "read", ref, nil),
		testBinding("b2", "tenant-a", "all", ref, nil),
		testBinding("b3", "tenant-b", "read", ref, nil),
		testBinding("b4", "tenant-a", "missing", ref, nil),
		testBinding("b5", "tenant-a", "all", nil, []*privatev1.ServiceAccountReference{
			privatev1.ServiceAccountReference_builder{Id: "service-id"}.Build(),
		}),
		testBinding("b6", "tenant-a", "read", []*privatev1.UserReference{
			privatev1.UserReference_builder{Name: "alice"}.Build(),
		}, nil),
	}
	resolver, err := NewResolver(store, permissionCatalog)
	if err != nil {
		t.Fatal(err)
	}
	user := Subject{Username: "alice", Tenants: collections.NewSet("tenant-a")}
	grants, err := resolver.Resolve(context.Background(), "tenant-a", user)
	if err != nil {
		t.Fatal(err)
	}
	if grants.Tenant != "tenant-a" || len(grants.Bindings) != 3 ||
		!slices.Contains(grants.Methods, "osac.public.v1.Clusters/Create") {
		t.Fatalf("unexpected tenant grants: %+v", grants)
	}
	if !slices.Equal(store.roleIDs, []string{"read", "all", "missing"}) {
		t.Fatalf("Roles must be retrieved by distinct IDs only: %v", store.roleIDs)
	}
	serviceGrants, err := resolver.Resolve(context.Background(), "tenant-a", Subject{
		ServiceAccountID: "service-id", Tenants: collections.NewSet("tenant-a"),
	})
	if err != nil || len(serviceGrants.Bindings) != 1 || serviceGrants.Bindings[0].BindingID != "b5" {
		t.Fatalf("service account grants: %+v, %v", serviceGrants, err)
	}
	store.roles["read"].GetSpec().SetPermissions([]*privatev1.PermissionRule{
		privatev1.PermissionRule_builder{Service: "osac.public.clusters", Methods: []string{"list"}}.Build(),
	})
	store.roles["all"].GetSpec().SetPermissions(nil)
	edited, err := resolver.Resolve(context.Background(), "tenant-a", user)
	if err != nil || !slices.Contains(edited.Methods, "osac.public.v1.Clusters/List") ||
		slices.Contains(edited.Methods, "osac.public.v1.Clusters/Get") {
		t.Fatalf("role edit was not reflected: %+v, %v", edited, err)
	}

	store.roleErr = errors.New("database failure")
	store.failRoleID = "missing"
	partial, err := resolver.Resolve(context.Background(), "tenant-a", user)
	if err == nil || partial != nil {
		t.Fatalf("database failure returned partial result: %+v, %v", partial, err)
	}
	store.roleErr = nil
	store.failRoleID = ""
	store.listErr = errors.New("database failure")
	partial, err = resolver.Resolve(context.Background(), "tenant-a", user)
	if err == nil || partial != nil {
		t.Fatalf("list failure returned partial result: %+v, %v", partial, err)
	}
	store.listErr = nil
	store.userErr = errors.New("database failure")
	partial, err = resolver.Resolve(context.Background(), "tenant-a", user)
	if err == nil || partial != nil {
		t.Fatalf("user lookup failure returned partial result: %+v, %v", partial, err)
	}
}

func TestResolveTenantIsolationAndDeletion(t *testing.T) {
	permissionCatalog, err := catalog.Build(protoregistry.GlobalFiles)
	if err != nil {
		t.Fatal(err)
	}
	userA := privatev1.User_builder{Metadata: privatev1.Metadata_builder{Tenant: "tenant-a"}.Build(),
		Spec: privatev1.UserSpec_builder{Username: "alice"}.Build()}.Build()
	userB := privatev1.User_builder{Metadata: privatev1.Metadata_builder{Tenant: "tenant-b"}.Build(),
		Spec: privatev1.UserSpec_builder{Username: "alice"}.Build()}.Build()
	role := testRole("read", "reader", "osac.public.clusters", "get")
	store := &stubStore{roles: map[string]*privatev1.Role{"read": role},
		users: map[string]*privatev1.User{"a": userA, "b": userB}}
	store.bindings = []*privatev1.RoleBinding{
		testBinding("foreign-id", "tenant-b", "read", []*privatev1.UserReference{
			privatev1.UserReference_builder{Id: "b"}.Build()}, nil),
		testBinding("wrong-user-id", "tenant-a", "read", []*privatev1.UserReference{
			privatev1.UserReference_builder{Id: "b"}.Build()}, nil),
		testBinding("wrong-user-scope", "tenant-a", "read", []*privatev1.UserReference{
			privatev1.UserReference_builder{Name: "alice", Tenant: "tenant-b"}.Build()}, nil),
		testBinding("shared-user-scope", "tenant-a", "read", []*privatev1.UserReference{
			privatev1.UserReference_builder{Name: "alice", Shared: true}.Build()}, nil),
		testBinding("valid", "tenant-a", "read", []*privatev1.UserReference{
			privatev1.UserReference_builder{Id: "a"}.Build()}, nil),
	}
	resolver, err := NewResolver(store, permissionCatalog)
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Username: "alice", Tenants: collections.NewSet("tenant-a")}
	for _, tenant := range []string{"", "tenant-b"} {
		if grants, resolveErr := resolver.Resolve(context.Background(), tenant, subject); resolveErr == nil || grants != nil {
			t.Fatalf("unverified tenant %q returned grants: %+v, %v", tenant, grants, resolveErr)
		}
	}
	for _, invalid := range []Subject{
		{Tenants: collections.NewSet("tenant-a")},
		{Username: "alice", ServiceAccountID: "service-id", Tenants: collections.NewSet("tenant-a")},
	} {
		if grants, resolveErr := resolver.Resolve(context.Background(), "tenant-a", invalid); resolveErr == nil || grants != nil {
			t.Fatalf("invalid subject returned grants: %+v, %v", grants, resolveErr)
		}
	}
	grants, err := resolver.Resolve(context.Background(), "tenant-a", subject)
	if err != nil || len(grants.Bindings) != 1 || grants.Bindings[0].BindingID != "valid" {
		t.Fatalf("cross-tenant user matched: %+v, %v", grants, err)
	}
	deleted := timestamppb.Now()
	store.bindings[4].GetMetadata().SetDeletionTimestamp(deleted)
	grants, err = resolver.Resolve(context.Background(), "tenant-a", subject)
	if err != nil || len(grants.Bindings) != 0 || len(grants.Methods) != 0 {
		t.Fatalf("deleting binding granted access: %+v, %v", grants, err)
	}
	store.bindings[4].GetMetadata().SetDeletionTimestamp(nil)
	role.GetMetadata().SetDeletionTimestamp(deleted)
	grants, err = resolver.Resolve(context.Background(), "tenant-a", subject)
	if err != nil || len(grants.Bindings) != 0 {
		t.Fatalf("deleting role granted access: %+v, %v", grants, err)
	}
	role.GetMetadata().SetDeletionTimestamp(nil)
	userA.GetMetadata().SetDeletionTimestamp(deleted)
	grants, err = resolver.Resolve(context.Background(), "tenant-a", subject)
	if err != nil || len(grants.Bindings) != 0 {
		t.Fatalf("deleting user granted access: %+v, %v", grants, err)
	}
}

func TestResolveNameOnlyUserRequiresActiveTenantRow(t *testing.T) {
	permissionCatalog, err := catalog.Build(protoregistry.GlobalFiles)
	if err != nil {
		t.Fatal(err)
	}
	user := privatev1.User_builder{Metadata: privatev1.Metadata_builder{Name: "alice-row", Tenant: "tenant-a"}.Build(),
		Spec: privatev1.UserSpec_builder{Username: "alice"}.Build()}.Build()
	store := &stubStore{
		roles: map[string]*privatev1.Role{"read": testRole("read", "reader", "osac.public.clusters", "get")},
		users: map[string]*privatev1.User{"alice-id": user},
		bindings: []*privatev1.RoleBinding{
			testBinding("name-only", "tenant-a", "read", []*privatev1.UserReference{
				privatev1.UserReference_builder{Name: "alice-row"}.Build(),
			}, nil),
		},
	}
	resolver, err := NewResolver(store, permissionCatalog)
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Username: "alice", Tenants: collections.NewSet("tenant-a")}
	grants, err := resolver.Resolve(context.Background(), "tenant-a", subject)
	if err != nil || len(grants.Bindings) != 1 {
		t.Fatalf("active name-only user did not match: %+v, %v", grants, err)
	}
	user.GetMetadata().SetDeletionTimestamp(timestamppb.Now())
	grants, err = resolver.Resolve(context.Background(), "tenant-a", subject)
	if err != nil || len(grants.Bindings) != 0 {
		t.Fatalf("deleted name-only user granted access: %+v, %v", grants, err)
	}
	if grants, resolveErr := resolver.Resolve(context.Background(), "tenant-b", Subject{
		ServiceAccountID: "service-id", Tenants: collections.NewSet("tenant-a"),
	}); resolveErr == nil || grants != nil {
		t.Fatalf("service account crossed tenants: %+v, %v", grants, resolveErr)
	}
}

func TestResolveSharedUserOnlyInSharedTenant(t *testing.T) {
	permissionCatalog, err := catalog.Build(protoregistry.GlobalFiles)
	if err != nil {
		t.Fatal(err)
	}
	store := &stubStore{
		roles: map[string]*privatev1.Role{"read": testRole("read", "reader", "osac.public.clusters", "get")},
		users: map[string]*privatev1.User{"shared-user": privatev1.User_builder{
			Metadata: privatev1.Metadata_builder{Name: "alice-row", Tenant: "shared"}.Build(),
			Spec:     privatev1.UserSpec_builder{Username: "alice"}.Build(),
		}.Build()},
		bindings: []*privatev1.RoleBinding{
			testBinding("tenant-binding", "tenant-a", "read", []*privatev1.UserReference{
				privatev1.UserReference_builder{Id: "shared-user"}.Build(),
			}, nil),
			testBinding("shared-binding", "shared", "read", []*privatev1.UserReference{
				privatev1.UserReference_builder{Name: "alice-row", Shared: true}.Build(),
			}, nil),
		},
	}
	resolver, err := NewResolver(store, permissionCatalog)
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Username: "alice", Tenants: collections.NewSet("tenant-a", "shared")}
	tenantGrants, err := resolver.Resolve(context.Background(), "tenant-a", subject)
	if err != nil || len(tenantGrants.Bindings) != 0 {
		t.Fatalf("shared User granted tenant access: %+v, %v", tenantGrants, err)
	}
	sharedGrants, err := resolver.Resolve(context.Background(), "shared", subject)
	if err != nil || len(sharedGrants.Bindings) != 1 || sharedGrants.Bindings[0].BindingID != "shared-binding" {
		t.Fatalf("shared User did not match in shared tenant: %+v, %v", sharedGrants, err)
	}
}
