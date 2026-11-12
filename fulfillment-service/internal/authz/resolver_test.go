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

	"github.com/osac-project/osac/fulfillment-service/internal/authz/catalog"
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

func (s *stubStore) ListBindings(_ context.Context, offset, limit int32) ([]*privatev1.RoleBinding, error) {
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
		"user-id": privatev1.User_builder{Spec: privatev1.UserSpec_builder{Username: "alice"}.Build()}.Build(),
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
	grants, err := resolver.Resolve(context.Background(), Subject{Username: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if len(grants.Bindings) != 4 || !slices.Contains(grants.MethodsByTenant["tenant-a"],
		"osac.public.v1.Clusters/Create") || slices.Contains(grants.MethodsByTenant["tenant-b"],
		"osac.public.v1.Clusters/Create") {
		t.Fatalf("unexpected tenant grants: %+v", grants)
	}
	if !slices.Equal(store.roleIDs, []string{"read", "all", "missing"}) {
		t.Fatalf("Roles must be retrieved by distinct IDs only: %v", store.roleIDs)
	}
	serviceGrants, err := resolver.Resolve(context.Background(), Subject{ServiceAccountID: "service-id"})
	if err != nil || len(serviceGrants.Bindings) != 1 || serviceGrants.Bindings[0].BindingID != "b5" {
		t.Fatalf("service account grants: %+v, %v", serviceGrants, err)
	}
	store.roles["read"].GetSpec().SetPermissions([]*privatev1.PermissionRule{
		privatev1.PermissionRule_builder{Service: "osac.public.clusters", Methods: []string{"list"}}.Build(),
	})
	edited, err := resolver.Resolve(context.Background(), Subject{Username: "alice"})
	if err != nil || !slices.Contains(edited.MethodsByTenant["tenant-b"], "osac.public.v1.Clusters/List") ||
		slices.Contains(edited.MethodsByTenant["tenant-b"], "osac.public.v1.Clusters/Get") {
		t.Fatalf("role edit was not reflected: %+v, %v", edited, err)
	}

	store.roleErr = errors.New("database failure")
	store.failRoleID = "missing"
	partial, err := resolver.Resolve(context.Background(), Subject{Username: "alice"})
	if err == nil || partial != nil {
		t.Fatalf("database failure returned partial result: %+v, %v", partial, err)
	}
	store.roleErr = nil
	store.failRoleID = ""
	store.listErr = errors.New("database failure")
	partial, err = resolver.Resolve(context.Background(), Subject{Username: "alice"})
	if err == nil || partial != nil {
		t.Fatalf("list failure returned partial result: %+v, %v", partial, err)
	}
	store.listErr = nil
	store.userErr = errors.New("database failure")
	partial, err = resolver.Resolve(context.Background(), Subject{Username: "alice"})
	if err == nil || partial != nil {
		t.Fatalf("user lookup failure returned partial result: %+v, %v", partial, err)
	}
}
