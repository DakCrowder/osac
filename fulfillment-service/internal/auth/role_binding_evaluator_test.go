/*
Copyright (c) 2026 Red Hat Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License.
*/

package auth

import (
	"context"
	"iter"
	"slices"
	"testing"

	"go.uber.org/mock/gomock"
	"google.golang.org/protobuf/reflect/protoregistry"

	"github.com/osac-project/osac/fulfillment-service/internal/authz"
	"github.com/osac-project/osac/fulfillment-service/internal/authz/catalog"
	"github.com/osac-project/osac/fulfillment-service/internal/database"
	privatev1 "github.com/osac-project/osac/proto/gen/osac/private/v1"
	publicv1 "github.com/osac-project/osac/proto/gen/osac/public/v1"
)

type evaluatorGrantStore struct {
	tenants        map[string][]authz.BindingGrant
	systemSubjects map[string][]authz.BindingGrant
}

func (s *evaluatorGrantStore) ListUserGrants(_ context.Context, tenant, _ string) iter.Seq2[authz.BindingGrant, error] {
	return evaluatorGrantResults(s.tenants[tenant])
}

func (s *evaluatorGrantStore) ListVerifiedUserGrants(ctx context.Context, tenant, username, subject string) iter.Seq2[authz.BindingGrant, error] {
	if tenant == SystemTenant {
		return evaluatorGrantResults(s.systemSubjects[subject])
	}
	return s.ListUserGrants(ctx, tenant, username)
}

func (*evaluatorGrantStore) ListServiceAccountGrants(context.Context, string, string) iter.Seq2[authz.BindingGrant, error] {
	panic("unexpected managed service account lookup")
}

func evaluatorGrantResults(grants []authz.BindingGrant) iter.Seq2[authz.BindingGrant, error] {
	return func(yield func(authz.BindingGrant, error) bool) {
		for _, grant := range grants {
			if !yield(grant, nil) {
				return
			}
		}
	}
}

func TestRoleBindingEvaluator(t *testing.T) {
	ctx := database.TxIntoContext(context.Background(), database.NewMockTx(gomock.NewController(t)))
	permissionCatalog, err := catalog.Build(protoregistry.GlobalFiles)
	if err != nil {
		t.Fatal(err)
	}
	store := &evaluatorGrantStore{
		tenants:        make(map[string][]authz.BindingGrant),
		systemSubjects: make(map[string][]authz.BindingGrant),
	}
	resolver, err := authz.NewResolver(store, permissionCatalog)
	if err != nil {
		t.Fatal(err)
	}
	evaluator := NewRoleBindingEvaluator(NewMockAuthorizationEvaluator(gomock.NewController(t)), resolver, "https://keycloak.test")
	identity := &AuthContext{
		AuthMethod: "jwt", Username: "alice", IdentitySubject: "verified-subject", ClientID: "osac-cli",
		Issuer: "https://keycloak.test",
		Groups: []any{"admins"}, RealmAccess: map[string]any{"roles": []any{"tenant-admin"}},
		Organization: map[string]any{"alpha": map[string]any{}, "beta": map[string]any{}},
	}
	check := func(method string, wantAllowed bool, wantTenants ...string) {
		t.Helper()
		decision, err := evaluator.Evaluate(ctx, identity, method)
		if err != nil || decision.Allowed != wantAllowed || !slices.Equal(decision.SubjectTenants, wantTenants) {
			t.Fatalf("Evaluate(%s) = %+v, %v, want allowed=%v tenants=%v", method, decision, err, wantAllowed, wantTenants)
		}
	}
	grant := func(id, service string, methods ...string) authz.BindingGrant {
		return authz.BindingGrant{RoleID: id, Rules: []*privatev1.PermissionRule{
			privatev1.PermissionRule_builder{Service: service, Methods: methods}.Build(),
		}}
	}

	t.Run("verified provider grant survives no group and revokes with the same identity", func(t *testing.T) {
		method := privatev1.Tenants_List_FullMethodName
		providerGrant := grant(authz.ProviderAdminRoleID, "*", "*")
		store.systemSubjects["another-user"] = []authz.BindingGrant{providerGrant}
		check(method, false)
		store.systemSubjects[identity.IdentitySubject] = []authz.BindingGrant{providerGrant}
		identity.Groups = nil
		check(method, true, "*")
		identity.Issuer = "https://other-trusted-issuer.test"
		check(method, false)
		identity.Issuer = "https://keycloak.test"
		store.systemSubjects[identity.IdentitySubject] = []authz.BindingGrant{
			grant(authz.ProviderAdminRoleID, "osac.public.tenants", "list"),
			grant("system-limited", "osac.private.tenants", "list"),
		}
		check(method, false)
		delete(store.systemSubjects, identity.IdentitySubject)
		check(method, false)
	})

	t.Run("ordinary grants and project administration stay scoped to their own tenant", func(t *testing.T) {
		store.tenants["alpha"] = []authz.BindingGrant{grant(authz.TenantAdminRoleID, "osac.public.projects", "delete")}
		store.tenants["beta"] = []authz.BindingGrant{grant("custom-manager", "osac.public.projects", "delete")}
		identity.ID = "stored-project"
		identity.Name = "project"
		identity.Tenant = "beta"
		check(publicv1.Projects_Delete_FullMethodName, false)
		identity.Tenant = "alpha"
		check(publicv1.Projects_Delete_FullMethodName, true, "alpha")
		identity.ID, identity.Name, identity.Tenant = "", "", ""
	})

	t.Run("reader role suppresses only the automatic onboarding grant", func(t *testing.T) {
		onboarding := grant("default-role", "osac.public.computeinstances", "create")
		onboarding.DefaultBinding = true
		store.tenants["beta"] = []authz.BindingGrant{
			onboarding, grant(authz.TenantReaderRoleID, "osac.public.computeinstances", "get"),
		}
		check(publicv1.ComputeInstances_Get_FullMethodName, true, "beta")
		check(publicv1.ComputeInstances_Create_FullMethodName, false)
		store.tenants["beta"] = append(store.tenants["beta"], grant("explicit", "osac.public.computeinstances", "create"))
		check(publicv1.ComputeInstances_Create_FullMethodName, true, "beta")
	})
}
