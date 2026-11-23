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
	"slices"
	"strings"

	"github.com/osac-project/osac/fulfillment-service/internal/authz"
	"github.com/osac-project/osac/fulfillment-service/internal/collections"
	"github.com/osac-project/osac/fulfillment-service/internal/database"
	privatev1 "github.com/osac-project/osac/proto/gen/osac/private/v1"
	publicv1 "github.com/osac-project/osac/proto/gen/osac/public/v1"
)

type RoleBindingEvaluator struct {
	legacy         AuthorizationEvaluator
	resolver       *authz.Resolver
	keycloakIssuer string
}

func NewRoleBindingEvaluator(legacy AuthorizationEvaluator, resolver *authz.Resolver, keycloakIssuer string) *RoleBindingEvaluator {
	return &RoleBindingEvaluator{legacy: legacy, resolver: resolver, keycloakIssuer: keycloakIssuer}
}

// usesLegacyAuthorization identifies workload tokens before considering any human role grants.
func (e *RoleBindingEvaluator) usesLegacyAuthorization(identity *AuthContext) bool {
	if identity.AuthMethod == "serviceaccount" {
		return identity.Issuer != e.keycloakIssuer
	}
	if identity.Issuer != e.keycloakIssuer {
		return false
	}
	if identity.ManagedServiceAccountCandidate {
		return true
	}
	switch identity.ClientID {
	case "osac-admin", "osac-controller", "osac-csi-driver", "osac-ui-backend":
		// These clients use client credentials. The account username is reserved by Keycloak.
		return identity.IdentitySubject != "" && identity.Username == "service-account-"+identity.ClientID
	default:
		return false
	}
}

func (e *RoleBindingEvaluator) UsesRoleBindings(identity *AuthContext) bool {
	return !e.usesLegacyAuthorization(identity)
}

func (e *RoleBindingEvaluator) isHuman(identity *AuthContext) bool {
	return identity.AuthMethod == "jwt" && identity.Issuer == e.keycloakIssuer &&
		identity.Username != "" && identity.IdentitySubject != ""
}

func isAuthorizationInfrastructure(method string) bool {
	return strings.HasPrefix(method, "/grpc.reflection.") ||
		strings.HasPrefix(method, "/metadata.") ||
		strings.HasPrefix(method, "/grpc.health.")
}

func ordinaryOrganizations(identity *AuthContext) collections.Set[string] {
	names, _ := OrganizationNames(identity.Organization)
	var tenants []string
	for _, tenant := range names {
		if tenant != "" && DefaultAllowedTenants.Contains(tenant) && tenant != "*" {
			tenants = append(tenants, tenant)
		}
	}
	return collections.NewSet(tenants...)
}

func (e *RoleBindingEvaluator) Evaluate(ctx context.Context, identity *AuthContext, method string) (*AuthzDecision, error) {
	if e.usesLegacyAuthorization(identity) || isAuthorizationInfrastructure(method) {
		return e.legacy.Evaluate(ctx, identity, method)
	}
	if !e.isHuman(identity) {
		return &AuthzDecision{}, nil
	}
	if _, err := database.TxFromContext(ctx); err != nil {
		return database.WithNewTx(ctx, func(txCtx context.Context) (*AuthzDecision, error) {
			return e.evaluateHuman(txCtx, identity, method)
		})
	}
	return e.evaluateHuman(ctx, identity, method)
}

func (e *RoleBindingEvaluator) evaluateHuman(ctx context.Context, identity *AuthContext, method string) (*AuthzDecision, error) {
	tenants := ordinaryOrganizations(identity)
	names := tenants.Inclusions()
	slices.Sort(names)
	decision := &AuthzDecision{
		SubjectUser:  identity.Username,
		TenantGrants: make(map[string]*authz.Grants),
	}
	if len(names) == 1 {
		decision.SubjectTenant = names[0]
	}
	system, err := e.resolver.Resolve(ctx, SystemTenant, authz.Subject{
		Username: identity.Username, IdentitySubject: identity.IdentitySubject, Tenants: SystemTenants,
	})
	if err != nil {
		return nil, err
	}
	fullMethod := strings.TrimPrefix(method, "/")
	if system.HasRole(authz.ProviderAdminRoleID) {
		decision.SubjectTenant = SystemTenant
		if slices.Contains(system.Methods, fullMethod) {
			decision.Allowed = true
			decision.SubjectTenants = []string{"*"}
			decision.PlatformGrant = system
			return decision, nil
		}
	}

	subject := authz.Subject{Username: identity.Username, IdentitySubject: identity.IdentitySubject, Tenants: tenants}
	for _, tenant := range names {
		grants, err := e.resolver.Resolve(ctx, tenant, subject)
		if err != nil {
			return nil, err
		}
		decision.TenantGrants[tenant] = grants
		if identity.Review && identity.Tenant != "" && identity.Tenant != tenant &&
			(identity.Tenant != SharedTenant || !sharedDefinitionRead(method)) {
			continue
		}
		if slices.Contains(grants.Methods, fullMethod) && projectAllowed(identity, method, tenant, grants) {
			decision.SubjectTenants = append(decision.SubjectTenants, tenant)
		}
	}
	decision.Allowed = len(decision.SubjectTenants) > 0 || method == publicv1.SelfSubjectAccessReviews_Create_FullMethodName
	return decision, nil
}

// Shared definitions use the existing generic tenancy visibility for reads.
func sharedDefinitionRead(method string) bool {
	if method == publicv1.Secrets_Get_FullMethodName || method == privatev1.Secrets_Get_FullMethodName {
		return false
	}
	return strings.HasSuffix(method, "/Get") || strings.HasSuffix(method, "/List")
}

func projectAllowed(identity *AuthContext, method, tenant string, grants *authz.Grants) bool {
	project, readProject := "", false
	switch method {
	case publicv1.Projects_Get_FullMethodName:
		readProject = true
		project = identity.Name
	case publicv1.Projects_Update_FullMethodName, publicv1.Projects_Delete_FullMethodName:
		project = identity.Name
	case publicv1.ProjectMemberships_Create_FullMethodName, publicv1.ProjectMemberships_Get_FullMethodName,
		publicv1.ProjectMemberships_Update_FullMethodName, publicv1.ProjectMemberships_Delete_FullMethodName:
		project = identity.Project
	default:
		return true
	}
	if identity.Tenant != "" && identity.Tenant != tenant {
		return false
	}
	if identity.ID != "" && (identity.Tenant == "" || project == "") {
		return false
	}
	if grants.HasRole(authz.TenantAdminRoleID) || (identity.Review && project == "") {
		return true
	}
	if project == "" {
		return false
	}
	project = NormalizeProjectNameForAuthorization(project)
	var groups []any
	switch organization := identity.Organization.(type) {
	case map[string]any:
		attributes, _ := organization[tenant].(map[string]any)
		groups, _ = attributes["groups"].([]any)
	case []any:
		// Realm-level groups are unambiguous only for a single organization.
		if len(ordinaryOrganizations(identity).Inclusions()) == 1 {
			groups = identity.Groups
		}
	}
	for _, value := range groups {
		group, _ := value.(string)
		if group == "/"+project+"/system:managers" ||
			(readProject && group == "/"+project+"/system:viewers") {
			return true
		}
	}
	return false
}
