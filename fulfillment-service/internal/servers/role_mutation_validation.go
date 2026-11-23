/*
Copyright (c) 2026 Red Hat Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License.
*/

package servers

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/osac-project/osac/fulfillment-service/internal/auth"
	"github.com/osac-project/osac/fulfillment-service/internal/authz"
	"github.com/osac-project/osac/fulfillment-service/internal/authz/catalog"
	privatev1 "github.com/osac-project/osac/proto/gen/osac/private/v1"
)

func roleMutationGrants(ctx context.Context, tenant string) (*authz.Grants, error) {
	decision, ok := auth.RoleMutationDecisionFromContext(ctx)
	if !ok {
		// The legacy evaluator continues to authorize writes until the named-role cutover.
		return nil, nil
	}
	if err := checkRoleMutationTenant(ctx, tenant); err != nil {
		return nil, err
	}
	if decision.PlatformGrant != nil {
		return decision.PlatformGrant, nil
	}
	grants := decision.Grants[tenant]
	if grants == nil || grants.Tenant != tenant || len(grants.Methods) == 0 {
		return nil, status.Error(codes.PermissionDenied, "role mutation requires delegation grants in the target tenant")
	}
	return grants, nil
}

func checkRoleMutationTenant(ctx context.Context, tenant string) error {
	if !auth.SubjectFromContext(ctx).Tenants.Contains(tenant) {
		return status.Error(codes.PermissionDenied, "role mutation is not authorized in the target tenant")
	}
	return nil
}

func validateRoleRules(permissionCatalog *catalog.Catalog, grants *authz.Grants, rules []*privatev1.PermissionRule) error {
	if permissionCatalog == nil {
		return status.Error(codes.Internal, "permission catalog is unavailable")
	}
	firstUncovered := 0
	for i, rule := range rules {
		var err error
		covered := true
		if grants == nil {
			err = permissionCatalog.ValidateRule(rule.GetService(), rule.GetMethods())
		} else {
			covered, err = grants.Covers(permissionCatalog, rule.GetService(), rule.GetMethods())
		}
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "invalid permissions rule %d: %s", i+1, err)
		}
		if !covered && firstUncovered == 0 {
			firstUncovered = i + 1
		}
	}
	if firstUncovered != 0 {
		return status.Errorf(codes.PermissionDenied, "permissions rule %d exceeds grants in the target tenant", firstUncovered)
	}
	return nil
}
