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
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/osac-project/osac/fulfillment-service/internal/auth"
	"github.com/osac-project/osac/fulfillment-service/internal/authz"
	"github.com/osac-project/osac/fulfillment-service/internal/database"
	"github.com/osac-project/osac/fulfillment-service/internal/database/dao"
	privatev1 "github.com/osac-project/osac/proto/gen/osac/private/v1"
)

func prepareUserAuthorization(ctx context.Context, current, candidate *privatev1.User) error {
	tenant := candidate.GetMetadata().GetTenant()
	username := candidate.GetSpec().GetUsername()
	if current != nil {
		if current.GetSpec().GetUsername() != username || current.GetMetadata().GetTenant() != tenant {
			return status.Error(codes.InvalidArgument, "user identity and tenant cannot change")
		}
		subject := current.GetStatus().GetKeycloakUserId()
		if subject != "" && candidate.GetStatus().GetKeycloakUserId() != subject {
			return status.Error(codes.InvalidArgument, "linked user identity cannot change")
		}
		return nil
	}
	if isDryRun(ctx) {
		return nil
	}
	tx, err := database.TxFromContext(ctx)
	if err != nil {
		return err
	}
	// Serialize creates across explicit onboarding and first login by tenant and username.
	if _, err := tx.Exec(ctx, "select pg_advisory_xact_lock(hashtextextended(jsonb_build_array($1::text, $2::text)::text, 0))", tenant, username); err != nil {
		return err
	}
	var exists bool
	err = tx.QueryRow(ctx, `
		select exists (select 1 from users where tenant = $1 and data #>> '{spec,username}' = $2)
	`, tenant, username).Scan(&exists)
	if err != nil {
		return err
	}
	if exists {
		return status.Error(codes.AlreadyExists, "username already exists in the tenant")
	}
	return nil
}

func assignUserDefaultRole(ctx context.Context, bindings *dao.GenericDAO[*privatev1.RoleBinding], user *privatev1.User) (err error) {
	tenant := user.GetMetadata().GetTenant()
	if !auth.DefaultAllowedTenants.Contains(tenant) {
		return nil
	}
	if user.GetSpec().GetUsername() == tenant+"-osac-break-glass" && auth.IsControllerServiceAccount(ctx) {
		return nil
	}
	tx, err := database.TxFromContext(ctx)
	if err != nil {
		return err
	}
	defer tx.ReportError(&err)
	var roleID string
	err = tx.QueryRow(ctx, `
		select coalesce(t.data #>> '{spec,default_role,id}', shared.data #>> '{spec,default_role,id}', '')
		from tenants t cross join tenants shared
		where t.id = $1 and t.deletion_timestamp = 'epoch' and shared.id = 'shared'
	`, tenant).Scan(&roleID)
	if err != nil {
		return fmt.Errorf("read tenant default role: %w", err)
	}
	if roleID == "" {
		return nil
	}
	var roleName, roleTenant string
	err = tx.QueryRow(ctx, `
		select name, tenant from roles
		where id = $1 and tenant in ($2, 'shared') and deletion_timestamp = 'epoch'
		for share
	`, roleID, tenant).Scan(&roleName, &roleTenant)
	if errors.Is(err, pgx.ErrNoRows) || roleID == authz.ProviderAdminRoleID {
		return status.Error(codes.FailedPrecondition, "tenant default Role is unavailable")
	}
	if err != nil {
		return err
	}

	_, err = bindings.Create().SetObject(privatev1.RoleBinding_builder{
		Metadata: privatev1.Metadata_builder{
			Name: authz.DefaultBindingPrefix + user.GetId(), Tenant: tenant,
			Creator: auth.SystemTenant, Project: user.GetMetadata().GetProject(),
		}.Build(),
		Spec: privatev1.RoleBindingSpec_builder{
			Role: privatev1.RoleReference_builder{Id: roleID, Name: roleName, Tenant: roleTenant, Shared: roleTenant == auth.SharedTenant}.Build(),
			Users: []*privatev1.UserReference{privatev1.UserReference_builder{
				Id: user.GetId(), Name: user.GetMetadata().GetName(), Tenant: tenant,
			}.Build()},
		}.Build(),
	}.Build()).Do(ctx)
	return err
}
