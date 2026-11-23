/*
Copyright (c) 2026 Red Hat Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License.
*/

package tenant

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/osac-project/osac/fulfillment-service/internal/auth"
	"github.com/osac-project/osac/fulfillment-service/internal/authz"
	privatev1 "github.com/osac-project/osac/proto/gen/osac/private/v1"
)

func (t *task) ensureBreakGlassBinding(ctx context.Context, keycloakID string) error {
	if keycloakID == "" {
		return errors.New("the tenant has no Keycloak break-glass identity")
	}
	tenant := t.tenant.GetId()
	username := tenant + "-osac-break-glass"
	filter := fmt.Sprintf("this.metadata.tenant == %q && this.spec.username == %q && this.metadata.deletion_timestamp == null", tenant, username)
	users, err := t.r.usersClient.List(ctx, privatev1.UsersListRequest_builder{Filter: &filter, Limit: new(int32(1))}.Build())
	if err != nil {
		return err
	}
	var user *privatev1.User
	if len(users.GetItems()) > 0 {
		user = users.GetItems()[0]
	} else {
		created, err := t.r.usersClient.Create(ctx, privatev1.UsersCreateRequest_builder{
			Object: privatev1.User_builder{
				Metadata: privatev1.Metadata_builder{Name: "break-glass-" + keycloakID, Tenant: tenant}.Build(),
				Spec:     privatev1.UserSpec_builder{Username: username, Email: "break-glass@" + tenant + ".osac.local", Enabled: true}.Build(),
				Status:   privatev1.UserStatus_builder{KeycloakUserId: keycloakID}.Build(),
			}.Build(),
		}.Build())
		if err != nil {
			return err
		}
		user = created.GetObject()
	}
	if user.GetStatus().GetKeycloakUserId() != keycloakID {
		return errors.New("waiting for the break-glass User to synchronize with Keycloak")
	}

	name := "break-glass-" + user.GetId()
	filter = fmt.Sprintf("this.metadata.tenant == %q && this.metadata.name == %q && this.metadata.deletion_timestamp == null", tenant, name)
	bindings, err := t.r.roleBindingsClient.List(ctx, privatev1.RoleBindingsListRequest_builder{Filter: &filter, Limit: new(int32(1))}.Build())
	if err != nil {
		return err
	}
	if len(bindings.GetItems()) > 0 {
		binding := bindings.GetItems()[0]
		users := binding.GetSpec().GetUsers()
		if binding.GetSpec().GetRole().GetId() != authz.TenantIDPManagerRoleID || len(users) != 1 || users[0].GetId() != user.GetId() {
			return errors.New("the tenant break-glass RoleBinding has unexpected contents")
		}
		if binding.GetStatus().GetState() == privatev1.RoleBindingState_ROLE_BINDING_STATE_READY {
			return nil
		}
		return errors.New("waiting for the break-glass RoleBinding to synchronize with Keycloak")
	}
	_, err = t.r.roleBindingsClient.Create(ctx, privatev1.RoleBindingsCreateRequest_builder{
		Object: privatev1.RoleBinding_builder{
			Metadata: privatev1.Metadata_builder{Name: name, Tenant: tenant}.Build(),
			Spec: privatev1.RoleBindingSpec_builder{
				Role:  privatev1.RoleReference_builder{Id: authz.TenantIDPManagerRoleID, Tenant: auth.SharedTenant}.Build(),
				Users: []*privatev1.UserReference{privatev1.UserReference_builder{Id: user.GetId()}.Build()},
			}.Build(),
		}.Build(),
	}.Build())
	if err != nil {
		return err
	}
	return errors.New("waiting for the break-glass RoleBinding to synchronize with Keycloak")
}

// Remove tenant bindings before Users and projects so Keycloak projection and
// project foreign keys can finish cleanup.
func (t *task) deleteTenantRoleBindings(ctx context.Context) (bool, error) {
	filter := fmt.Sprintf("this.metadata.tenant == %q", t.tenant.GetId())
	response, err := t.r.roleBindingsClient.List(ctx, privatev1.RoleBindingsListRequest_builder{
		Filter: &filter, Limit: new(int32(100)),
	}.Build())
	if err != nil {
		return false, err
	}
	for _, binding := range response.GetItems() {
		if binding.GetMetadata().HasDeletionTimestamp() {
			_, err = t.r.roleBindingsClient.Signal(ctx, privatev1.RoleBindingsSignalRequest_builder{Id: binding.GetId()}.Build())
		} else {
			_, err = t.r.roleBindingsClient.Delete(ctx, privatev1.RoleBindingsDeleteRequest_builder{Id: binding.GetId()}.Build())
		}
		if err != nil && status.Code(err) != codes.NotFound {
			return false, err
		}
	}
	return len(response.GetItems()) > 0, nil
}
