/*
Copyright (c) 2026 Red Hat Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License.
*/

package rolebinding

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/osac-project/osac/fulfillment-service/internal/authz"
	"github.com/osac-project/osac/fulfillment-service/internal/controllers"
	"github.com/osac-project/osac/fulfillment-service/internal/idp"
	privatev1 "github.com/osac-project/osac/proto/gen/osac/private/v1"
)

var projectedRoles = map[string]string{
	authz.ProviderAdminRoleID:    "cloud-provider-admin",
	authz.ProviderReaderRoleID:   "cloud-provider-reader",
	authz.TenantAdminRoleID:      "tenant-admin",
	authz.TenantReaderRoleID:     "tenant-reader",
	authz.TenantIDPManagerRoleID: "tenant-idp-manager",
}

func (t *task) projectRealmRole(ctx context.Context) error {
	deleting := t.binding.GetMetadata().HasDeletionTimestamp()
	if !deleting && t.addFinalizer() {
		return nil
	}
	t.setDefaults()
	annotations := maps.Clone(t.binding.GetMetadata().GetAnnotations())
	previousRole := annotations[authz.ProjectionRoleAnnotation]
	role := t.binding.GetSpec().GetRole().GetId()
	desired := t.binding.GetSpec().GetUsers()
	if deleting || projectedRoles[role] == "" {
		desired = nil
	}

	for _, ref := range t.binding.GetStatus().GetUsers() {
		same := role == previousRole && slices.ContainsFunc(desired, func(user *privatev1.UserReference) bool {
			return ref.GetId() == user.GetId()
		})
		if !same {
			if err := t.syncRealmRole(ctx, previousRole, ref.GetId(), false); err != nil {
				return controllers.RequeueAfter(err, 5*time.Second)
			}
		}
	}
	// A process can stop after writing to Keycloak and before saving status.
	// Check the current desired role on deletion as well.
	if deleting {
		for _, ref := range t.binding.GetSpec().GetUsers() {
			if err := t.syncRealmRole(ctx, role, ref.GetId(), false); err != nil {
				return controllers.RequeueAfter(err, 5*time.Second)
			}
		}
		t.removeFinalizer()
		return nil
	}

	for _, ref := range desired {
		if role == previousRole && slices.ContainsFunc(t.binding.GetStatus().GetUsers(), func(user *privatev1.UserReference) bool {
			return user.GetId() == ref.GetId()
		}) {
			continue
		}
		if err := t.syncRealmRole(ctx, role, ref.GetId(), true); err != nil {
			return controllers.RequeueAfter(err, 5*time.Second)
		}
	}
	if len(desired) == 0 {
		delete(annotations, authz.ProjectionRoleAnnotation)
	} else {
		if annotations == nil {
			annotations = make(map[string]string)
		}
		annotations[authz.ProjectionRoleAnnotation] = role
	}
	t.binding.GetMetadata().SetAnnotations(annotations)
	t.binding.GetStatus().SetUsers(desired)
	t.binding.GetStatus().SetState(privatev1.RoleBindingState_ROLE_BINDING_STATE_READY)
	t.binding.GetStatus().ClearMessage()
	return nil
}

func (t *task) syncRealmRole(ctx context.Context, roleID, userID string, assign bool) error {
	roleName := projectedRoles[roleID]
	if roleName == "" || userID == "" {
		return nil
	}
	response, err := t.r.usersClient.Get(ctx, privatev1.UsersGetRequest_builder{Id: userID}.Build())
	if !assign && status.Code(err) == codes.NotFound {
		return nil
	}
	if err != nil {
		return err
	}
	user := response.GetObject()
	idpUserID := user.GetStatus().GetKeycloakUserId()
	if idpUserID == "" {
		if !assign {
			return nil
		}
		return fmt.Errorf("waiting for the binding user to synchronize with Keycloak")
	}
	tenant := user.GetMetadata().GetTenant()
	roles := []*idp.Role{{Name: roleName}}
	if assign {
		return t.r.idpClient.AssignTenantRolesToUser(ctx, tenant, idpUserID, roles)
	}
	needed, err := t.realmRoleStillBound(ctx, roleID, idpUserID)
	if err != nil || needed {
		return err
	}
	if err := t.r.idpClient.RemoveTenantRolesFromUser(ctx, tenant, idpUserID, roles); err != nil {
		return err
	}
	// A newly added binding might have projected the role after the first read.
	needed, err = t.realmRoleStillBound(ctx, roleID, idpUserID)
	if err != nil || !needed {
		return err
	}
	return t.r.idpClient.AssignTenantRolesToUser(ctx, tenant, idpUserID, roles)
}

func (t *task) realmRoleStillBound(ctx context.Context, roleID, idpUserID string) (bool, error) {
	const pageSize = int32(100)
	filter := fmt.Sprintf("this.spec.role.id == %q && this.metadata.deletion_timestamp == null", roleID)
	for offset := int32(0); ; offset += pageSize {
		response, err := t.r.roleBindingsClient.List(ctx, privatev1.RoleBindingsListRequest_builder{
			Filter: &filter, Limit: new(pageSize), Offset: &offset, Order: new("this.id asc"),
		}.Build())
		if err != nil {
			return false, err
		}
		for _, binding := range response.GetItems() {
			if binding.GetId() == t.binding.GetId() {
				continue
			}
			for _, ref := range binding.GetSpec().GetUsers() {
				user, err := t.r.usersClient.Get(ctx, privatev1.UsersGetRequest_builder{Id: ref.GetId()}.Build())
				if status.Code(err) == codes.NotFound {
					continue
				}
				if err != nil {
					return false, err
				}
				if user.GetObject().GetStatus().GetKeycloakUserId() == idpUserID {
					return true, nil
				}
			}
		}
		if len(response.GetItems()) < int(pageSize) {
			return false, nil
		}
	}
}
