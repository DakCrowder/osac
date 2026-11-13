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
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/osac-project/osac/fulfillment-service/internal/auth"
	"github.com/osac-project/osac/fulfillment-service/internal/authz"
	"github.com/osac-project/osac/fulfillment-service/internal/authz/catalog"
	"github.com/osac-project/osac/fulfillment-service/internal/collections"
	"github.com/osac-project/osac/fulfillment-service/internal/database/dao"
	privatev1 "github.com/osac-project/osac/proto/gen/osac/private/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

var _ = Describe("RoleBinding grant resolution with PostgreSQL", func() {
	It("does not use project metadata to scope tenant grants", func() {
		permissionCatalog, err := catalog.Build(protoregistry.GlobalFiles)
		Expect(err).ToNot(HaveOccurred())
		readTenancy, err := auth.NewDefaultTenancyLogic().SetLogger(logger).Build()
		Expect(err).ToNot(HaveOccurred())
		bindingsDAO, err := dao.NewGenericDAO[*privatev1.RoleBinding]().SetLogger(logger).SetTenancyLogic(tenancy).Build()
		Expect(err).ToNot(HaveOccurred())
		rolesDAO, err := dao.NewGenericDAO[*privatev1.Role]().SetLogger(logger).SetTenancyLogic(tenancy).Build()
		Expect(err).ToNot(HaveOccurred())
		role, err := rolesDAO.Create().SetObject(privatev1.Role_builder{
			Metadata: privatev1.Metadata_builder{Name: "project-reader", Tenant: testTenant}.Build(),
			Spec: privatev1.RoleSpec_builder{Permissions: []*privatev1.PermissionRule{
				privatev1.PermissionRule_builder{Service: "osac.public.clusters", Methods: []string{"get"}}.Build(),
			}}.Build(),
		}.Build()).Do(ctx)
		Expect(err).ToNot(HaveOccurred())
		projectsDAO, err := dao.NewGenericDAO[*privatev1.Project]().SetLogger(logger).SetTenancyLogic(tenancy).Build()
		Expect(err).ToNot(HaveOccurred())
		_, err = projectsDAO.Create().SetObject(privatev1.Project_builder{
			Metadata: privatev1.Metadata_builder{Name: "project-1", Tenant: testTenant}.Build(),
		}.Build()).Do(ctx)
		Expect(err).ToNot(HaveOccurred())
		projectBinding, err := bindingsDAO.Create().SetObject(privatev1.RoleBinding_builder{
			Metadata: privatev1.Metadata_builder{Name: "project-grant", Tenant: testTenant, Project: "project-1"}.Build(),
			Spec: privatev1.RoleBindingSpec_builder{
				Role: privatev1.RoleReference_builder{Id: role.GetObject().GetId()}.Build(),
				ServiceAccounts: []*privatev1.ServiceAccountReference{
					privatev1.ServiceAccountReference_builder{Id: "project-service"}.Build(),
				},
			}.Build(),
		}.Build()).Do(ctx)
		Expect(err).ToNot(HaveOccurred())
		defaultBinding, err := bindingsDAO.Create().SetObject(privatev1.RoleBinding_builder{
			Metadata: privatev1.Metadata_builder{Name: "tenant-grant", Tenant: testTenant}.Build(),
			Spec: privatev1.RoleBindingSpec_builder{
				Role: privatev1.RoleReference_builder{Id: role.GetObject().GetId()}.Build(),
				ServiceAccounts: []*privatev1.ServiceAccountReference{
					privatev1.ServiceAccountReference_builder{Id: "project-service"}.Build(),
				},
			}.Build(),
		}.Build()).Do(ctx)
		Expect(err).ToNot(HaveOccurred())
		readBindings, err := dao.NewGenericDAO[*privatev1.RoleBinding]().SetLogger(logger).SetTenancyLogic(readTenancy).Build()
		Expect(err).ToNot(HaveOccurred())
		readRoles, err := dao.NewGenericDAO[*privatev1.Role]().SetLogger(logger).SetTenancyLogic(readTenancy).Build()
		Expect(err).ToNot(HaveOccurred())
		readUsers, err := dao.NewGenericDAO[*privatev1.User]().SetLogger(logger).SetTenancyLogic(readTenancy).Build()
		Expect(err).ToNot(HaveOccurred())
		store := authz.DAOStore{Bindings: readBindings, Roles: readRoles, Users: readUsers}
		resolver, err := authz.NewResolver(store, permissionCatalog)
		Expect(err).ToNot(HaveOccurred())
		grants, err := resolver.Resolve(ctx, testTenant, authz.Subject{
			ServiceAccountID: "project-service", Tenants: collections.NewSet(testTenant),
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(grants.Methods).To(ContainElement("osac.public.v1.Clusters/Get"))
		Expect(grants.Bindings).To(HaveLen(2))
		Expect(grants.Bindings).To(ContainElement(HaveField("BindingID", projectBinding.GetObject().GetId())))
		Expect(grants.Bindings).To(ContainElement(HaveField("BindingID", defaultBinding.GetObject().GetId())))
	})

	It("persists name references and keeps grants attached to the original Role ID", func() {
		permissionCatalog, err := catalog.Build(protoregistry.GlobalFiles)
		Expect(err).ToNot(HaveOccurred())
		rolesServer, err := NewPrivateRolesServer().SetLogger(logger).SetAttributionLogic(attribution).
			SetTenancyLogic(tenancy).SetPermissionCatalog(permissionCatalog).Build()
		Expect(err).ToNot(HaveOccurred())
		bindingsServer, err := NewPrivateRoleBindingsServer().SetLogger(logger).
			SetAttributionLogic(attribution).SetTenancyLogic(tenancy).Build()
		Expect(err).ToNot(HaveOccurred())

		roleResponse, err := rolesServer.Create(ctx, privatev1.RolesCreateRequest_builder{
			Object: privatev1.Role_builder{
				Metadata: privatev1.Metadata_builder{Name: "stable-reader", Tenant: testTenant}.Build(),
				Spec: privatev1.RoleSpec_builder{Permissions: []*privatev1.PermissionRule{
					privatev1.PermissionRule_builder{Service: "osac.public.clusters", Methods: []string{"get"}}.Build(),
				}}.Build(),
			}.Build(),
		}.Build())
		Expect(err).ToNot(HaveOccurred())
		roleID := roleResponse.GetObject().GetId()
		for _, roleRef := range []*privatev1.RoleReference{
			privatev1.RoleReference_builder{Tenant: auth.SharedTenant}.Build(),
			privatev1.RoleReference_builder{Name: "missing-role"}.Build(),
			privatev1.RoleReference_builder{Id: roleID, Name: "wrong-name"}.Build(),
		} {
			_, err = bindingsServer.Create(ctx, privatev1.RoleBindingsCreateRequest_builder{
				Object: privatev1.RoleBinding_builder{
					Metadata: privatev1.Metadata_builder{Name: "invalid-grant", Tenant: testTenant}.Build(),
					Spec:     privatev1.RoleBindingSpec_builder{Role: roleRef}.Build(),
				}.Build(),
			}.Build())
			Expect(status.Code(err)).To(Equal(codes.InvalidArgument))
		}

		usersDAO, err := dao.NewGenericDAO[*privatev1.User]().SetLogger(logger).SetTenancyLogic(tenancy).Build()
		Expect(err).ToNot(HaveOccurred())
		userResponse, err := usersDAO.Create().SetObject(privatev1.User_builder{
			Metadata: privatev1.Metadata_builder{Name: "alice-row", Tenant: testTenant}.Build(),
			Spec:     privatev1.UserSpec_builder{Username: "alice"}.Build(),
		}.Build()).Do(ctx)
		Expect(err).ToNot(HaveOccurred())

		bindingResponse, err := bindingsServer.Create(ctx, privatev1.RoleBindingsCreateRequest_builder{
			Object: privatev1.RoleBinding_builder{
				Metadata: privatev1.Metadata_builder{Name: "alice-grant", Tenant: testTenant}.Build(),
				Spec: privatev1.RoleBindingSpec_builder{
					Role: privatev1.RoleReference_builder{Name: "stable-reader"}.Build(),
					Users: []*privatev1.UserReference{
						privatev1.UserReference_builder{Id: userResponse.GetObject().GetId()}.Build(),
					},
				}.Build(),
			}.Build(),
		}.Build())
		Expect(err).ToNot(HaveOccurred())
		Expect(bindingResponse.GetObject().GetSpec().GetRole().GetId()).To(Equal(roleID))
		Expect(bindingResponse.GetObject().GetSpec().GetRole().GetName()).To(Equal("stable-reader"))
		Expect(bindingResponse.GetObject().GetSpec().GetRole().GetTenant()).To(Equal(testTenant))
		Expect(bindingResponse.GetObject().GetSpec().GetRole().GetShared()).To(BeFalse())

		bindingsDAO, err := dao.NewGenericDAO[*privatev1.RoleBinding]().SetLogger(logger).SetTenancyLogic(tenancy).Build()
		Expect(err).ToNot(HaveOccurred())
		_, err = bindingsDAO.Create().SetObject(privatev1.RoleBinding_builder{
			Metadata: privatev1.Metadata_builder{Name: "service-grant", Tenant: testTenant}.Build(),
			Spec: privatev1.RoleBindingSpec_builder{
				Role: privatev1.RoleReference_builder{Id: roleID}.Build(),
				ServiceAccounts: []*privatev1.ServiceAccountReference{
					privatev1.ServiceAccountReference_builder{Id: "service-1"}.Build(),
				},
			}.Build(),
		}.Build()).Do(ctx)
		Expect(err).ToNot(HaveOccurred())
		rolesDAO, err := dao.NewGenericDAO[*privatev1.Role]().SetLogger(logger).SetTenancyLogic(tenancy).Build()
		Expect(err).ToNot(HaveOccurred())
		stored, err := bindingsDAO.Get().SetId(bindingResponse.GetObject().GetId()).Do(ctx)
		Expect(err).ToNot(HaveOccurred())
		Expect(stored.GetObject().GetSpec().GetRole().GetId()).To(Equal(roleID))
		updated, err := bindingsServer.Update(ctx, privatev1.RoleBindingsUpdateRequest_builder{
			Object: privatev1.RoleBinding_builder{Id: bindingResponse.GetObject().GetId(),
				Spec: privatev1.RoleBindingSpec_builder{
					Role: privatev1.RoleReference_builder{Name: "stable-reader"}.Build(),
				}.Build(),
			}.Build(),
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.role"}},
		}.Build())
		Expect(err).ToNot(HaveOccurred())
		Expect(updated.GetObject().GetSpec().GetRole().GetId()).To(Equal(roleID))
		Expect(updated.GetObject().GetSpec().GetRole().GetTenant()).To(Equal(testTenant))
		store := authz.DAOStore{Bindings: bindingsDAO, Roles: rolesDAO, Users: usersDAO}
		resolver, err := authz.NewResolver(store, permissionCatalog)
		Expect(err).ToNot(HaveOccurred())
		user := authz.Subject{Username: "alice", Tenants: collections.NewSet(testTenant)}
		service := authz.Subject{ServiceAccountID: "service-1", Tenants: collections.NewSet(testTenant)}
		grants, err := resolver.Resolve(ctx, testTenant, user)
		Expect(err).ToNot(HaveOccurred())
		Expect(grants.Methods).To(ContainElement("osac.public.v1.Clusters/Get"))
		serviceGrants, err := resolver.Resolve(ctx, testTenant, service)
		Expect(err).ToNot(HaveOccurred())
		Expect(serviceGrants.Methods).To(ContainElement("osac.public.v1.Clusters/Get"))
		otherServiceGrants, err := resolver.Resolve(ctx, testTenant, authz.Subject{
			ServiceAccountID: "service-2", Tenants: collections.NewSet(testTenant),
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(otherServiceGrants.Bindings).To(BeEmpty())

		_, err = rolesServer.Update(ctx, privatev1.RolesUpdateRequest_builder{
			Object: privatev1.Role_builder{Id: roleID, Spec: privatev1.RoleSpec_builder{
				Permissions: []*privatev1.PermissionRule{
					privatev1.PermissionRule_builder{Service: "osac.public.clusters", Methods: []string{"list"}}.Build(),
				}}.Build()}.Build(),
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.permissions"}},
		}.Build())
		Expect(err).ToNot(HaveOccurred())
		grants, err = resolver.Resolve(ctx, testTenant, user)
		Expect(err).ToNot(HaveOccurred())
		Expect(grants.Methods).To(ContainElement("osac.public.v1.Clusters/List"))
		Expect(grants.Methods).ToNot(ContainElement("osac.public.v1.Clusters/Get"))

		_, err = rolesServer.Delete(ctx, privatev1.RolesDeleteRequest_builder{Id: roleID}.Build())
		Expect(err).ToNot(HaveOccurred())
		_, err = rolesServer.Create(ctx, privatev1.RolesCreateRequest_builder{
			Object: privatev1.Role_builder{
				Metadata: privatev1.Metadata_builder{Name: "stable-reader", Tenant: auth.SharedTenant}.Build(),
				Spec: privatev1.RoleSpec_builder{Permissions: []*privatev1.PermissionRule{
					privatev1.PermissionRule_builder{Service: "osac.public.clusters", Methods: []string{"*"}}.Build(),
				}}.Build(),
			}.Build(),
		}.Build())
		Expect(err).ToNot(HaveOccurred())
		grants, err = resolver.Resolve(ctx, testTenant, user)
		Expect(err).ToNot(HaveOccurred())
		Expect(grants.Methods).To(BeEmpty())
		Expect(grants.Bindings).To(BeEmpty())
		serviceGrants, err = resolver.Resolve(ctx, testTenant, service)
		Expect(err).ToNot(HaveOccurred())
		Expect(serviceGrants.Bindings).To(BeEmpty())

		statusUpdated, err := bindingsServer.Update(ctx, privatev1.RoleBindingsUpdateRequest_builder{
			Object: privatev1.RoleBinding_builder{Id: bindingResponse.GetObject().GetId(),
				Status: privatev1.RoleBindingStatus_builder{
					State: privatev1.RoleBindingState_ROLE_BINDING_STATE_READY,
				}.Build(),
			}.Build(),
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"status.state"}},
		}.Build())
		Expect(err).ToNot(HaveOccurred())
		Expect(statusUpdated.GetObject().GetSpec().GetRole().GetId()).To(Equal(roleID))

		version := statusUpdated.GetObject().GetMetadata().GetVersion()
		finalizerUpdated, err := bindingsServer.Update(ctx, privatev1.RoleBindingsUpdateRequest_builder{
			Object: privatev1.RoleBinding_builder{Id: bindingResponse.GetObject().GetId(),
				Metadata: privatev1.Metadata_builder{Version: version, Finalizers: []string{"test/hold"}}.Build(),
			}.Build(),
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"metadata.finalizers"}},
		}.Build())
		Expect(err).ToNot(HaveOccurred())
		Expect(finalizerUpdated.GetObject().GetSpec().GetRole().GetId()).To(Equal(roleID))
		_, err = bindingsServer.Update(ctx, privatev1.RoleBindingsUpdateRequest_builder{
			Object: privatev1.RoleBinding_builder{Id: bindingResponse.GetObject().GetId(),
				Metadata: privatev1.Metadata_builder{Version: version, Finalizers: []string{"test/other"}}.Build(),
			}.Build(),
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"metadata.finalizers"}},
		}.Build())
		Expect(status.Code(err)).To(Equal(codes.Aborted))
	})

	It("stops granting from rows held by finalizers after deletion", func() {
		permissionCatalog, err := catalog.Build(protoregistry.GlobalFiles)
		Expect(err).ToNot(HaveOccurred())
		rolesDAO, err := dao.NewGenericDAO[*privatev1.Role]().SetLogger(logger).SetTenancyLogic(tenancy).Build()
		Expect(err).ToNot(HaveOccurred())
		bindingsDAO, err := dao.NewGenericDAO[*privatev1.RoleBinding]().SetLogger(logger).SetTenancyLogic(tenancy).Build()
		Expect(err).ToNot(HaveOccurred())
		usersDAO, err := dao.NewGenericDAO[*privatev1.User]().SetLogger(logger).SetTenancyLogic(tenancy).Build()
		Expect(err).ToNot(HaveOccurred())
		userResponse, err := usersDAO.Create().SetObject(privatev1.User_builder{
			Metadata: privatev1.Metadata_builder{Name: "held-user", Tenant: testTenant,
				Finalizers: []string{"test/hold"}}.Build(),
			Spec: privatev1.UserSpec_builder{Username: "held-alice"}.Build(),
		}.Build()).Do(ctx)
		Expect(err).ToNot(HaveOccurred())
		role := func(name string) string {
			response, createErr := rolesDAO.Create().SetObject(privatev1.Role_builder{
				Metadata: privatev1.Metadata_builder{Name: name, Tenant: testTenant,
					Finalizers: []string{"test/hold"}}.Build(),
				Spec: privatev1.RoleSpec_builder{Permissions: []*privatev1.PermissionRule{
					privatev1.PermissionRule_builder{Service: "osac.public.clusters", Methods: []string{"get"}}.Build(),
				}}.Build(),
			}.Build()).Do(ctx)
			Expect(createErr).ToNot(HaveOccurred())
			return response.GetObject().GetId()
		}
		binding := func(name, roleID string) string {
			response, createErr := bindingsDAO.Create().SetObject(privatev1.RoleBinding_builder{
				Metadata: privatev1.Metadata_builder{Name: name, Tenant: testTenant,
					Finalizers: []string{"test/hold"}}.Build(),
				Spec: privatev1.RoleBindingSpec_builder{
					Role: privatev1.RoleReference_builder{Id: roleID}.Build(),
					Users: []*privatev1.UserReference{
						privatev1.UserReference_builder{Id: userResponse.GetObject().GetId()}.Build(),
					},
				}.Build(),
			}.Build()).Do(ctx)
			Expect(createErr).ToNot(HaveOccurred())
			return response.GetObject().GetId()
		}
		store := authz.DAOStore{Bindings: bindingsDAO, Roles: rolesDAO, Users: usersDAO}
		resolver, err := authz.NewResolver(store, permissionCatalog)
		Expect(err).ToNot(HaveOccurred())
		subject := authz.Subject{Username: "held-alice", Tenants: collections.NewSet(testTenant)}
		resolve := func() *authz.Grants {
			grants, resolveErr := resolver.Resolve(ctx, testTenant, subject)
			Expect(resolveErr).ToNot(HaveOccurred())
			return grants
		}
		firstRole := role("held-reader-1")
		firstBinding := binding("held-binding-1", firstRole)
		_, err = bindingsDAO.Create().SetObject(privatev1.RoleBinding_builder{
			Metadata: privatev1.Metadata_builder{Name: "foreign-held-binding", Tenant: auth.SharedTenant}.Build(),
		}.Build()).Do(ctx)
		Expect(err).ToNot(HaveOccurred())
		page, err := store.ListBindings(ctx, testTenant, 0, 100)
		Expect(err).ToNot(HaveOccurred())
		Expect(page).To(HaveLen(1))
		Expect(page[0].GetId()).To(Equal(firstBinding))
		Expect(resolve().Bindings).To(HaveLen(1))
		_, err = bindingsDAO.Delete().SetId(firstBinding).Do(ctx)
		Expect(err).ToNot(HaveOccurred())
		storedBinding, err := bindingsDAO.Get().SetId(firstBinding).Do(ctx)
		Expect(err).ToNot(HaveOccurred())
		Expect(storedBinding.GetObject().GetMetadata().GetDeletionTimestamp()).ToNot(BeNil())
		Expect(resolve().Bindings).To(BeEmpty())

		binding("held-binding-2", firstRole)
		Expect(resolve().Bindings).To(HaveLen(1))
		_, err = rolesDAO.Delete().SetId(firstRole).Do(ctx)
		Expect(err).ToNot(HaveOccurred())
		storedRole, err := rolesDAO.Get().SetId(firstRole).Do(ctx)
		Expect(err).ToNot(HaveOccurred())
		Expect(storedRole.GetObject().GetMetadata().GetDeletionTimestamp()).ToNot(BeNil())
		Expect(resolve().Bindings).To(BeEmpty())

		secondRole := role("held-reader-2")
		binding("held-binding-3", secondRole)
		Expect(resolve().Bindings).To(HaveLen(1))
		_, err = usersDAO.Delete().SetId(userResponse.GetObject().GetId()).Do(ctx)
		Expect(err).ToNot(HaveOccurred())
		storedUser, err := usersDAO.Get().SetId(userResponse.GetObject().GetId()).Do(ctx)
		Expect(err).ToNot(HaveOccurred())
		Expect(storedUser.GetObject().GetMetadata().GetDeletionTimestamp()).ToNot(BeNil())
		Expect(resolve().Bindings).To(BeEmpty())
	})

	It("preserves a legacy name-only reference on status and finalizer updates", func() {
		rolesDAO, err := dao.NewGenericDAO[*privatev1.Role]().SetLogger(logger).SetTenancyLogic(tenancy).Build()
		Expect(err).ToNot(HaveOccurred())
		_, err = rolesDAO.Create().SetObject(privatev1.Role_builder{
			Metadata: privatev1.Metadata_builder{Name: "legacy-shared-role", Tenant: auth.SharedTenant}.Build(),
		}.Build()).Do(ctx)
		Expect(err).ToNot(HaveOccurred())
		bindingsDAO, err := dao.NewGenericDAO[*privatev1.RoleBinding]().SetLogger(logger).SetTenancyLogic(tenancy).Build()
		Expect(err).ToNot(HaveOccurred())
		legacy, err := bindingsDAO.Create().SetObject(privatev1.RoleBinding_builder{
			Metadata: privatev1.Metadata_builder{Name: "legacy-binding", Tenant: testTenant}.Build(),
			Spec: privatev1.RoleBindingSpec_builder{
				Role: privatev1.RoleReference_builder{Name: "legacy-shared-role"}.Build(),
			}.Build(),
		}.Build()).Do(ctx)
		Expect(err).ToNot(HaveOccurred())
		bindingsServer, err := NewPrivateRoleBindingsServer().SetLogger(logger).
			SetAttributionLogic(attribution).SetTenancyLogic(tenancy).Build()
		Expect(err).ToNot(HaveOccurred())

		updated, err := bindingsServer.Update(ctx, privatev1.RoleBindingsUpdateRequest_builder{
			Object: privatev1.RoleBinding_builder{Id: legacy.GetObject().GetId(),
				Status: privatev1.RoleBindingStatus_builder{
					State: privatev1.RoleBindingState_ROLE_BINDING_STATE_READY,
				}.Build(),
			}.Build(),
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"status.state"}},
		}.Build())
		Expect(err).ToNot(HaveOccurred())
		Expect(updated.GetObject().GetSpec().GetRole().GetId()).To(BeEmpty())

		finalizerUpdated, err := bindingsServer.Update(ctx, privatev1.RoleBindingsUpdateRequest_builder{
			Object: privatev1.RoleBinding_builder{Id: legacy.GetObject().GetId(),
				Metadata: privatev1.Metadata_builder{
					Version: updated.GetObject().GetMetadata().GetVersion(), Finalizers: []string{"test/hold"},
				}.Build(),
			}.Build(),
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"metadata.finalizers"}},
		}.Build())
		Expect(err).ToNot(HaveOccurred())
		Expect(finalizerUpdated.GetObject().GetSpec().GetRole().GetId()).To(BeEmpty())
		Expect(finalizerUpdated.GetObject().GetSpec().GetRole().GetName()).To(Equal("legacy-shared-role"))
	})

	It("falls back to the shared Role for an unqualified name", func() {
		rolesDAO, err := dao.NewGenericDAO[*privatev1.Role]().SetLogger(logger).SetTenancyLogic(tenancy).Build()
		Expect(err).ToNot(HaveOccurred())
		shared, err := rolesDAO.Create().SetObject(privatev1.Role_builder{
			Metadata: privatev1.Metadata_builder{Name: "explicit-shared-reader", Tenant: auth.SharedTenant}.Build(),
		}.Build()).Do(ctx)
		Expect(err).ToNot(HaveOccurred())
		bindingsServer, err := NewPrivateRoleBindingsServer().SetLogger(logger).
			SetAttributionLogic(attribution).SetTenancyLogic(tenancy).Build()
		Expect(err).ToNot(HaveOccurred())

		for i, tc := range []struct {
			name string
			ref  *privatev1.RoleReference
			code codes.Code
		}{
			{"unqualified name", privatev1.RoleReference_builder{Name: "explicit-shared-reader"}.Build(), codes.OK},
			{"explicit tenant", privatev1.RoleReference_builder{Name: "explicit-shared-reader", Tenant: auth.SharedTenant}.Build(), codes.OK},
			{"shared selector", privatev1.RoleReference_builder{Name: "explicit-shared-reader", Shared: true}.Build(), codes.OK},
			{"role ID", privatev1.RoleReference_builder{Id: shared.GetObject().GetId()}.Build(), codes.OK},
			{"conflicting selectors", privatev1.RoleReference_builder{Name: "explicit-shared-reader", Tenant: testTenant, Shared: true}.Build(), codes.InvalidArgument},
			{"wrong tenant", privatev1.RoleReference_builder{Id: shared.GetObject().GetId(), Tenant: testTenant}.Build(), codes.InvalidArgument},
			{"wrong name", privatev1.RoleReference_builder{Id: shared.GetObject().GetId(), Name: "other"}.Build(), codes.InvalidArgument},
		} {
			binding, createErr := bindingsServer.Create(ctx, privatev1.RoleBindingsCreateRequest_builder{
				Object: privatev1.RoleBinding_builder{
					Metadata: privatev1.Metadata_builder{Name: fmt.Sprintf("selection-%d", i), Tenant: testTenant}.Build(),
					Spec:     privatev1.RoleBindingSpec_builder{Role: tc.ref}.Build(),
				}.Build(),
			}.Build())
			Expect(status.Code(createErr)).To(Equal(tc.code), tc.name)
			if tc.code == codes.OK {
				ref := binding.GetObject().GetSpec().GetRole()
				Expect(ref.GetId()).To(Equal(shared.GetObject().GetId()), tc.name)
				Expect(ref.GetName()).To(Equal("explicit-shared-reader"), tc.name)
				Expect(ref.GetTenant()).To(Equal(auth.SharedTenant), tc.name)
				Expect(ref.GetShared()).To(BeTrue(), tc.name)
			}
		}
	})
})
