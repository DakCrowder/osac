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
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
	grpccodes "google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/osac-project/osac/fulfillment-service/internal/auth"
	"github.com/osac-project/osac/fulfillment-service/internal/collections"
	"github.com/osac-project/osac/fulfillment-service/internal/database/dao"
	privatev1 "github.com/osac-project/osac/proto/gen/osac/private/v1"
	publicv1 "github.com/osac-project/osac/proto/gen/osac/public/v1"
)

var _ = Describe("Managed keys servers", func() {
	var public *ManagedKeysServer
	var private *PrivateManagedKeysServer
	var assignable collections.Set[string]
	var defaultTenant string
	var visibility *auth.Visibility
	var keyTenancy *auth.MockTenancyLogic

	BeforeEach(func() {
		assignable, defaultTenant, visibility = collections.NewSet(testTenant), testTenant, auth.TotalVisibility()
		keyTenancy = auth.NewMockTenancyLogic(gomock.NewController(GinkgoT()))
		keyTenancy.EXPECT().DetermineAssignableTenants(gomock.Any()).DoAndReturn(func(context.Context) (collections.Set[string], error) { return assignable, nil }).AnyTimes()
		keyTenancy.EXPECT().DetermineDefaultTenant(gomock.Any()).DoAndReturn(func(context.Context) (string, error) { return defaultTenant, nil }).AnyTimes()
		keyTenancy.EXPECT().DetermineVisibility(gomock.Any()).DoAndReturn(func(context.Context) (*auth.Visibility, error) { return visibility, nil }).AnyTimes()
		var err error
		public, err = NewManagedKeysServer().SetLogger(logger).SetAttributionLogic(attribution).SetTenancyLogic(keyTenancy).Build()
		Expect(err).ToNot(HaveOccurred())
		private, err = NewPrivateManagedKeysServer().SetLogger(logger).SetAttributionLogic(attribution).SetTenancyLogic(keyTenancy).Build()
		Expect(err).ToNot(HaveOccurred())
	})

	create := func(name string) *publicv1.ManagedKey {
		response, err := public.Create(ctx, publicv1.ManagedKeysCreateRequest_builder{Object: publicv1.ManagedKey_builder{
			Metadata: publicv1.Metadata_builder{Name: name, Tenant: testTenant}.Build(),
		}.Build()}.Build())
		Expect(err).ToNot(HaveOccurred())
		return response.GetObject()
	}
	version := func(generation uint64) *privatev1.ManagedKeyVersion {
		return privatev1.ManagedKeyVersion_builder{Generation: generation, CreationTimestamp: timestamppb.New(time.Unix(int64(generation), 0)), BackendObjectId: "provider-object", BackendVersionId: new("opaque-version")}.Build()
	}
	confirm := func(key *publicv1.ManagedKey) *privatev1.ManagedKey {
		response, err := private.Update(ctx, privatev1.ManagedKeysUpdateRequest_builder{
			Object:     privatev1.ManagedKey_builder{Id: key.GetId(), State: privatev1.ManagedKeyState_MANAGED_KEY_STATE_ACTIVE, Versions: []*privatev1.ManagedKeyVersion{version(1)}, Backend: privatev1.KeyBackend_KEY_BACKEND_VAULT_TRANSIT}.Build(),
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"state", "versions", "backend"}},
		}.Build())
		Expect(err).ToNot(HaveOccurred())
		return response.GetObject()
	}

	It("persists an unconfirmed identity with defaults, attribution and a change record", func() {
		key := create("my-key")
		Expect(key.GetId()).ToNot(BeEmpty())
		Expect(key.GetMetadata().GetTenant()).To(Equal(testTenant))
		Expect(key.GetMetadata().GetCreator()).To(Equal("system"))
		Expect(key.GetUsage()).To(Equal(publicv1.ManagedKeyUsage_MANAGED_KEY_USAGE_ENCRYPT_DECRYPT))
		Expect(key.GetState()).To(Equal(publicv1.ManagedKeyState_MANAGED_KEY_STATE_UNSPECIFIED))
		Expect(key.GetVersions()).To(BeEmpty())
		Expect(key.GetRevocationTimestamp()).To(BeNil())
		Expect(key.GetLastRotationTimestamp()).To(BeNil())
		response, err := private.Get(ctx, privatev1.ManagedKeysGetRequest_builder{Id: key.GetId()}.Build())
		Expect(err).ToNot(HaveOccurred())
		Expect(response.GetObject().GetBackend()).To(Equal(privatev1.KeyBackend_KEY_BACKEND_UNSPECIFIED))
		var count int
		Expect(suiteTx.QueryRow(ctx, `select count(*) from changes where "table" = 'managed_keys' and data->>'id' = $1`, key.GetId()).Scan(&count)).To(Succeed())
		Expect(count).To(Equal(1))
	})

	It("defaults an omitted tenant for a tenant-scoped identity", func() {
		response, err := public.Create(ctx, publicv1.ManagedKeysCreateRequest_builder{Object: publicv1.ManagedKey_builder{Metadata: publicv1.Metadata_builder{Name: "default-tenant"}.Build()}.Build()}.Build())
		Expect(err).ToNot(HaveOccurred())
		Expect(response.GetObject().GetMetadata().GetTenant()).To(Equal(testTenant))
	})

	It("lists with CEL filtering, ordering, and pagination", func() {
		create("a-key")
		create("b-key")
		response, err := public.List(ctx, publicv1.ManagedKeysListRequest_builder{Filter: new("this.usage == 1"), Order: new("metadata.name desc"), Limit: new(int32(1))}.Build())
		Expect(err).ToNot(HaveOccurred())
		Expect(response.GetSize()).To(Equal(int32(1)))
		Expect(response.GetTotal()).To(Equal(int32(2)))
		Expect(response.GetItems()[0].GetMetadata().GetName()).To(Equal("b-key"))
	})

	DescribeTable("rejects invalid and private order expressions", func(order string) {
		_, err := public.List(ctx, publicv1.ManagedKeysListRequest_builder{Order: new(order)}.Build())
		Expect(grpcstatus.Code(err)).To(Equal(grpccodes.InvalidArgument))
	}, Entry("private backend", "backend"), Entry("SQL injection", "metadata.name; drop table managed_keys"), Entry("direction injection", "metadata.name desc nulls last"), Entry("map", "metadata.labels"), Entry("message", "metadata"), Entry("list", "versions"))

	It("maps confirmed private metadata without exposing backend coordinates", func() {
		key := create("confirmed-key")
		confirm(key)
		response, err := public.Get(ctx, publicv1.ManagedKeysGetRequest_builder{Id: key.GetId()}.Build())
		Expect(err).ToNot(HaveOccurred())
		Expect(response.GetObject().GetState()).To(Equal(publicv1.ManagedKeyState_MANAGED_KEY_STATE_ACTIVE))
		Expect(response.GetObject().GetVersions()).To(HaveLen(1))
		Expect(response.GetObject().GetVersions()[0].GetGeneration()).To(Equal(uint64(1)))
		_, err = public.List(ctx, publicv1.ManagedKeysListRequest_builder{Filter: new("this.backend == 1")}.Build())
		Expect(grpcstatus.Code(err)).To(Equal(grpccodes.InvalidArgument))
	})

	It("preserves private state during a public update without a mask", func() {
		key := create("confirmed-key")
		confirmed := confirm(key)
		response, err := public.Update(ctx, publicv1.ManagedKeysUpdateRequest_builder{Object: publicv1.ManagedKey_builder{
			Id: key.GetId(), Metadata: publicv1.Metadata_builder{DisplayName: "Friendly", Description: "Description", Version: confirmed.GetMetadata().GetVersion()}.Build(),
		}.Build(), Lock: true}.Build())
		Expect(err).ToNot(HaveOccurred())
		Expect(response.GetObject().GetMetadata().GetDisplayName()).To(Equal("Friendly"))
		fetched, err := private.Get(ctx, privatev1.ManagedKeysGetRequest_builder{Id: key.GetId()}.Build())
		Expect(err).ToNot(HaveOccurred())
		Expect(proto.Equal(fetched.GetObject().GetVersions()[0], confirmed.GetVersions()[0])).To(BeTrue())
		Expect(fetched.GetObject().GetBackend()).To(Equal(confirmed.GetBackend()))
		Expect(fetched.GetObject().GetState()).To(Equal(confirmed.GetState()))
	})

	It("accepts round-tripping unchanged read-only fields and explicit metadata clears", func() {
		key := create("roundtrip-key")
		confirm(key)
		fetched, err := public.Get(ctx, publicv1.ManagedKeysGetRequest_builder{Id: key.GetId()}.Build())
		Expect(err).ToNot(HaveOccurred())
		object := fetched.GetObject()
		object.GetMetadata().SetDescription("new description")
		_, err = public.Update(ctx, publicv1.ManagedKeysUpdateRequest_builder{Object: object}.Build())
		Expect(err).ToNot(HaveOccurred())
		response, err := public.Update(ctx, publicv1.ManagedKeysUpdateRequest_builder{Object: publicv1.ManagedKey_builder{Id: key.GetId()}.Build(), UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"metadata.description"}}}.Build())
		Expect(err).ToNot(HaveOccurred())
		Expect(response.GetObject().GetMetadata().GetDescription()).To(BeEmpty())
		Expect(response.GetObject().GetVersions()).To(HaveLen(1))
	})

	It("filters and sorts descriptive metadata stored in JSON", func() {
		key := create("descriptive-key")
		_, err := public.Update(ctx, publicv1.ManagedKeysUpdateRequest_builder{Object: publicv1.ManagedKey_builder{Id: key.GetId(), Metadata: publicv1.Metadata_builder{Description: "find-me"}.Build()}.Build()}.Build())
		Expect(err).ToNot(HaveOccurred())
		response, err := public.List(ctx, publicv1.ManagedKeysListRequest_builder{Filter: new("this.metadata.description == 'find-me'"), Order: new("metadata.description desc, metadata.name asc")}.Build())
		Expect(err).ToNot(HaveOccurred())
		Expect(response.GetTotal()).To(Equal(int32(1)))
		Expect(response.GetItems()[0].GetMetadata().GetDescription()).To(Equal("find-me"))
	})

	It("enforces public optimistic locking", func() {
		key := create("locked-key")
		confirm(key)
		_, err := public.Update(ctx, publicv1.ManagedKeysUpdateRequest_builder{Object: key, Lock: true, UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"metadata.description"}}}.Build())
		Expect(grpcstatus.Code(err)).To(Equal(grpccodes.Aborted))
	})

	DescribeTable("rejects public masks outside descriptive metadata", func(path string) {
		key := create("restricted-key")
		_, err := public.Update(ctx, publicv1.ManagedKeysUpdateRequest_builder{Object: key, UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{path}}}.Build())
		Expect(grpcstatus.Code(err)).To(Equal(grpccodes.InvalidArgument))
	}, Entry("state", "state"), Entry("versions", "versions"), Entry("usage", "usage"), Entry("whole metadata", "metadata"), Entry("tenant", "metadata.tenant"), Entry("name", "metadata.name"), Entry("labels", "metadata.labels"), Entry("private backend", "backend"))

	It("rejects lifecycle changes supplied without a mask", func() {
		key := create("restricted-key")
		key.SetState(publicv1.ManagedKeyState_MANAGED_KEY_STATE_ACTIVE)
		_, err := public.Update(ctx, publicv1.ManagedKeysUpdateRequest_builder{Object: key}.Build())
		Expect(grpcstatus.Code(err)).To(Equal(grpccodes.InvalidArgument))
	})

	DescribeTable("rejects confirmed fields on creation", func(field string) {
		object := privatev1.ManagedKey_builder{Metadata: privatev1.Metadata_builder{Name: "invalid-key"}.Build()}.Build()
		switch field {
		case "state":
			object.SetState(privatev1.ManagedKeyState_MANAGED_KEY_STATE_ACTIVE)
		case "versions":
			object.SetVersions([]*privatev1.ManagedKeyVersion{version(1)})
		case "backend":
			object.SetBackend(privatev1.KeyBackend_KEY_BACKEND_VAULT_TRANSIT)
		case "revocation":
			object.SetRevocationTimestamp(timestamppb.Now())
		case "rotation":
			object.SetLastRotationTimestamp(timestamppb.Now())
		}
		_, err := private.Create(ctx, privatev1.ManagedKeysCreateRequest_builder{Object: object}.Build())
		Expect(grpcstatus.Code(err)).To(Equal(grpccodes.InvalidArgument))
	}, Entry("state", "state"), Entry("versions", "versions"), Entry("backend", "backend"), Entry("revocation", "revocation"), Entry("rotation", "rotation"))

	DescribeTable("rejects immutable private updates", func(path string) {
		assignable = auth.AllTenants
		key := create("immutable-key")
		confirmed := confirm(key)
		candidate := proto.Clone(confirmed).(*privatev1.ManagedKey)
		switch path {
		case "usage":
			candidate.SetUsage(privatev1.ManagedKeyUsage_MANAGED_KEY_USAGE_UNSPECIFIED)
		case "backend":
			candidate.SetBackend(privatev1.KeyBackend_KEY_BACKEND_UNSPECIFIED)
		case "metadata.name":
			candidate.GetMetadata().SetName("renamed")
		case "metadata.tenant":
			candidate.GetMetadata().SetTenant(auth.SystemTenant)
		case "metadata.project":
			candidate.GetMetadata().SetProject("elsewhere")
		}
		_, err := private.Update(ctx, privatev1.ManagedKeysUpdateRequest_builder{Object: candidate, UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{path}}}.Build())
		Expect(grpcstatus.Code(err)).To(Equal(grpccodes.InvalidArgument))
	}, Entry("usage", "usage"), Entry("backend", "backend"), Entry("name", "metadata.name"), Entry("tenant", "metadata.tenant"), Entry("project", "metadata.project"))

	DescribeTable("rejects invalid or rewritten generation history", func(generations []uint64) {
		key := create("generation-key")
		confirm(key)
		versions := make([]*privatev1.ManagedKeyVersion, len(generations))
		for i, generation := range generations {
			versions[i] = version(generation)
		}
		_, err := private.Update(ctx, privatev1.ManagedKeysUpdateRequest_builder{Object: privatev1.ManagedKey_builder{Id: key.GetId(), Versions: versions}.Build(), UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"versions"}}}.Build())
		Expect(grpcstatus.Code(err)).To(Equal(grpccodes.InvalidArgument))
	}, Entry("zero", []uint64{0}), Entry("duplicate", []uint64{1, 1}), Entry("descending", []uint64{1, 3, 2}), Entry("removed", []uint64{}), Entry("rewritten", []uint64{2}))

	It("persists private rotation, revocation and recovery metadata", func() {
		key := create("lifecycle-key")
		confirmed := confirm(key)
		confirmed.SetVersions(append(confirmed.GetVersions(), version(3)))
		confirmed.SetLastRotationTimestamp(timestamppb.Now())
		confirmed.SetState(privatev1.ManagedKeyState_MANAGED_KEY_STATE_REVOKED)
		confirmed.SetRevocationTimestamp(timestamppb.Now())
		response, err := private.Update(ctx, privatev1.ManagedKeysUpdateRequest_builder{Object: confirmed}.Build())
		Expect(err).ToNot(HaveOccurred())
		revoked := response.GetObject()
		revoked.SetState(privatev1.ManagedKeyState_MANAGED_KEY_STATE_ACTIVE)
		revoked.ClearRevocationTimestamp()
		response, err = private.Update(ctx, privatev1.ManagedKeysUpdateRequest_builder{Object: revoked}.Build())
		Expect(err).ToNot(HaveOccurred())
		Expect(response.GetObject().GetVersions()).To(HaveLen(2))
		Expect(response.GetObject().GetLastRotationTimestamp()).ToNot(BeNil())
		Expect(response.GetObject().GetRevocationTimestamp()).To(BeNil())
	})

	It("rejects shared ownership and an administrator's implicit shared default", func() {
		assignable = auth.AllTenants
		defaultTenant = auth.SharedTenant
		_, err := public.Create(ctx, publicv1.ManagedKeysCreateRequest_builder{Object: publicv1.ManagedKey_builder{Metadata: publicv1.Metadata_builder{Name: "shared-key"}.Build()}.Build()}.Build())
		Expect(grpcstatus.Code(err)).To(Equal(grpccodes.PermissionDenied))
	})

	It("denies creating a key in an unassigned tenant", func() {
		_, err := public.Create(ctx, publicv1.ManagedKeysCreateRequest_builder{Object: publicv1.ManagedKey_builder{Metadata: publicv1.Metadata_builder{Name: "foreign-key", Tenant: "another-tenant"}.Build()}.Build()}.Build())
		Expect(grpcstatus.Code(err)).To(Equal(grpccodes.PermissionDenied))
	})

	It("allows provider administrators to create system-owned identities", func() {
		assignable = auth.AllTenants
		response, err := public.Create(ctx, publicv1.ManagedKeysCreateRequest_builder{Object: publicv1.ManagedKey_builder{Metadata: publicv1.Metadata_builder{Name: "provider-key", Tenant: auth.SystemTenant}.Build()}.Build()}.Build())
		Expect(err).ToNot(HaveOccurred())
		Expect(response.GetObject().GetMetadata().GetTenant()).To(Equal(auth.SystemTenant))
	})

	It("denies system creation even to a finite identity claiming system membership", func() {
		assignable = collections.NewSet(auth.SystemTenant)
		_, err := public.Create(ctx, publicv1.ManagedKeysCreateRequest_builder{Object: publicv1.ManagedKey_builder{Metadata: publicv1.Metadata_builder{Name: "provider-key", Tenant: auth.SystemTenant}.Build()}.Build()}.Build())
		Expect(grpcstatus.Code(err)).To(Equal(grpccodes.PermissionDenied))
	})

	It("denies implicit system creation for a finite identity", func() {
		assignable = collections.NewSet(auth.SystemTenant)
		defaultTenant = auth.SystemTenant
		_, err := public.Create(ctx, publicv1.ManagedKeysCreateRequest_builder{Object: publicv1.ManagedKey_builder{Metadata: publicv1.Metadata_builder{Name: "implicit-system"}.Build()}.Build()}.Build())
		Expect(grpcstatus.Code(err)).To(Equal(grpccodes.PermissionDenied))
	})

	It("enforces tenant and project visibility on list, get, update, delete and signal", func() {
		key := create("hidden-key")
		visibility, _ = auth.NewVisibility().AddVisibleTenant("another-tenant").Build()
		response, err := public.List(ctx, &publicv1.ManagedKeysListRequest{})
		Expect(err).ToNot(HaveOccurred())
		Expect(response.GetItems()).To(BeEmpty())
		_, err = public.Get(ctx, publicv1.ManagedKeysGetRequest_builder{Id: key.GetId()}.Build())
		Expect(grpcstatus.Code(err)).To(Equal(grpccodes.NotFound))
		_, err = public.Update(ctx, publicv1.ManagedKeysUpdateRequest_builder{Object: key}.Build())
		Expect(grpcstatus.Code(err)).To(Equal(grpccodes.NotFound))
		_, err = public.Delete(ctx, publicv1.ManagedKeysDeleteRequest_builder{Id: key.GetId()}.Build())
		Expect(grpcstatus.Code(err)).To(Equal(grpccodes.NotFound))
		_, err = private.Signal(ctx, privatev1.ManagedKeysSignalRequest_builder{Id: key.GetId()}.Build())
		Expect(grpcstatus.Code(err)).To(Equal(grpccodes.NotFound))
	})

	It("isolates named projects and allows the same name in different scopes", func() {
		projects, err := NewPrivateProjectsServer().SetLogger(logger).SetAttributionLogic(attribution).SetTenancyLogic(keyTenancy).Build()
		Expect(err).ToNot(HaveOccurred())
		for _, name := range []string{"visible", "hidden"} {
			_, err = projects.Create(ctx, privatev1.ProjectsCreateRequest_builder{Object: privatev1.Project_builder{
				Metadata: privatev1.Metadata_builder{Name: name}.Build(), Spec: privatev1.ProjectSpec_builder{Title: name}.Build(),
			}.Build()}.Build())
			Expect(err).ToNot(HaveOccurred())
		}
		keys := map[string]*publicv1.ManagedKey{}
		for _, project := range []string{"", "visible", "hidden"} {
			response, err := public.Create(ctx, publicv1.ManagedKeysCreateRequest_builder{Object: publicv1.ManagedKey_builder{Metadata: publicv1.Metadata_builder{Name: "same-name", Project: project}.Build()}.Build()}.Build())
			Expect(err).ToNot(HaveOccurred())
			keys[project] = response.GetObject()
		}
		visibility, err = auth.NewVisibility().AddVisibleTenant(testTenant).AddVisibleProject(testTenant, "visible").Build()
		Expect(err).ToNot(HaveOccurred())
		response, err := public.List(ctx, &publicv1.ManagedKeysListRequest{})
		Expect(err).ToNot(HaveOccurred())
		Expect(response.GetTotal()).To(Equal(int32(2)))
		_, err = public.Get(ctx, publicv1.ManagedKeysGetRequest_builder{Id: keys["hidden"].GetId()}.Build())
		Expect(grpcstatus.Code(err)).To(Equal(grpccodes.NotFound))
		_, err = public.Create(ctx, publicv1.ManagedKeysCreateRequest_builder{Object: publicv1.ManagedKey_builder{Metadata: publicv1.Metadata_builder{Name: "denied", Project: "hidden"}.Build()}.Build()}.Build())
		Expect(grpcstatus.Code(err)).To(Equal(grpccodes.PermissionDenied))
	})

	It("reserves names within tenant/project scope", func() {
		create("duplicate-key")
		_, err := public.Create(ctx, publicv1.ManagedKeysCreateRequest_builder{Object: publicv1.ManagedKey_builder{Metadata: publicv1.Metadata_builder{Name: "duplicate-key"}.Build()}.Build()}.Build())
		Expect(grpcstatus.Code(err)).To(Equal(grpccodes.AlreadyExists))
	})

	It("records Signal and archives a deleted identity", func() {
		key := create("deleted-key")
		_, err := private.Signal(ctx, privatev1.ManagedKeysSignalRequest_builder{Id: key.GetId()}.Build())
		Expect(err).ToNot(HaveOccurred())
		var count int
		Expect(suiteTx.QueryRow(ctx, `select count(*) from changes where "table" = 'managed_keys' and op = 'SIGNAL' and data->>'id' = $1`, key.GetId()).Scan(&count)).To(Succeed())
		Expect(count).To(Equal(1))
		_, err = public.Delete(ctx, publicv1.ManagedKeysDeleteRequest_builder{Id: key.GetId()}.Build())
		Expect(err).ToNot(HaveOccurred())
		_, err = public.Get(ctx, publicv1.ManagedKeysGetRequest_builder{Id: key.GetId()}.Build())
		Expect(grpcstatus.Code(err)).To(Equal(grpccodes.NotFound))
		Expect(suiteTx.QueryRow(ctx, `select count(*) from archived_managed_keys where id = $1`, key.GetId()).Scan(&count)).To(Succeed())
		Expect(count).To(Equal(1))
	})

	It("supports REST create, masked patch and get through generated bindings", func() {
		mux := runtime.NewServeMux()
		Expect(publicv1.RegisterManagedKeysHandlerServer(ctx, mux, public)).To(Succeed())
		request := httptest.NewRequest(http.MethodPost, "/api/fulfillment/v1/managed_keys", strings.NewReader(`{"metadata":{"name":"rest-key"}}`)).WithContext(ctx)
		request.Header.Set("Content-Type", "application/json")
		result := httptest.NewRecorder()
		mux.ServeHTTP(result, request)
		Expect(result.Code).To(Equal(http.StatusOK), result.Body.String())
		listed, err := public.List(ctx, &publicv1.ManagedKeysListRequest{})
		Expect(err).ToNot(HaveOccurred())
		key := listed.GetItems()[0]
		request = httptest.NewRequest(http.MethodPatch, "/api/fulfillment/v1/managed_keys/"+key.GetId(), strings.NewReader(`{"metadata":{"description":"from REST"}}`)).WithContext(ctx)
		request.Header.Set("Content-Type", "application/json")
		result = httptest.NewRecorder()
		mux.ServeHTTP(result, request)
		Expect(result.Code).To(Equal(http.StatusOK), result.Body.String())
		fetched, err := public.Get(ctx, publicv1.ManagedKeysGetRequest_builder{Id: key.GetId()}.Build())
		Expect(err).ToNot(HaveOccurred())
		Expect(fetched.GetObject().GetMetadata().GetDescription()).To(Equal("from REST"))
	})

	It("validates missing objects and names without panicking", func() {
		_, err := public.Create(ctx, &publicv1.ManagedKeysCreateRequest{})
		Expect(grpcstatus.Code(err)).To(Equal(grpccodes.InvalidArgument))
		_, err = private.Create(ctx, privatev1.ManagedKeysCreateRequest_builder{Object: &privatev1.ManagedKey{}}.Build())
		Expect(grpcstatus.Code(err)).To(Equal(grpccodes.InvalidArgument))
		_, err = public.Update(ctx, &publicv1.ManagedKeysUpdateRequest{})
		Expect(grpcstatus.Code(err)).To(Equal(grpccodes.InvalidArgument))
		_, err = private.Update(ctx, &privatev1.ManagedKeysUpdateRequest{})
		Expect(grpcstatus.Code(err)).To(Equal(grpccodes.InvalidArgument))
	})

	// Keep the test fixture tied to the standard DAO rather than a separate persistence model.
	It("stores only resource metadata and JSON lifecycle data", func() {
		key := create("json-key")
		confirmed := confirm(key)
		keys, err := dao.NewGenericDAO[*privatev1.ManagedKey]().SetLogger(logger).SetTenancyLogic(keyTenancy).Build()
		Expect(err).ToNot(HaveOccurred())
		response, err := keys.Get().SetId(key.GetId()).Do(ctx)
		Expect(err).ToNot(HaveOccurred())
		Expect(proto.Equal(response.GetObject(), confirmed)).To(BeTrue())
	})
})
