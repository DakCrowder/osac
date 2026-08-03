/*
Copyright (c) 2026 Red Hat Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License.
*/

package it

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	grpccodes "google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	privatev1 "github.com/osac-project/fulfillment-service/internal/api/osac/private/v1"
	"github.com/osac-project/fulfillment-service/internal/uuid"
)

var _ = Describe("Secrets", func() {
	var (
		ctx    context.Context
		client privatev1.SecretsClient
	)

	BeforeEach(func() {
		ctx = context.Background()
		client = privatev1.NewSecretsClient(tool.InternalView().AdminConn())
	})

	createSecret := func(tenant, name string, data map[string][]byte) *privatev1.Secret {
		resp, err := client.Create(ctx, privatev1.SecretsCreateRequest_builder{
			Object: privatev1.Secret_builder{
				Metadata: privatev1.Metadata_builder{
					Name:   name,
					Tenant: tenant,
				}.Build(),
				Spec: privatev1.SecretSpec_builder{
					Data: data,
				}.Build(),
			}.Build(),
		}.Build())
		Expect(err).ToNot(HaveOccurred())
		obj := resp.GetObject()
		DeferCleanup(func() {
			_, _ = client.Delete(context.Background(), privatev1.SecretsDeleteRequest_builder{
				Id: obj.GetId(),
			}.Build())
		})
		return obj
	}

	Describe("Vault-backed CRUD", func() {
		It("Creates a secret and retrieves resolved data from vault", func() {
			name := fmt.Sprintf("secret-%s", uuid.New())
			data := map[string][]byte{
				"tls.crt": []byte("-----BEGIN CERTIFICATE-----"),
				"tls.key": []byte("-----BEGIN PRIVATE KEY-----"),
			}

			created := createSecret("engineering", name, data)
			Expect(created.GetId()).ToNot(BeEmpty())
			Expect(created.GetSpec().GetBackend()).To(Equal(
				privatev1.SecretBackend_SECRET_BACKEND_VAULT))

			getResp, err := client.Get(ctx, privatev1.SecretsGetRequest_builder{
				Id: created.GetId(),
			}.Build())
			Expect(err).ToNot(HaveOccurred())
			obj := getResp.GetObject()
			Expect(obj.GetStatus().GetResolvedData()).To(HaveKeyWithValue(
				"tls.crt", []byte("-----BEGIN CERTIFICATE-----")))
			Expect(obj.GetStatus().GetResolvedData()).To(HaveKeyWithValue(
				"tls.key", []byte("-----BEGIN PRIVATE KEY-----")))
		})

		It("Defaults unspecified backend to Vault", func() {
			name := fmt.Sprintf("secret-%s", uuid.New())
			created := createSecret("engineering", name, map[string][]byte{
				"token": []byte("my-token"),
			})
			Expect(created.GetSpec().GetBackend()).To(Equal(
				privatev1.SecretBackend_SECRET_BACKEND_VAULT))

			getResp, err := client.Get(ctx, privatev1.SecretsGetRequest_builder{
				Id: created.GetId(),
			}.Build())
			Expect(err).ToNot(HaveOccurred())
			Expect(getResp.GetObject().GetStatus().GetResolvedData()).To(
				HaveKeyWithValue("token", []byte("my-token")))
		})

		It("Updates secret data in vault", func() {
			name := fmt.Sprintf("secret-%s", uuid.New())
			created := createSecret("engineering", name, map[string][]byte{
				"key1": []byte("original"),
			})

			_, err := client.Update(ctx, privatev1.SecretsUpdateRequest_builder{
				Object: privatev1.Secret_builder{
					Id: created.GetId(),
					Spec: privatev1.SecretSpec_builder{
						Data: map[string][]byte{
							"key1": []byte("updated"),
							"key2": []byte("new-value"),
						},
					}.Build(),
				}.Build(),
				UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.data"}},
			}.Build())
			Expect(err).ToNot(HaveOccurred())

			getResp, err := client.Get(ctx, privatev1.SecretsGetRequest_builder{
				Id: created.GetId(),
			}.Build())
			Expect(err).ToNot(HaveOccurred())
			resolved := getResp.GetObject().GetStatus().GetResolvedData()
			Expect(resolved).To(HaveKeyWithValue("key1", []byte("updated")))
			Expect(resolved).To(HaveKeyWithValue("key2", []byte("new-value")))
		})

		It("Deletes secret from both database and vault", func() {
			name := fmt.Sprintf("secret-%s", uuid.New())
			created := createSecret("engineering", name, map[string][]byte{
				"key": []byte("value"),
			})

			_, err := client.Delete(ctx, privatev1.SecretsDeleteRequest_builder{
				Id: created.GetId(),
			}.Build())
			Expect(err).ToNot(HaveOccurred())

			_, err = client.Get(ctx, privatev1.SecretsGetRequest_builder{
				Id: created.GetId(),
			}.Build())
			Expect(err).To(HaveOccurred())
			st, ok := grpcstatus.FromError(err)
			Expect(ok).To(BeTrue())
			Expect(st.Code()).To(Equal(grpccodes.NotFound))
		})

		It("List does not include resolved data", func() {
			name1 := fmt.Sprintf("secret-%s", uuid.New())
			name2 := fmt.Sprintf("secret-%s", uuid.New())
			createSecret("engineering", name1, map[string][]byte{"k": []byte("v1")})
			createSecret("engineering", name2, map[string][]byte{"k": []byte("v2")})

			listResp, err := client.List(ctx, privatev1.SecretsListRequest_builder{
				Filter: proto.String(fmt.Sprintf(
					"this.metadata.tenant == 'engineering' && (this.metadata.name == '%s' || this.metadata.name == '%s')",
					name1, name2,
				)),
			}.Build())
			Expect(err).ToNot(HaveOccurred())
			Expect(listResp.GetItems()).To(HaveLen(2))
			for _, item := range listResp.GetItems() {
				Expect(item.GetStatus().GetResolvedData()).To(BeEmpty())
				Expect(item.GetSpec().GetData()).To(BeEmpty())
			}
		})
	})

	Describe("Tenant isolation", func() {
		It("Secrets in different tenants are isolated", func() {
			name := fmt.Sprintf("shared-name-%s", uuid.New())
			secretEng := createSecret("engineering", name, map[string][]byte{
				"data": []byte("engineering-data"),
			})
			secretDev := createSecret("development", name, map[string][]byte{
				"data": []byte("development-data"),
			})

			getEng, err := client.Get(ctx, privatev1.SecretsGetRequest_builder{
				Id: secretEng.GetId(),
			}.Build())
			Expect(err).ToNot(HaveOccurred())
			Expect(getEng.GetObject().GetStatus().GetResolvedData()).To(
				HaveKeyWithValue("data", []byte("engineering-data")))

			getDev, err := client.Get(ctx, privatev1.SecretsGetRequest_builder{
				Id: secretDev.GetId(),
			}.Build())
			Expect(err).ToNot(HaveOccurred())
			Expect(getDev.GetObject().GetStatus().GetResolvedData()).To(
				HaveKeyWithValue("data", []byte("development-data")))

			listEng, err := client.List(ctx, privatev1.SecretsListRequest_builder{
				Filter: proto.String(fmt.Sprintf("this.metadata.tenant == 'engineering' && this.metadata.name == '%s'", name)),
			}.Build())
			Expect(err).ToNot(HaveOccurred())
			Expect(listEng.GetItems()).To(HaveLen(1))
			Expect(listEng.GetItems()[0].GetMetadata().GetTenant()).To(Equal("engineering"))

			listDev, err := client.List(ctx, privatev1.SecretsListRequest_builder{
				Filter: proto.String(fmt.Sprintf("this.metadata.tenant == 'development' && this.metadata.name == '%s'", name)),
			}.Build())
			Expect(err).ToNot(HaveOccurred())
			Expect(listDev.GetItems()).To(HaveLen(1))
			Expect(listDev.GetItems()[0].GetMetadata().GetTenant()).To(Equal("development"))
		})
	})

	Describe("Hub backend", func() {
		It("Creates a Hub secret with coordinates", func() {
			name := fmt.Sprintf("hub-secret-%s", uuid.New())
			resp, err := client.Create(ctx, privatev1.SecretsCreateRequest_builder{
				Object: privatev1.Secret_builder{
					Metadata: privatev1.Metadata_builder{
						Name:   name,
						Tenant: "engineering",
					}.Build(),
					Spec: privatev1.SecretSpec_builder{
						Backend: privatev1.SecretBackend_SECRET_BACKEND_HUB,
						Coordinates: map[string]string{
							"cluster":   "hub-1",
							"namespace": "default",
							"name":      "my-k8s-secret",
						},
					}.Build(),
				}.Build(),
			}.Build())
			Expect(err).ToNot(HaveOccurred())
			obj := resp.GetObject()
			DeferCleanup(func() {
				_, _ = client.Delete(context.Background(), privatev1.SecretsDeleteRequest_builder{
					Id: obj.GetId(),
				}.Build())
			})

			Expect(obj.GetSpec().GetBackend()).To(Equal(
				privatev1.SecretBackend_SECRET_BACKEND_HUB))
			Expect(obj.GetSpec().GetCoordinates()).To(HaveKeyWithValue("cluster", "hub-1"))
			Expect(obj.GetSpec().GetData()).To(BeEmpty())

			getResp, err := client.Get(ctx, privatev1.SecretsGetRequest_builder{
				Id: obj.GetId(),
			}.Build())
			Expect(err).ToNot(HaveOccurred())
			Expect(getResp.GetObject().GetStatus().GetResolvedData()).To(BeEmpty())
		})
	})

	Describe("Validation", func() {
		It("Rejects changing backend on update", func() {
			name := fmt.Sprintf("secret-%s", uuid.New())
			created := createSecret("engineering", name, map[string][]byte{
				"key": []byte("value"),
			})

			_, err := client.Update(ctx, privatev1.SecretsUpdateRequest_builder{
				Object: privatev1.Secret_builder{
					Id: created.GetId(),
					Spec: privatev1.SecretSpec_builder{
						Backend: privatev1.SecretBackend_SECRET_BACKEND_HUB,
					}.Build(),
				}.Build(),
				UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.backend"}},
			}.Build())
			Expect(err).To(HaveOccurred())
			st, ok := grpcstatus.FromError(err)
			Expect(ok).To(BeTrue())
			Expect(st.Code()).To(Equal(grpccodes.InvalidArgument))
			Expect(st.Message()).To(ContainSubstring("immutable"))
		})

		It("Rejects Hub secret with data", func() {
			name := fmt.Sprintf("hub-secret-%s", uuid.New())
			_, err := client.Create(ctx, privatev1.SecretsCreateRequest_builder{
				Object: privatev1.Secret_builder{
					Metadata: privatev1.Metadata_builder{
						Name:   name,
						Tenant: "engineering",
					}.Build(),
					Spec: privatev1.SecretSpec_builder{
						Backend: privatev1.SecretBackend_SECRET_BACKEND_HUB,
						Coordinates: map[string]string{
							"cluster": "hub-1",
						},
						Data: map[string][]byte{
							"key": []byte("value"),
						},
					}.Build(),
				}.Build(),
			}.Build())
			Expect(err).To(HaveOccurred())
			st, ok := grpcstatus.FromError(err)
			Expect(ok).To(BeTrue())
			Expect(st.Code()).To(Equal(grpccodes.InvalidArgument))
			Expect(st.Message()).To(ContainSubstring("spec.data"))
		})
	})
})
