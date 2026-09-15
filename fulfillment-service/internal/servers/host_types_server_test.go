/*
Copyright (c) 2025 Red Hat Inc.

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

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	grpccodes "google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/osac-project/osac/fulfillment-service/internal/database"
	"github.com/osac-project/osac/fulfillment-service/internal/services"
	publicv1 "github.com/osac-project/osac/proto/gen/osac/public/v1"
)

var _ = Describe("Host types server", func() {
	Describe("Creation", func() {
		It("Can be built if all the required parameters are set", func() {
			server, err := NewHostTypesServer().
				SetLogger(logger).
				SetAttributionLogic(attribution).
				SetTenancyLogic(tenancy).
				Build()
			Expect(err).ToNot(HaveOccurred())
			Expect(server).ToNot(BeNil())
		})

		It("Fails if logger is not set", func() {
			server, err := NewHostTypesServer().
				SetAttributionLogic(attribution).
				SetTenancyLogic(tenancy).
				Build()
			Expect(err).To(MatchError("logger is mandatory"))
			Expect(server).To(BeNil())
		})

		It("Fails if attribution logic is not set", func() {
			server, err := NewHostTypesServer().
				SetLogger(logger).
				SetTenancyLogic(tenancy).
				Build()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("attribution logic is mandatory"))
			Expect(server).To(BeNil())
		})

		It("Fails if tenancy logic is not set", func() {
			server, err := NewHostTypesServer().
				SetLogger(logger).
				SetAttributionLogic(attribution).
				Build()
			Expect(err).To(MatchError("tenancy logic is mandatory"))
			Expect(server).To(BeNil())
		})
	})

	Describe("Behaviour", func() {
		var server *HostTypesServer
		newServer := func(flags *services.Flags) *HostTypesServer {
			result, err := NewHostTypesServer().
				SetLogger(logger).
				SetAttributionLogic(attribution).
				SetTenancyLogic(tenancy).
				SetServiceFlags(flags).
				Build()
			Expect(err).ToNot(HaveOccurred())
			return result
		}

		BeforeEach(func() {
			server = newServer(nil)
		})

		It("Creates object", func() {
			response, err := server.Create(ctx, publicv1.HostTypesCreateRequest_builder{
				Object: publicv1.HostType_builder{
					Metadata: publicv1.Metadata_builder{
						Name: fmt.Sprintf("test-%s", uuid.NewString()[:8]),
					}.Build(),
				}.Build(),
			}.Build())
			Expect(err).ToNot(HaveOccurred())
			Expect(response).ToNot(BeNil())
			object := response.GetObject()
			Expect(object).ToNot(BeNil())
			Expect(object.GetId()).ToNot(BeEmpty())
		})

		It("Creates object with interfaces", func() {
			interfaces := []*publicv1.NetworkInterface{
				publicv1.NetworkInterface_builder{
					Name:        "data-0",
					Role:        "fabric",
					Description: "100GbE data interface",
				}.Build(),
				publicv1.NetworkInterface_builder{
					Name:        "data-1",
					Role:        "fabric",
					Description: "100GbE data interface",
				}.Build(),
				publicv1.NetworkInterface_builder{
					Name:        "mgmt-0",
					Role:        "management",
					Description: "1GbE management interface",
				}.Build(),
			}
			createResponse, err := server.Create(ctx, publicv1.HostTypesCreateRequest_builder{
				Object: publicv1.HostType_builder{
					Metadata: publicv1.Metadata_builder{
						Name: fmt.Sprintf("test-%s", uuid.NewString()[:8]),
					}.Build(),
					Title:      "BM host type",
					Interfaces: interfaces,
				}.Build(),
			}.Build())
			Expect(err).ToNot(HaveOccurred())
			object := createResponse.GetObject()
			Expect(object.GetInterfaces()).To(HaveLen(3))
			Expect(object.GetInterfaces()[0].GetName()).To(Equal("data-0"))
			Expect(object.GetInterfaces()[0].GetRole()).To(Equal("fabric"))
			Expect(object.GetInterfaces()[0].GetDescription()).To(Equal("100GbE data interface"))
			Expect(object.GetInterfaces()[1].GetName()).To(Equal("data-1"))
			Expect(object.GetInterfaces()[2].GetName()).To(Equal("mgmt-0"))
			Expect(object.GetInterfaces()[2].GetRole()).To(Equal("management"))

			getResponse, err := server.Get(ctx, publicv1.HostTypesGetRequest_builder{
				Id: object.GetId(),
			}.Build())
			Expect(err).ToNot(HaveOccurred())
			Expect(proto.Equal(createResponse.GetObject(), getResponse.GetObject())).To(BeTrue())
		})

		It("Creates object without interfaces", func() {
			createResponse, err := server.Create(ctx, publicv1.HostTypesCreateRequest_builder{
				Object: publicv1.HostType_builder{
					Metadata: publicv1.Metadata_builder{
						Name: fmt.Sprintf("test-%s", uuid.NewString()[:8]),
					}.Build(),
					Title: "VM host type",
				}.Build(),
			}.Build())
			Expect(err).ToNot(HaveOccurred())
			object := createResponse.GetObject()
			Expect(object.GetInterfaces()).To(BeEmpty())
		})

		It("Updates object interfaces", func() {
			createResponse, err := server.Create(ctx, publicv1.HostTypesCreateRequest_builder{
				Object: publicv1.HostType_builder{
					Metadata: publicv1.Metadata_builder{
						Name: fmt.Sprintf("test-%s", uuid.NewString()[:8]),
					}.Build(),
					Title: "BM host type",
				}.Build(),
			}.Build())
			Expect(err).ToNot(HaveOccurred())
			object := createResponse.GetObject()
			Expect(object.GetInterfaces()).To(BeEmpty())
			name := object.GetMetadata().GetName()
			updateResponse, err := server.Update(ctx, publicv1.HostTypesUpdateRequest_builder{
				Object: publicv1.HostType_builder{
					Id:       object.GetId(),
					Metadata: publicv1.Metadata_builder{Name: name}.Build(),
					Title:    "BM host type",
					Interfaces: []*publicv1.NetworkInterface{
						publicv1.NetworkInterface_builder{
							Name:        "data-0",
							Role:        "fabric",
							Description: "100GbE data interface",
						}.Build(),
					},
				}.Build(),
			}.Build())
			Expect(err).ToNot(HaveOccurred())
			Expect(updateResponse.GetObject().GetInterfaces()).To(HaveLen(1))
			Expect(updateResponse.GetObject().GetInterfaces()[0].GetName()).To(Equal("data-0"))

			getResponse, err := server.Get(ctx, publicv1.HostTypesGetRequest_builder{
				Id: object.GetId(),
			}.Build())
			Expect(err).ToNot(HaveOccurred())
			Expect(getResponse.GetObject().GetInterfaces()).To(HaveLen(1))
			Expect(getResponse.GetObject().GetInterfaces()[0].GetName()).To(Equal("data-0"))
		})

		It("List objects", func() {
			// Create a few objects:
			const count = 10
			for range count {
				_, err := server.Create(ctx, publicv1.HostTypesCreateRequest_builder{
					Object: publicv1.HostType_builder{
						Metadata: publicv1.Metadata_builder{
							Name: fmt.Sprintf("test-%s", uuid.NewString()[:8]),
						}.Build(),
					}.Build(),
				}.Build())
				Expect(err).ToNot(HaveOccurred())
			}

			// List the objects:
			response, err := server.List(ctx, publicv1.HostTypesListRequest_builder{}.Build())
			Expect(err).ToNot(HaveOccurred())
			Expect(response).ToNot(BeNil())
			items := response.GetItems()
			Expect(items).To(HaveLen(count))
		})

		It("List objects with limit", func() {
			// Create a few objects:
			const count = 10
			for range count {
				_, err := server.Create(ctx, publicv1.HostTypesCreateRequest_builder{
					Object: publicv1.HostType_builder{
						Metadata: publicv1.Metadata_builder{
							Name: fmt.Sprintf("test-%s", uuid.NewString()[:8]),
						}.Build(),
					}.Build(),
				}.Build())
				Expect(err).ToNot(HaveOccurred())
			}

			// List the objects:
			response, err := server.List(ctx, publicv1.HostTypesListRequest_builder{
				Limit: new(int32(1)),
			}.Build())
			Expect(err).ToNot(HaveOccurred())
			Expect(response.GetSize()).To(BeNumerically("==", 1))
		})

		It("List objects with offset", func() {
			// Create a few objects:
			const count = 10
			for range count {
				_, err := server.Create(ctx, publicv1.HostTypesCreateRequest_builder{
					Object: publicv1.HostType_builder{
						Metadata: publicv1.Metadata_builder{
							Name: fmt.Sprintf("test-%s", uuid.NewString()[:8]),
						}.Build(),
					}.Build(),
				}.Build())
				Expect(err).ToNot(HaveOccurred())
			}

			// List the objects:
			response, err := server.List(ctx, publicv1.HostTypesListRequest_builder{
				Offset: new(int32(1)),
			}.Build())
			Expect(err).ToNot(HaveOccurred())
			Expect(response.GetSize()).To(BeNumerically("==", count-1))
		})

		It("List objects with filter", func() {
			// Create a few objects:
			const count = 10
			var objects []*publicv1.HostType
			for range count {
				response, err := server.Create(ctx, publicv1.HostTypesCreateRequest_builder{
					Object: publicv1.HostType_builder{
						Metadata: publicv1.Metadata_builder{
							Name: fmt.Sprintf("test-%s", uuid.NewString()[:8]),
						}.Build(),
					}.Build(),
				}.Build())
				Expect(err).ToNot(HaveOccurred())
				objects = append(objects, response.GetObject())
			}

			// List the objects:
			for _, object := range objects {
				response, err := server.List(ctx, publicv1.HostTypesListRequest_builder{
					Filter: new(fmt.Sprintf("this.id == '%s'", object.GetId())),
				}.Build())
				Expect(err).ToNot(HaveOccurred())
				Expect(response.GetSize()).To(BeNumerically("==", 1))
				Expect(response.GetItems()[0].GetId()).To(Equal(object.GetId()))
			}
		})

		DescribeTable("filters host types by enabled compute services", func(flags *services.Flags, expectedIDs func(bareMetalID, virtualID string) []string) {
			testServer := newServer(flags)
			bareMetalResponse, err := testServer.Create(ctx, publicv1.HostTypesCreateRequest_builder{
				Object: publicv1.HostType_builder{
					Metadata: publicv1.Metadata_builder{
						Name: fmt.Sprintf("test-bm-%s", uuid.NewString()[:8]),
					}.Build(),
					Title: "BM host type",
					Interfaces: []*publicv1.NetworkInterface{
						publicv1.NetworkInterface_builder{Name: "data-0"}.Build(),
					},
				}.Build(),
			}.Build())
			Expect(err).ToNot(HaveOccurred())

			virtualResponse, err := testServer.Create(ctx, publicv1.HostTypesCreateRequest_builder{
				Object: publicv1.HostType_builder{
					Metadata: publicv1.Metadata_builder{
						Name: fmt.Sprintf("test-vm-%s", uuid.NewString()[:8]),
					}.Build(),
					Title: "VM host type",
				}.Build(),
			}.Build())
			Expect(err).ToNot(HaveOccurred())

			response, err := testServer.List(ctx, publicv1.HostTypesListRequest_builder{}.Build())
			Expect(err).ToNot(HaveOccurred())
			actualIDs := make([]string, 0, len(response.GetItems()))
			for _, item := range response.GetItems() {
				actualIDs = append(actualIDs, item.GetId())
			}
			Expect(actualIDs).To(ConsistOf(expectedIDs(
				bareMetalResponse.GetObject().GetId(),
				virtualResponse.GetObject().GetId(),
			)))
		},
			Entry("no service flags preserves all host types", nil, func(bareMetalID, virtualID string) []string {
				return []string{bareMetalID, virtualID}
			}),
			Entry("both compute services enabled preserves all host types", &services.Flags{CaaS: true, VMaaS: true, BMaaS: true}, func(bareMetalID, virtualID string) []string {
				return []string{bareMetalID, virtualID}
			}),
			Entry("BMaaS disabled returns virtual host types", &services.Flags{CaaS: true, VMaaS: true}, func(_, virtualID string) []string {
				return []string{virtualID}
			}),
			Entry("VMaaS disabled returns bare-metal host types", &services.Flags{CaaS: true, BMaaS: true}, func(bareMetalID, _ string) []string {
				return []string{bareMetalID}
			}),
			Entry("both compute services disabled returns no host types", &services.Flags{}, func(_, _ string) []string {
				return []string{}
			}),
		)

		It("applies service filtering in addition to the client filter", func() {
			testServer := newServer(&services.Flags{CaaS: true, VMaaS: true})
			bareMetalResponse, err := testServer.Create(ctx, publicv1.HostTypesCreateRequest_builder{
				Object: publicv1.HostType_builder{
					Metadata: publicv1.Metadata_builder{
						Name: fmt.Sprintf("test-bm-filter-%s", uuid.NewString()[:8]),
					}.Build(),
					Interfaces: []*publicv1.NetworkInterface{
						publicv1.NetworkInterface_builder{Name: "data-0"}.Build(),
					},
				}.Build(),
			}.Build())
			Expect(err).ToNot(HaveOccurred())

			response, err := testServer.List(ctx, publicv1.HostTypesListRequest_builder{
				Filter: new(fmt.Sprintf("this.id == '%s'", bareMetalResponse.GetObject().GetId())),
			}.Build())
			Expect(err).ToNot(HaveOccurred())
			Expect(response.GetItems()).To(BeEmpty())
		})

		It("returns NotFound for a host type belonging to a disabled service", func() {
			seedServer := newServer(&services.Flags{CaaS: true, VMaaS: true, BMaaS: true})
			bareMetalResponse, err := seedServer.Create(ctx, publicv1.HostTypesCreateRequest_builder{
				Object: publicv1.HostType_builder{
					Metadata: publicv1.Metadata_builder{
						Name: fmt.Sprintf("test-bm-get-%s", uuid.NewString()[:8]),
					}.Build(),
					Interfaces: []*publicv1.NetworkInterface{
						publicv1.NetworkInterface_builder{Name: "data-0"}.Build(),
					},
				}.Build(),
			}.Build())
			Expect(err).ToNot(HaveOccurred())

			virtualResponse, err := seedServer.Create(ctx, publicv1.HostTypesCreateRequest_builder{
				Object: publicv1.HostType_builder{
					Metadata: publicv1.Metadata_builder{
						Name: fmt.Sprintf("test-vm-get-%s", uuid.NewString()[:8]),
					}.Build(),
				}.Build(),
			}.Build())
			Expect(err).ToNot(HaveOccurred())

			testServer := newServer(&services.Flags{CaaS: true, VMaaS: true, BMaaS: false})
			_, err = testServer.Get(ctx, publicv1.HostTypesGetRequest_builder{
				Id: bareMetalResponse.GetObject().GetId(),
			}.Build())
			Expect(grpcstatus.Code(err)).To(Equal(grpccodes.NotFound))

			response, err := testServer.Get(ctx, publicv1.HostTypesGetRequest_builder{
				Id: virtualResponse.GetObject().GetId(),
			}.Build())
			Expect(err).ToNot(HaveOccurred())
			Expect(response.GetObject().GetId()).To(Equal(virtualResponse.GetObject().GetId()))
		})

		It("Get object", func() {
			// Create the object:
			createResponse, err := server.Create(ctx, publicv1.HostTypesCreateRequest_builder{
				Object: publicv1.HostType_builder{
					Metadata: publicv1.Metadata_builder{
						Name: fmt.Sprintf("test-%s", uuid.NewString()[:8]),
					}.Build(),
				}.Build(),
			}.Build())
			Expect(err).ToNot(HaveOccurred())

			// Get it:
			getResponse, err := server.Get(ctx, publicv1.HostTypesGetRequest_builder{
				Id: createResponse.GetObject().GetId(),
			}.Build())
			Expect(err).ToNot(HaveOccurred())
			Expect(proto.Equal(createResponse.GetObject(), getResponse.GetObject())).To(BeTrue())
		})

		It("Update object", func() {
			// Create the object:
			createResponse, err := server.Create(ctx, publicv1.HostTypesCreateRequest_builder{
				Object: publicv1.HostType_builder{
					Metadata: publicv1.Metadata_builder{
						Name: fmt.Sprintf("test-%s", uuid.NewString()[:8]),
					}.Build(),
					Title:       "My title",
					Description: "My description.",
				}.Build(),
			}.Build())
			Expect(err).ToNot(HaveOccurred())
			object := createResponse.GetObject()
			name := object.GetMetadata().GetName()
			// Update the object:
			updateResponse, err := server.Update(ctx, publicv1.HostTypesUpdateRequest_builder{
				Object: publicv1.HostType_builder{
					Id:          object.GetId(),
					Metadata:    publicv1.Metadata_builder{Name: name}.Build(),
					Title:       "Your title",
					Description: "Your description.",
				}.Build(),
			}.Build())
			Expect(err).ToNot(HaveOccurred())
			Expect(updateResponse.GetObject().GetTitle()).To(Equal("Your title"))
			Expect(updateResponse.GetObject().GetDescription()).To(Equal("Your description."))

			// Get and verify:
			getResponse, err := server.Get(ctx, publicv1.HostTypesGetRequest_builder{
				Id: object.GetId(),
			}.Build())
			Expect(err).ToNot(HaveOccurred())
			Expect(getResponse.GetObject().GetTitle()).To(Equal("Your title"))
			Expect(getResponse.GetObject().GetDescription()).To(Equal("Your description."))
		})

		It("Delete object", func() {
			// Create the object:
			createResponse, err := server.Create(ctx, publicv1.HostTypesCreateRequest_builder{
				Object: publicv1.HostType_builder{
					Metadata: publicv1.Metadata_builder{
						Name: fmt.Sprintf("test-%s", uuid.NewString()[:8]),
					}.Build(),
				}.Build(),
			}.Build())
			Expect(err).ToNot(HaveOccurred())
			object := createResponse.GetObject()

			// Add a finalizer, as otherwise the object will be immediately deleted and archived and it
			// won't be possible to verify the deletion timestamp. This can't be done using the server
			// because this is a public object, and public objects don't have the finalizers field.
			tx, err := database.TxFromContext(ctx)
			Expect(err).ToNot(HaveOccurred())
			_, err = tx.Exec(
				ctx,
				`update host_types set finalizers = '{"a"}' where id = $1`,
				object.GetId(),
			)
			Expect(err).ToNot(HaveOccurred())

			// Delete the object:
			_, err = server.Delete(ctx, publicv1.HostTypesDeleteRequest_builder{
				Id: object.GetId(),
			}.Build())
			Expect(err).ToNot(HaveOccurred())

			// Get and verify:
			getResponse, err := server.Get(ctx, publicv1.HostTypesGetRequest_builder{
				Id: object.GetId(),
			}.Build())
			Expect(err).ToNot(HaveOccurred())
			object = getResponse.GetObject()
			Expect(object.GetMetadata().GetDeletionTimestamp()).ToNot(BeNil())
		})
	})
})
