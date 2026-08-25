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
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	clnt "sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("HubClientProvider", func() {
	var (
		ctrl              *gomock.Controller
		mockHubLookup     *MockHubLookup
		provider          HubClientProvider
		ctx               context.Context
		testKubeconfig    []byte
		testNamespace     string
		hubID             string
		mockClientFactory HubClientFactory
	)

	BeforeEach(func() {
		ctrl = gomock.NewController(GinkgoT())
		mockHubLookup = NewMockHubLookup(ctrl)
		ctx = context.Background()
		// Minimal valid kubeconfig for testing
		testKubeconfig = []byte(`
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://test-server:6443
  name: test-cluster
contexts:
- context:
    cluster: test-cluster
    user: test-user
  name: test-context
current-context: test-context
users:
- name: test-user
  user:
    token: test-token
`)
		testNamespace = "test-namespace"
		hubID = "test-hub-id"

		// Mock client factory that returns a fake client
		mockClientFactory = func(config *rest.Config) (clnt.Client, error) {
			scheme := runtime.NewScheme()
			return clnt.New(config, clnt.Options{Scheme: scheme})
		}

		var err error
		provider, err = NewHubClientProvider().
			SetHubLookup(mockHubLookup).
			SetHubClientFactory(mockClientFactory).
			Build()
		Expect(err).ToNot(HaveOccurred())
	})

	AfterEach(func() {
		ctrl.Finish()
	})

	Describe("GetClient", func() {
		Context("when called multiple times for the same hub", func() {
			It("validates authorization on every request, even for cached clients", func() {
				// Expect GetKubeconfig to be called on first request
				mockHubLookup.EXPECT().
					GetKubeconfig(gomock.Any(), hubID).
					Return(testKubeconfig, testNamespace, nil).
					Times(1)

				// First call - should cache the client
				info1, err := provider.GetClient(ctx, hubID)
				Expect(err).ToNot(HaveOccurred())
				Expect(info1).ToNot(BeNil())
				Expect(info1.Namespace).To(Equal(testNamespace))

				// Expect GetKubeconfig to be called AGAIN on second request
				// This ensures authorization is validated even for cached clients
				mockHubLookup.EXPECT().
					GetKubeconfig(gomock.Any(), hubID).
					Return(testKubeconfig, testNamespace, nil).
					Times(1)

				// Second call - should validate auth before returning cached client
				info2, err := provider.GetClient(ctx, hubID)
				Expect(err).ToNot(HaveOccurred())
				Expect(info2).ToNot(BeNil())
				Expect(info2.Namespace).To(Equal(testNamespace))

				// The cached client should be reused (same pointer)
				Expect(info2.Client).To(BeIdenticalTo(info1.Client))
			})
		})

		Context("when authorization fails on second request", func() {
			It("returns an error instead of returning the cached client", func() {
				// First request succeeds
				mockHubLookup.EXPECT().
					GetKubeconfig(gomock.Any(), hubID).
					Return(testKubeconfig, testNamespace, nil).
					Times(1)

				info1, err := provider.GetClient(ctx, hubID)
				Expect(err).ToNot(HaveOccurred())
				Expect(info1).ToNot(BeNil())

				// Second request fails authorization (e.g., token expired, user revoked)
				mockHubLookup.EXPECT().
					GetKubeconfig(gomock.Any(), hubID).
					Return(nil, "", status.Errorf(codes.PermissionDenied, "access denied")).
					Times(1)

				// Second call should fail, not return the cached client
				info2, err := provider.GetClient(ctx, hubID)
				Expect(err).To(HaveOccurred())
				Expect(info2).To(BeNil())
				Expect(status.Code(err)).To(Equal(codes.PermissionDenied))
			})
		})

		Context("when hub is not found", func() {
			It("returns a NotFound error", func() {
				mockHubLookup.EXPECT().
					GetKubeconfig(gomock.Any(), hubID).
					Return(nil, "", status.Errorf(codes.NotFound, "hub not found")).
					Times(1)

				info, err := provider.GetClient(ctx, hubID)
				Expect(err).To(HaveOccurred())
				Expect(info).To(BeNil())
				Expect(status.Code(err)).To(Equal(codes.NotFound))
			})
		})

		Context("when namespace is empty", func() {
			It("returns an Internal error", func() {
				mockHubLookup.EXPECT().
					GetKubeconfig(gomock.Any(), hubID).
					Return(testKubeconfig, "", nil).
					Times(1)

				info, err := provider.GetClient(ctx, hubID)
				Expect(err).To(HaveOccurred())
				Expect(info).To(BeNil())
				Expect(status.Code(err)).To(Equal(codes.Internal))
				Expect(err.Error()).To(ContainSubstring("empty namespace"))
			})
		})

		Context("when kubeconfig is invalid", func() {
			It("returns an Internal error", func() {
				invalidKubeconfig := []byte("invalid-yaml")
				mockHubLookup.EXPECT().
					GetKubeconfig(gomock.Any(), hubID).
					Return(invalidKubeconfig, testNamespace, nil).
					Times(1)

				info, err := provider.GetClient(ctx, hubID)
				Expect(err).To(HaveOccurred())
				Expect(info).To(BeNil())
				Expect(status.Code(err)).To(Equal(codes.Internal))
				Expect(err.Error()).To(ContainSubstring("failed to parse kubeconfig"))
			})
		})

		Context("when client factory fails", func() {
			It("returns an Internal error", func() {
				failingFactory := func(config *rest.Config) (clnt.Client, error) {
					return nil, fmt.Errorf("client creation failed")
				}

				provider, err := NewHubClientProvider().
					SetHubLookup(mockHubLookup).
					SetHubClientFactory(failingFactory).
					Build()
				Expect(err).ToNot(HaveOccurred())

				mockHubLookup.EXPECT().
					GetKubeconfig(gomock.Any(), hubID).
					Return(testKubeconfig, testNamespace, nil).
					Times(1)

				info, err := provider.GetClient(ctx, hubID)
				Expect(err).To(HaveOccurred())
				Expect(info).To(BeNil())
				Expect(status.Code(err)).To(Equal(codes.Internal))
				Expect(err.Error()).To(ContainSubstring("failed to create client"))
			})
		})
	})

	Describe("Builder", func() {
		It("requires hub lookup", func() {
			_, err := NewHubClientProvider().
				SetHubClientFactory(mockClientFactory).
				Build()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("hub lookup is mandatory"))
		})

		It("requires hub client factory", func() {
			_, err := NewHubClientProvider().
				SetHubLookup(mockHubLookup).
				Build()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("hub client factory is mandatory"))
		})
	})
})
