package reconciliation_test

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/osac-project/osac-metering/internal/events"
	"github.com/osac-project/osac-metering/internal/projection"
	"github.com/osac-project/osac-metering/internal/reconciliation"
	privatev1 "github.com/osac-project/osac/proto/gen/osac/private/v1"
)

type networkPoolClient struct {
	response *privatev1.ExternalIPPoolsListResponse
}

func (c networkPoolClient) List(context.Context, *privatev1.ExternalIPPoolsListRequest, ...grpc.CallOption) (*privatev1.ExternalIPPoolsListResponse, error) {
	return c.response, nil
}

func (c networkPoolClient) Get(_ context.Context, request *privatev1.ExternalIPPoolsGetRequest, _ ...grpc.CallOption) (*privatev1.ExternalIPPoolsGetResponse, error) {
	for _, pool := range c.response.GetItems() {
		if pool.GetId() == request.GetId() {
			return &privatev1.ExternalIPPoolsGetResponse{Object: pool}, nil
		}
	}
	return nil, fmt.Errorf("pool %s not found", request.GetId())
}

type networkExternalIPClient struct {
	items []*privatev1.ExternalIP
}

func (c networkExternalIPClient) List(context.Context, *privatev1.ExternalIPsListRequest, ...grpc.CallOption) (*privatev1.ExternalIPsListResponse, error) {
	return &privatev1.ExternalIPsListResponse{Total: int32(len(c.items)), Items: c.items}, nil
}

func (c networkExternalIPClient) Get(_ context.Context, request *privatev1.ExternalIPsGetRequest, _ ...grpc.CallOption) (*privatev1.ExternalIPsGetResponse, error) {
	for _, item := range c.items {
		if item.GetId() == request.GetId() {
			return &privatev1.ExternalIPsGetResponse{Object: item}, nil
		}
	}
	return nil, fmt.Errorf("external IP %s not found", request.GetId())
}

type networkNATGatewayClient struct {
	items []*privatev1.NATGateway
}

func (c networkNATGatewayClient) List(context.Context, *privatev1.NATGatewaysListRequest, ...grpc.CallOption) (*privatev1.NATGatewaysListResponse, error) {
	return &privatev1.NATGatewaysListResponse{Total: int32(len(c.items)), Items: c.items}, nil
}

func (c networkNATGatewayClient) Get(_ context.Context, request *privatev1.NATGatewaysGetRequest, _ ...grpc.CallOption) (*privatev1.NATGatewaysGetResponse, error) {
	for _, item := range c.items {
		if item.GetId() == request.GetId() {
			return &privatev1.NATGatewaysGetResponse{Object: item}, nil
		}
	}
	return nil, fmt.Errorf("NAT gateway %s not found", request.GetId())
}

var _ = Describe("ExternalIP pool loader", func() {
	It("does not fail reconciliation for pending networking resources without timestamps", func() {
		store := newMockStore()
		reconciler := reconciliation.NewReconciler(nil, nil, store, &mockPublisher{}, logr.Discard(), time.Hour)
		reconciler.SetNetworkingClients(
			networkExternalIPClient{items: []*privatev1.ExternalIP{{
				Id:       "ip-pending",
				Metadata: &privatev1.Metadata{Tenant: "tenant-1", Version: 1},
				Spec:     &privatev1.ExternalIPSpec{Pool: &privatev1.ExternalIPPoolReference{Id: "pool-1"}},
				Status:   &privatev1.ExternalIPStatus{State: privatev1.ExternalIPState_EXTERNAL_IP_STATE_PENDING},
			}}},
			networkNATGatewayClient{items: []*privatev1.NATGateway{{
				Id:       "nat-pending",
				Metadata: &privatev1.Metadata{Tenant: "tenant-1", Version: 1},
				Spec: &privatev1.NATGatewaySpec{
					VirtualNetwork: &privatev1.VirtualNetworkLocalReference{Id: "vnet-1"},
					ExternalIp:     &privatev1.ExternalIPLocalReference{Id: "ip-pending"},
				},
				Status: &privatev1.NATGatewayStatus{State: privatev1.NATGatewayState_NAT_GATEWAY_STATE_PENDING},
			}}},
			networkPoolClient{response: &privatev1.ExternalIPPoolsListResponse{
				Total: 1,
				Items: []*privatev1.ExternalIPPool{{
					Id:   "pool-1",
					Spec: &privatev1.ExternalIPPoolSpec{IpFamily: privatev1.IPFamily_IP_FAMILY_IPV4},
				}},
			}},
			"deployment-1",
		)

		Expect(reconciler.Reconcile(context.Background())).To(Succeed())
		Expect(store.states).To(BeEmpty())
	})

	It("fails reconciliation for a billable ExternalIP without a timestamp", func() {
		store := newMockStore()
		store.states["ip-billable"] = projection.ResourceState{
			ResourceID: "ip-billable",
			IsBillable: true,
		}
		reconciler := reconciliation.NewReconciler(nil, nil, store, &mockPublisher{}, logr.Discard(), time.Hour)
		reconciler.SetNetworkingClients(
			networkExternalIPClient{items: []*privatev1.ExternalIP{{
				Id:       "ip-billable",
				Metadata: &privatev1.Metadata{Tenant: "tenant-1", Version: 2},
				Spec:     &privatev1.ExternalIPSpec{Pool: &privatev1.ExternalIPPoolReference{Id: "pool-1"}},
				Status:   &privatev1.ExternalIPStatus{State: privatev1.ExternalIPState_EXTERNAL_IP_STATE_ALLOCATED},
			}}},
			nil,
			networkPoolClient{response: &privatev1.ExternalIPPoolsListResponse{
				Total: 1,
				Items: []*privatev1.ExternalIPPool{{
					Id:   "pool-1",
					Spec: &privatev1.ExternalIPPoolSpec{IpFamily: privatev1.IPFamily_IP_FAMILY_IPV4},
				}},
			}},
			"deployment-1",
		)

		Expect(reconciler.Reconcile(context.Background())).To(MatchError(ContainSubstring("no authoritative transition time")))
	})

	It("fails reconciliation for an unprojected billable ExternalIP without a timestamp", func() {
		store := newMockStore()
		reconciler := reconciliation.NewReconciler(nil, nil, store, &mockPublisher{}, logr.Discard(), time.Hour)
		reconciler.SetNetworkingClients(
			networkExternalIPClient{items: []*privatev1.ExternalIP{{
				Id:       "ip-unprojected",
				Metadata: &privatev1.Metadata{Tenant: "tenant-1", Version: 1},
				Spec:     &privatev1.ExternalIPSpec{Pool: &privatev1.ExternalIPPoolReference{Id: "pool-1"}},
				Status:   &privatev1.ExternalIPStatus{State: privatev1.ExternalIPState_EXTERNAL_IP_STATE_ALLOCATED},
			}}},
			nil,
			networkPoolClient{response: &privatev1.ExternalIPPoolsListResponse{
				Total: 1,
				Items: []*privatev1.ExternalIPPool{{
					Id:   "pool-1",
					Spec: &privatev1.ExternalIPPoolSpec{IpFamily: privatev1.IPFamily_IP_FAMILY_IPV4},
				}},
			}},
			"deployment-1",
		)

		Expect(reconciler.Reconcile(context.Background())).To(MatchError(ContainSubstring("no authoritative transition time")))
	})

	It("fails reconciliation for an unprojected billable NATGateway without a timestamp", func() {
		store := newMockStore()
		reconciler := reconciliation.NewReconciler(nil, nil, store, &mockPublisher{}, logr.Discard(), time.Hour)
		reconciler.SetNetworkingClients(
			nil,
			networkNATGatewayClient{items: []*privatev1.NATGateway{{
				Id:       "nat-unprojected",
				Metadata: &privatev1.Metadata{Tenant: "tenant-1", Version: 1},
				Spec: &privatev1.NATGatewaySpec{
					VirtualNetwork: &privatev1.VirtualNetworkLocalReference{Id: "vnet-1"},
					ExternalIp:     &privatev1.ExternalIPLocalReference{Id: "ip-1"},
				},
				Status: &privatev1.NATGatewayStatus{State: privatev1.NATGatewayState_NAT_GATEWAY_STATE_READY},
			}}},
			nil,
			"deployment-1",
		)

		Expect(reconciler.Reconcile(context.Background())).To(MatchError(ContainSubstring("no authoritative transition time")))
	})

	It("returns immutable pool identities", func() {
		pools, err := reconciliation.LoadExternalIPPools(context.Background(), networkPoolClient{
			response: &privatev1.ExternalIPPoolsListResponse{
				Total: 1,
				Items: []*privatev1.ExternalIPPool{{
					Id: "pool-1",
					Spec: &privatev1.ExternalIPPoolSpec{
						IpFamily: privatev1.IPFamily_IP_FAMILY_IPV4,
					},
				}},
			},
		})

		Expect(err).NotTo(HaveOccurred())
		Expect(pools).To(Equal(map[string]string{"pool-1": "ipv4"}))
	})

	It("preserves an IPv6 pool family", func() {
		pools, err := reconciliation.LoadExternalIPPools(context.Background(), networkPoolClient{
			response: &privatev1.ExternalIPPoolsListResponse{
				Total: 1,
				Items: []*privatev1.ExternalIPPool{{
					Id:   "pool-1",
					Spec: &privatev1.ExternalIPPoolSpec{IpFamily: privatev1.IPFamily_IP_FAMILY_IPV6},
				}},
			},
		})

		Expect(err).NotTo(HaveOccurred())
		Expect(pools).To(Equal(map[string]string{"pool-1": "ipv6"}))
	})

	It("resets an ExternalIP billing slice when reconciliation finds new attribution", func() {
		stateTime := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
		attachmentTime := stateTime.Add(time.Hour)
		ip := &privatev1.ExternalIP{
			Id: "ip-1",
			Metadata: &privatev1.Metadata{
				Tenant:  "tenant-1",
				Project: "project-1",
				Version: 2,
			},
			Spec: &privatev1.ExternalIPSpec{
				Pool: &privatev1.ExternalIPPoolReference{Id: "pool-1"},
			},
			Status: &privatev1.ExternalIPStatus{
				State:                    privatev1.ExternalIPState_EXTERNAL_IP_STATE_ALLOCATED,
				Attached:                 true,
				StateTransitionTime:      timestamppb.New(stateTime),
				AttachmentTransitionTime: timestamppb.New(attachmentTime),
				Attribution: &privatev1.ExternalIPAttribution{
					Target: &privatev1.ExternalIPAttribution_ComputeInstance{
						ComputeInstance: &privatev1.ComputeInstanceLocalReference{Id: "vm-1"},
					},
				},
			},
		}
		billableSince := stateTime.Add(-time.Hour)
		store := newMockStore()
		store.states["ip-1"] = projection.ResourceState{
			ResourceID:         "ip-1",
			ResourceType:       events.ResourceTypeExternalIP,
			TenantID:           "tenant-1",
			ProjectID:          "project-1",
			CurrentState:       events.ExternalIPStateAllocated,
			IsBillable:         true,
			BillableSince:      &billableSince,
			FulfillmentVersion: 1,
			BillingDimensions: map[string]any{
				"deployment": "deployment-1",
				"pool":       "pool-1",
				"ip_family":  "ipv4",
				"attached":   false,
				"tenant_id":  "tenant-1",
				"project_id": "project-1",
			},
		}
		reconciler := reconciliation.NewReconciler(nil, nil, store, &mockPublisher{}, logr.Discard(), time.Hour)
		reconciler.SetNetworkingClients(
			networkExternalIPClient{items: []*privatev1.ExternalIP{ip}},
			nil,
			networkPoolClient{response: &privatev1.ExternalIPPoolsListResponse{
				Total: 1,
				Items: []*privatev1.ExternalIPPool{{
					Id:   "pool-1",
					Spec: &privatev1.ExternalIPPoolSpec{IpFamily: privatev1.IPFamily_IP_FAMILY_IPV4},
				}},
			}},
			"deployment-1",
		)

		Expect(reconciler.Reconcile(context.Background())).To(Succeed())
		Expect(*store.states["ip-1"].BillableSince).To(Equal(attachmentTime))
	})
})
