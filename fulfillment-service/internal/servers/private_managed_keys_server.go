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
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	grpccodes "google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/osac-project/osac/fulfillment-service/internal/auth"
	privatev1 "github.com/osac-project/osac/proto/gen/osac/private/v1"
)

// PrivateManagedKeysServerBuilder contains the data and logic needed to create a private managed keys server.
type PrivateManagedKeysServerBuilder struct {
	logger            *slog.Logger
	attributionLogic  auth.AttributionLogic
	tenancyLogic      auth.TenancyLogic
	metricsRegisterer prometheus.Registerer
	filterDesc        protoreflect.MessageDescriptor
}

var _ privatev1.ManagedKeysServer = (*PrivateManagedKeysServer)(nil)

// PrivateManagedKeysServer is the implementation of the private managed keys gRPC service.
type PrivateManagedKeysServer struct {
	privatev1.UnimplementedManagedKeysServer
	logger  *slog.Logger
	generic *GenericServer[*privatev1.ManagedKey]
}

// NewPrivateManagedKeysServer creates a new builder for the private managed keys server.
func NewPrivateManagedKeysServer() *PrivateManagedKeysServerBuilder {
	return &PrivateManagedKeysServerBuilder{}
}

// SetLogger sets the logger. This is mandatory.
func (b *PrivateManagedKeysServerBuilder) SetLogger(value *slog.Logger) *PrivateManagedKeysServerBuilder {
	b.logger = value
	return b
}

// SetAttributionLogic sets the attribution logic.
func (b *PrivateManagedKeysServerBuilder) SetAttributionLogic(value auth.AttributionLogic) *PrivateManagedKeysServerBuilder {
	b.attributionLogic = value
	return b
}

// SetTenancyLogic sets the tenancy logic. This is mandatory.
func (b *PrivateManagedKeysServerBuilder) SetTenancyLogic(value auth.TenancyLogic) *PrivateManagedKeysServerBuilder {
	b.tenancyLogic = value
	return b
}

// SetMetricsRegisterer sets the Prometheus registerer used to register the metrics for the underlying database
// access objects. This is optional. If not set, no metrics will be recorded.
func (b *PrivateManagedKeysServerBuilder) SetMetricsRegisterer(value prometheus.Registerer) *PrivateManagedKeysServerBuilder {
	b.metricsRegisterer = value
	return b
}

// SetFilterDesc sets the protobuf message descriptor used to validate and translate CEL filter
// expressions. This is optional. When unset, the descriptor of this server's own private message type is used.
func (b *PrivateManagedKeysServerBuilder) SetFilterDesc(value protoreflect.MessageDescriptor) *PrivateManagedKeysServerBuilder {
	b.filterDesc = value
	return b
}

// Build creates the private managed keys server.
func (b *PrivateManagedKeysServerBuilder) Build() (result *PrivateManagedKeysServer, err error) {
	// Check parameters:
	if b.logger == nil {
		err = errors.New("logger is mandatory")
		return
	}
	if b.tenancyLogic == nil {
		err = errors.New("tenancy logic is mandatory")
		return
	}

	// Create the server early, so that we can use its methods:
	s := &PrivateManagedKeysServer{
		logger: b.logger,
	}

	// Create the generic server:
	s.generic, err = NewGenericServer[*privatev1.ManagedKey]().
		SetLogger(b.logger).
		SetService(privatev1.ManagedKeys_ServiceDesc.ServiceName).
		SetAttributionLogic(b.attributionLogic).
		SetTenancyLogic(b.tenancyLogic).
		SetMetricsRegisterer(b.metricsRegisterer).
		SetFilterDesc(b.filterDesc).
		SetPersistDescriptiveMetadata(true).
		AddAllowedTenants(auth.SystemTenant).
		Build()
	if err != nil {
		return
	}

	// Return the server:
	result = s
	return
}

func (s *PrivateManagedKeysServer) List(ctx context.Context,
	request *privatev1.ManagedKeysListRequest) (response *privatev1.ManagedKeysListResponse, err error) {
	err = s.generic.ListWithOrder(ctx, request, &response, request.GetOrder())
	return
}

func (s *PrivateManagedKeysServer) Get(ctx context.Context,
	request *privatev1.ManagedKeysGetRequest) (response *privatev1.ManagedKeysGetResponse, err error) {
	err = s.generic.Get(ctx, request, &response)
	return
}

func (s *PrivateManagedKeysServer) Create(ctx context.Context,
	request *privatev1.ManagedKeysCreateRequest) (response *privatev1.ManagedKeysCreateResponse, err error) {
	err = s.generic.CreateWithCandidatePreparation(ctx, request, &response,
		func(ctx context.Context, _ *privatev1.ManagedKey, candidate *privatev1.ManagedKey) error {
			if candidate.GetMetadata().GetTenant() == auth.SharedTenant {
				return grpcstatus.Error(grpccodes.InvalidArgument, "managed keys cannot belong to shared; select an explicit tenant")
			}
			visibility, err := s.generic.tenancyLogic.DetermineVisibility(ctx)
			if err != nil {
				return grpcstatus.Error(grpccodes.Internal, "failed to determine project visibility")
			}
			metadata := candidate.GetMetadata()
			if !visibility.IsProjectVisible(metadata.GetTenant(), metadata.GetProject()) {
				return grpcstatus.Error(grpccodes.PermissionDenied, "managed key project is not visible to the caller")
			}
			if candidate.GetState() != privatev1.ManagedKeyState_MANAGED_KEY_STATE_UNSPECIFIED ||
				len(candidate.GetVersions()) != 0 || candidate.GetRevocationTimestamp() != nil ||
				candidate.GetLastRotationTimestamp() != nil || candidate.GetBackend() != privatev1.KeyBackend_KEY_BACKEND_UNSPECIFIED {
				return grpcstatus.Error(grpccodes.InvalidArgument, "confirmed lifecycle and backend fields cannot be supplied on creation")
			}
			if candidate.GetUsage() == privatev1.ManagedKeyUsage_MANAGED_KEY_USAGE_UNSPECIFIED {
				candidate.SetUsage(privatev1.ManagedKeyUsage_MANAGED_KEY_USAGE_ENCRYPT_DECRYPT)
			}
			return nil
		})
	return
}

func (s *PrivateManagedKeysServer) Update(ctx context.Context,
	request *privatev1.ManagedKeysUpdateRequest) (response *privatev1.ManagedKeysUpdateResponse, err error) {

	if request.GetObject() == nil || request.GetObject().GetId() == "" {
		return nil, grpcstatus.Error(grpccodes.InvalidArgument, "object identifier is mandatory")
	}
	err = s.generic.UpdateWithCandidatePreparation(ctx, request, &response, s.validateUpdate)
	return
}

func (s *PrivateManagedKeysServer) Delete(ctx context.Context,
	request *privatev1.ManagedKeysDeleteRequest) (response *privatev1.ManagedKeysDeleteResponse, err error) {
	err = s.generic.Delete(ctx, request, &response)
	return
}

func (s *PrivateManagedKeysServer) Signal(ctx context.Context,
	request *privatev1.ManagedKeysSignalRequest) (response *privatev1.ManagedKeysSignalResponse, err error) {
	err = s.generic.Signal(ctx, request, &response)
	return
}

// validateUpdate operates on the merged, locked object, never on a partial request.
func (s *PrivateManagedKeysServer) validateUpdate(_ context.Context, current, candidate *privatev1.ManagedKey) error {
	if current.GetUsage() != candidate.GetUsage() {
		return grpcstatus.Error(grpccodes.InvalidArgument, "field 'usage' is immutable")
	}
	if current.GetBackend() != privatev1.KeyBackend_KEY_BACKEND_UNSPECIFIED && current.GetBackend() != candidate.GetBackend() {
		return grpcstatus.Error(grpccodes.InvalidArgument, "field 'backend' is immutable once assigned")
	}
	oldMetadata, metadata := current.GetMetadata(), candidate.GetMetadata()
	if metadata.GetName() != oldMetadata.GetName() || metadata.GetTenant() != oldMetadata.GetTenant() || metadata.GetProject() != oldMetadata.GetProject() {
		return grpcstatus.Error(grpccodes.InvalidArgument, "managed key name, tenant, and project are immutable")
	}
	var previous uint64
	for _, version := range candidate.GetVersions() {
		if version.GetGeneration() <= previous {
			return grpcstatus.Error(grpccodes.InvalidArgument, "versions must have strictly ascending generations")
		}
		previous = version.GetGeneration()
	}
	// Confirmed generations are retained and cannot be rewritten by a later update.
	if len(candidate.GetVersions()) < len(current.GetVersions()) {
		return grpcstatus.Error(grpccodes.InvalidArgument, "confirmed versions cannot be removed")
	}
	for i, version := range current.GetVersions() {
		if !proto.Equal(version, candidate.GetVersions()[i]) {
			return grpcstatus.Error(grpccodes.InvalidArgument, "confirmed versions are immutable")
		}
	}
	return nil
}
