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
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	"github.com/osac-project/osac/fulfillment-service/internal/auth"
	privatev1 "github.com/osac-project/osac/proto/gen/osac/private/v1"
	publicv1 "github.com/osac-project/osac/proto/gen/osac/public/v1"
)

// ManagedKeysServerBuilder contains the data and logic needed to create a public managed keys server.
type ManagedKeysServerBuilder struct {
	logger            *slog.Logger
	attributionLogic  auth.AttributionLogic
	tenancyLogic      auth.TenancyLogic
	metricsRegisterer prometheus.Registerer
}

var _ publicv1.ManagedKeysServer = (*ManagedKeysServer)(nil)

// ManagedKeysServer is the implementation of the public managed keys gRPC service. It delegates to the private server
// after mapping between public and private types.
type ManagedKeysServer struct {
	publicv1.UnimplementedManagedKeysServer

	logger    *slog.Logger
	private   *PrivateManagedKeysServer
	inMapper  *GenericMapper[*publicv1.ManagedKey, *privatev1.ManagedKey]
	outMapper *GenericMapper[*privatev1.ManagedKey, *publicv1.ManagedKey]
}

// NewManagedKeysServer creates a new builder for the public managed keys server.
func NewManagedKeysServer() *ManagedKeysServerBuilder {
	return &ManagedKeysServerBuilder{}
}

// SetLogger sets the logger. This is mandatory.
func (b *ManagedKeysServerBuilder) SetLogger(value *slog.Logger) *ManagedKeysServerBuilder {
	b.logger = value
	return b
}

// SetAttributionLogic sets the attribution logic.
func (b *ManagedKeysServerBuilder) SetAttributionLogic(value auth.AttributionLogic) *ManagedKeysServerBuilder {
	b.attributionLogic = value
	return b
}

// SetTenancyLogic sets the tenancy logic. This is mandatory.
func (b *ManagedKeysServerBuilder) SetTenancyLogic(value auth.TenancyLogic) *ManagedKeysServerBuilder {
	b.tenancyLogic = value
	return b
}

// SetMetricsRegisterer sets the Prometheus registerer used to register the metrics for the underlying database
// access objects. This is optional. If not set, no metrics will be recorded.
func (b *ManagedKeysServerBuilder) SetMetricsRegisterer(value prometheus.Registerer) *ManagedKeysServerBuilder {
	b.metricsRegisterer = value
	return b
}

// Build creates the public managed keys server.
func (b *ManagedKeysServerBuilder) Build() (result *ManagedKeysServer, err error) {
	if b.logger == nil {
		err = errors.New("logger is mandatory")
		return
	}
	if b.attributionLogic == nil {
		err = errors.New("attribution logic is mandatory")
		return
	}
	if b.tenancyLogic == nil {
		err = errors.New("tenancy logic is mandatory")
		return
	}

	inMapper, err := NewGenericMapper[*publicv1.ManagedKey, *privatev1.ManagedKey]().
		SetLogger(b.logger).
		SetStrict(true).
		Build()
	if err != nil {
		return
	}
	outMapper, err := NewGenericMapper[*privatev1.ManagedKey, *publicv1.ManagedKey]().
		SetLogger(b.logger).
		SetStrict(false).
		Build()
	if err != nil {
		return
	}

	delegate, err := NewPrivateManagedKeysServer().
		SetLogger(b.logger).
		SetAttributionLogic(b.attributionLogic).
		SetTenancyLogic(b.tenancyLogic).
		SetMetricsRegisterer(b.metricsRegisterer).
		SetFilterDesc((*publicv1.ManagedKey)(nil).ProtoReflect().Descriptor()).
		Build()
	if err != nil {
		return
	}

	result = &ManagedKeysServer{
		logger:    b.logger,
		private:   delegate,
		inMapper:  inMapper,
		outMapper: outMapper,
	}
	return
}

func (s *ManagedKeysServer) List(ctx context.Context,
	request *publicv1.ManagedKeysListRequest) (response *publicv1.ManagedKeysListResponse, err error) {
	privateRequest := &privatev1.ManagedKeysListRequest{}
	privateRequest.SetOffset(request.GetOffset())
	if request.HasLimit() {
		privateRequest.SetLimit(request.GetLimit())
	}
	privateRequest.SetFilter(request.GetFilter())
	privateRequest.SetOrder(request.GetOrder())
	privateResponse, err := s.private.List(ctx, privateRequest)
	if err != nil {
		return nil, err
	}

	privateItems := privateResponse.GetItems()
	publicItems := make([]*publicv1.ManagedKey, len(privateItems))
	for i, privateItem := range privateItems {
		publicItem := &publicv1.ManagedKey{}
		err = s.outMapper.Copy(ctx, privateItem, publicItem)
		if err != nil {
			s.logger.ErrorContext(ctx, "Failed to map private managed key to public", slog.Any("error", err))
			return nil, err
		}
		publicItems[i] = publicItem
	}

	response = &publicv1.ManagedKeysListResponse{}
	response.SetSize(privateResponse.GetSize())
	response.SetTotal(privateResponse.GetTotal())
	response.SetItems(publicItems)
	return
}

func (s *ManagedKeysServer) Get(ctx context.Context,
	request *publicv1.ManagedKeysGetRequest) (response *publicv1.ManagedKeysGetResponse, err error) {
	privateRequest := &privatev1.ManagedKeysGetRequest{}
	privateRequest.SetId(request.GetId())

	privateResponse, err := s.private.Get(ctx, privateRequest)
	if err != nil {
		return nil, err
	}

	publicObject := &publicv1.ManagedKey{}
	err = s.outMapper.Copy(ctx, privateResponse.GetObject(), publicObject)
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to map private managed key to public", slog.Any("error", err))
		return nil, err
	}

	response = &publicv1.ManagedKeysGetResponse{}
	response.SetObject(publicObject)
	return
}

func (s *ManagedKeysServer) Create(ctx context.Context,
	request *publicv1.ManagedKeysCreateRequest) (response *publicv1.ManagedKeysCreateResponse, err error) {
	if request.GetObject() == nil || request.GetObject().GetMetadata() == nil {
		return nil, grpcstatus.Error(grpccodes.InvalidArgument, "object metadata is mandatory")
	}
	assignable, err := s.private.generic.tenancyLogic.DetermineAssignableTenants(ctx)
	if err != nil {
		return nil, grpcstatus.Error(grpccodes.Internal, "failed to determine assignable tenants")
	}
	tenant := request.GetObject().GetMetadata().GetTenant()
	if tenant == "" {
		if !assignable.Finite() {
			return nil, grpcstatus.Error(grpccodes.PermissionDenied, "administrators must select an explicit tenant for managed keys")
		}
		tenant, err = s.private.generic.tenancyLogic.DetermineDefaultTenant(ctx)
		if err != nil {
			return nil, grpcstatus.Error(grpccodes.Internal, "failed to determine default tenant")
		}
	}
	if tenant == auth.SharedTenant {
		return nil, grpcstatus.Error(grpccodes.PermissionDenied, "managed keys cannot belong to shared; select an explicit tenant")
	}
	if tenant == auth.SystemTenant && assignable.Finite() {
		return nil, grpcstatus.Error(grpccodes.PermissionDenied, "only provider administrators can create system keys")
	}
	privateObject := &privatev1.ManagedKey{}
	err = s.inMapper.Copy(ctx, request.GetObject(), privateObject)
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to map public managed key to private", slog.Any("error", err))
		return nil, err
	}

	privateRequest := &privatev1.ManagedKeysCreateRequest{}
	privateRequest.SetObject(privateObject)

	privateResponse, err := s.private.Create(ctx, privateRequest)
	if err != nil {
		return nil, err
	}

	publicObject := &publicv1.ManagedKey{}
	err = s.outMapper.Copy(ctx, privateResponse.GetObject(), publicObject)
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to map private managed key to public", slog.Any("error", err))
		return nil, err
	}

	response = &publicv1.ManagedKeysCreateResponse{}
	response.SetObject(publicObject)
	return
}

func (s *ManagedKeysServer) Update(ctx context.Context,
	request *publicv1.ManagedKeysUpdateRequest) (response *publicv1.ManagedKeysUpdateResponse, err error) {
	if request.GetObject() == nil || request.GetObject().GetId() == "" {
		return nil, grpcstatus.Error(grpccodes.InvalidArgument, "object identifier is mandatory")
	}
	mask := request.GetUpdateMask()
	if mask == nil {
		mask = &fieldmaskpb.FieldMask{Paths: []string{"metadata.display_name", "metadata.description"}}
	}
	paths := make([]string, 0, len(mask.GetPaths()))
	for _, path := range mask.GetPaths() {
		// The REST gateway includes this field in its inferred mask when the body
		// supplies the optimistic-lock token. It never selects a stored-field write.
		if path == "metadata.version" {
			continue
		}
		if path != "metadata.display_name" && path != "metadata.description" {
			return nil, grpcstatus.Errorf(grpccodes.InvalidArgument, "field '%s' is not publicly writable", path)
		}
		paths = append(paths, path)
	}
	mask = &fieldmaskpb.FieldMask{Paths: paths}
	privateObject := &privatev1.ManagedKey{}
	if err = s.inMapper.Copy(ctx, request.GetObject(), privateObject); err != nil {
		return nil, err
	}
	privateRequest := privatev1.ManagedKeysUpdateRequest_builder{
		Object: privateObject, UpdateMask: mask, Lock: request.GetLock(),
	}.Build()
	var privateResponse *privatev1.ManagedKeysUpdateResponse
	err = s.private.generic.UpdateWithCandidatePreparation(ctx, privateRequest, &privateResponse,
		func(ctx context.Context, current, candidate *privatev1.ManagedKey) error {
			publicCurrent := &publicv1.ManagedKey{}
			if err := s.outMapper.Copy(ctx, current, publicCurrent); err != nil {
				return err
			}
			if err := rejectManagedKeyChanges(request.GetObject().ProtoReflect(), publicCurrent.ProtoReflect(), ""); err != nil {
				return err
			}
			return s.private.validateUpdate(ctx, current, candidate)
		})
	if err != nil {
		return nil, err
	}

	publicObject := &publicv1.ManagedKey{}
	err = s.outMapper.Copy(ctx, privateResponse.GetObject(), publicObject)
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to map private managed key to public", slog.Any("error", err))
		return nil, err
	}

	response = &publicv1.ManagedKeysUpdateResponse{}
	response.SetObject(publicObject)
	return
}

func (s *ManagedKeysServer) Delete(ctx context.Context,
	request *publicv1.ManagedKeysDeleteRequest) (response *publicv1.ManagedKeysDeleteResponse, err error) {
	privateRequest := &privatev1.ManagedKeysDeleteRequest{}
	privateRequest.SetId(request.GetId())

	_, err = s.private.Delete(ctx, privateRequest)
	if err != nil {
		return nil, err
	}

	response = &publicv1.ManagedKeysDeleteResponse{}
	return
}

// Allow round-tripping unchanged read-only fields, while rejecting any supplied changes.
// Absent fields in a partial request do not erase stored lifecycle or ownership metadata.
func rejectManagedKeyChanges(submitted, stored protoreflect.Message, prefix string) (err error) {
	submitted.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		name := string(field.Name())
		if prefix == "metadata." && (name == "display_name" || name == "description" || name == "version") {
			return true
		}
		if name == "metadata" {
			err = rejectManagedKeyChanges(value.Message(), stored.Get(field).Message(), "metadata.")
			return err == nil
		}
		left, right := submitted.New(), stored.New()
		left.Set(field, value)
		if stored.Has(field) {
			right.Set(field, stored.Get(field))
		}
		if !proto.Equal(left.Interface(), right.Interface()) {
			err = grpcstatus.Errorf(grpccodes.InvalidArgument, "field '%s%s' is not publicly writable", prefix, name)
		}
		return err == nil
	})
	return
}
