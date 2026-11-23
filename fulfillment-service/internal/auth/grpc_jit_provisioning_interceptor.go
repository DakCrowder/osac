/*
Copyright (c) 2026 Red Hat Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License.
*/

package auth

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/osac-project/osac/fulfillment-service/internal/database"
	"github.com/osac-project/osac/fulfillment-service/internal/util"
)

//go:generate mockgen -source=$GOFILE -destination=grpc_jit_provisioning_interceptor_mock.go -package=$GOPACKAGE UserProvisioner

// UserProvisioner provisions user records in the database.
type UserProvisioner interface {
	Provision(ctx context.Context, username, tenant string, claims jwt.MapClaims) error
}

// GrpcJitProvisioningInterceptorBuilder builds a GrpcJitProvisioningInterceptor.
type GrpcJitProvisioningInterceptorBuilder struct {
	logger               *slog.Logger
	provisioner          UserProvisioner
	roleBindingEvaluator *RoleBindingEvaluator
}

// GrpcJitProvisioningInterceptor performs just-in-time user provisioning for authenticated requests.
// It runs before RoleBinding authorization and after legacy authorization.
type GrpcJitProvisioningInterceptor struct {
	logger               *slog.Logger
	provisioner          UserProvisioner
	roleBindingEvaluator *RoleBindingEvaluator
}

// NewGrpcJitProvisioningInterceptor creates a new builder.
func NewGrpcJitProvisioningInterceptor() *GrpcJitProvisioningInterceptorBuilder {
	return &GrpcJitProvisioningInterceptorBuilder{}
}

// SetLogger sets the logger.
func (b *GrpcJitProvisioningInterceptorBuilder) SetLogger(value *slog.Logger) *GrpcJitProvisioningInterceptorBuilder {
	b.logger = value
	return b
}

// SetProvisioner sets the user provisioner.
func (b *GrpcJitProvisioningInterceptorBuilder) SetProvisioner(value UserProvisioner) *GrpcJitProvisioningInterceptorBuilder {
	b.provisioner = util.NormalizeNil(value)
	return b
}

func (b *GrpcJitProvisioningInterceptorBuilder) SetRoleBindingEvaluator(value *RoleBindingEvaluator) *GrpcJitProvisioningInterceptorBuilder {
	b.roleBindingEvaluator = value
	return b
}

// Build creates the interceptor.
func (b *GrpcJitProvisioningInterceptorBuilder) Build() (result *GrpcJitProvisioningInterceptor, err error) {
	if b.logger == nil {
		return nil, fmt.Errorf("logger is mandatory")
	}
	result = &GrpcJitProvisioningInterceptor{
		logger:               b.logger,
		provisioner:          b.provisioner,
		roleBindingEvaluator: b.roleBindingEvaluator,
	}
	return result, nil
}

// UnaryServer is the unary server interceptor function.
func (i *GrpcJitProvisioningInterceptor) UnaryServer(ctx context.Context, req any,
	info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	err := i.provisionIfNeeded(ctx, info.FullMethod)
	if err != nil {
		return nil, err
	}
	return handler(ctx, req)
}

// StreamServer is the stream server interceptor function.
//
// RoleBinding mode may provision a user in a short transaction before a stream
// starts. Legacy mode continues to provision users on unary calls.
func (i *GrpcJitProvisioningInterceptor) StreamServer(srv any, stream grpc.ServerStream,
	info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if i.roleBindingEvaluator != nil {
		if err := i.provisionIfNeeded(stream.Context(), info.FullMethod); err != nil {
			return err
		}
	}
	return handler(srv, stream)
}

// provisionIfNeeded checks if user provisioning is needed and performs it.
// Returns nil if provisioning is not needed or succeeds, error if provisioning fails.
func (i *GrpcJitProvisioningInterceptor) provisionIfNeeded(ctx context.Context, method string) error {
	// Skip if no provisioner configured
	if i.provisioner == nil {
		return nil
	}
	if i.roleBindingEvaluator != nil {
		return i.provisionHuman(ctx, method)
	}

	// Get subject from context (set by authz interceptor)
	subject := SubjectFromContext(ctx)
	if subject == nil {
		// No subject means anonymous or unauthenticated request - skip provisioning
		return nil
	}
	if subject.ManagedServiceAccount {
		// Managed service accounts are not tenant users.
		return nil
	}

	tenant := subject.Tenant
	if tenant == "" || tenant == SystemTenant || tenant == SharedTenant {
		// Only provision user records for a known home tenant other than system or shared.
		return nil
	}

	// Get username from subject
	username := subject.User

	// Get JWT token from context for additional claims
	token := TokenFromContext(ctx)
	if token == nil {
		// No token in context - skip provisioning
		return nil
	}

	// Extract JWT claims for email, name, etc.
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		i.logger.ErrorContext(ctx, "Failed to extract claims from JWT token for user provisioning")
		return nil
	}

	// Provisioning normally shares the RPC transaction. Methods that manage their own
	// short transactions provide only the manager, so scope provisioning separately.
	provision := func(provisionCtx context.Context) error {
		return i.provisioner.Provision(provisionCtx, username, tenant, claims)
	}
	var err error
	// A missing transaction with a manager is expected for methods configured to
	// manage their own transactions. JIT provisioning still needs one, so scope it
	// separately; ordinary RPCs keep sharing their existing transaction.
	if _, txErr := database.TxFromContext(ctx); txErr == nil {
		err = provision(ctx)
	} else if _, managerErr := database.TxManagerFromContext(ctx); managerErr == nil {
		_, err = database.WithNewTx(ctx, func(txCtx context.Context) (struct{}, error) {
			return struct{}{}, provision(txCtx)
		})
	} else {
		err = provision(ctx)
	}
	if err != nil {
		i.logger.ErrorContext(ctx, "Failed to provision user",
			slog.String("!username", username),
			slog.String("!tenant", tenant),
			slog.Any("error", err),
		)
		return fmt.Errorf("user provisioning failed: %w", err)
	}

	return nil
}

func (i *GrpcJitProvisioningInterceptor) provisionHuman(ctx context.Context, method string) error {
	token := TokenFromContext(ctx)
	if token == nil || isAuthorizationInfrastructure(method) {
		return nil
	}
	identity, err := ExtractAuthContext(token)
	if err != nil {
		return status.Error(codes.Internal, "failed to process authentication")
	}
	if i.roleBindingEvaluator.usesLegacyAuthorization(identity) || !i.roleBindingEvaluator.isHuman(identity) {
		return nil
	}
	tenants := ordinaryOrganizations(identity)
	names := tenants.Inclusions()
	if len(names) != 1 {
		return nil
	}
	tenant := names[0]
	if identity.Username == tenant+"-osac-break-glass" {
		return nil
	}
	claims, _ := token.Claims.(jwt.MapClaims)
	_, err = database.WithNewTx(ctx, func(txCtx context.Context) (struct{}, error) {
		txCtx = ContextWithSubject(txCtx, &Subject{User: identity.Username, Tenant: tenant, Tenants: tenants})
		return struct{}{}, i.provisioner.Provision(txCtx, identity.Username, tenant, claims)
	})
	if err != nil {
		i.logger.ErrorContext(ctx, "Failed to provision authenticated user", slog.Any("error", err))
		return status.Error(codes.Internal, "user provisioning failed")
	}
	return nil
}
