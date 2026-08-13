/*
Copyright (c) 2026 Red Hat Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License.
*/

package vault

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path"

	"github.com/osac-project/osac/fulfillment-service/internal/auth"
)

type UserJWTTokenSourceBuilder struct {
	logger          *slog.Logger
	vaultAddress    string
	parentNamespace string
	caPool          *x509.CertPool
}

type UserJWTTokenSource struct {
	logger          *slog.Logger
	vaultAddress    string
	parentNamespace string
	httpClient      *http.Client
}

func NewUserJWTTokenSource() *UserJWTTokenSourceBuilder {
	return &UserJWTTokenSourceBuilder{}
}

func (b *UserJWTTokenSourceBuilder) SetLogger(value *slog.Logger) *UserJWTTokenSourceBuilder {
	b.logger = value
	return b
}

func (b *UserJWTTokenSourceBuilder) SetVaultAddress(value string) *UserJWTTokenSourceBuilder {
	b.vaultAddress = value
	return b
}

func (b *UserJWTTokenSourceBuilder) SetParentNamespace(value string) *UserJWTTokenSourceBuilder {
	b.parentNamespace = value
	return b
}

func (b *UserJWTTokenSourceBuilder) SetCaPool(value *x509.CertPool) *UserJWTTokenSourceBuilder {
	b.caPool = value
	return b
}

func (b *UserJWTTokenSourceBuilder) Build() (result *UserJWTTokenSource, err error) {
	if b.logger == nil {
		err = errors.New("logger is mandatory")
		return
	}
	if b.vaultAddress == "" {
		err = errors.New("vault address is mandatory")
		return
	}
	if b.parentNamespace == "" {
		err = errors.New("parent namespace is mandatory")
		return
	}

	httpClient, httpErr := newHTTPClient(b.caPool)
	if httpErr != nil {
		err = httpErr
		return
	}

	result = &UserJWTTokenSource{
		logger:          b.logger,
		vaultAddress:    b.vaultAddress,
		parentNamespace: b.parentNamespace,
		httpClient:      httpClient,
	}
	return
}

func (s *UserJWTTokenSource) VaultToken(ctx context.Context, tenant string) (string, error) {
	token := auth.TokenFromContext(ctx)
	if token == nil || token.Raw == "" {
		return "", fmt.Errorf("user JWT token not found in request context")
	}

	if tenant == "" {
		return "", fmt.Errorf("tenant is required for user vault authentication")
	}

	namespace := path.Join(s.parentNamespace, tenant)
	vaultToken, _, err := loginToVault(
		ctx,
		s.httpClient,
		s.vaultAddress,
		namespace,
		TenantAuthMountPath,
		TenantAuthRole,
		token.Raw,
	)
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to authenticate user to vault",
			slog.String("tenant", tenant),
			slog.Any("error", err),
		)
		return "", fmt.Errorf("failed to authenticate user to vault for tenant %q: %w", tenant, err)
	}

	s.logger.DebugContext(ctx, "User authenticated to vault",
		slog.String("tenant", tenant),
	)

	return vaultToken, nil
}
