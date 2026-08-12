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
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

type ServiceTenantTokenSourceBuilder struct {
	logger                *slog.Logger
	vaultAddress          string
	parentNamespace       string
	keycloakTokenEndpoint string
	keycloakClientID      string
	keycloakClientSecret  string
	caPool                *x509.CertPool
}

type ServiceTenantTokenSource struct {
	logger                *slog.Logger
	vaultAddress          string
	parentNamespace       string
	keycloakTokenEndpoint string
	keycloakClientID      string
	keycloakClientSecret  string
	httpClient            *http.Client

	mu           sync.Mutex
	tenantTokens map[string]cachedToken

	kcMu          sync.Mutex
	cachedKCToken string
	kcTokenExpiry time.Time

	sfGroup singleflight.Group
}

type cachedToken struct {
	token  string
	expiry time.Time
}

func NewServiceTenantTokenSource() *ServiceTenantTokenSourceBuilder {
	return &ServiceTenantTokenSourceBuilder{}
}

func (b *ServiceTenantTokenSourceBuilder) SetLogger(value *slog.Logger) *ServiceTenantTokenSourceBuilder {
	b.logger = value
	return b
}

func (b *ServiceTenantTokenSourceBuilder) SetVaultAddress(value string) *ServiceTenantTokenSourceBuilder {
	b.vaultAddress = value
	return b
}

func (b *ServiceTenantTokenSourceBuilder) SetParentNamespace(value string) *ServiceTenantTokenSourceBuilder {
	b.parentNamespace = value
	return b
}

func (b *ServiceTenantTokenSourceBuilder) SetKeycloakTokenEndpoint(value string) *ServiceTenantTokenSourceBuilder {
	b.keycloakTokenEndpoint = value
	return b
}

func (b *ServiceTenantTokenSourceBuilder) SetKeycloakClientID(value string) *ServiceTenantTokenSourceBuilder {
	b.keycloakClientID = value
	return b
}

func (b *ServiceTenantTokenSourceBuilder) SetKeycloakClientSecret(value string) *ServiceTenantTokenSourceBuilder {
	b.keycloakClientSecret = value
	return b
}

func (b *ServiceTenantTokenSourceBuilder) SetCaPool(value *x509.CertPool) *ServiceTenantTokenSourceBuilder {
	b.caPool = value
	return b
}

func (b *ServiceTenantTokenSourceBuilder) Build() (result *ServiceTenantTokenSource, err error) {
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
	if b.keycloakTokenEndpoint == "" {
		err = errors.New("keycloak token endpoint is mandatory")
		return
	}
	if b.keycloakClientID == "" {
		err = errors.New("keycloak client ID is mandatory")
		return
	}
	if b.keycloakClientSecret == "" {
		err = errors.New("keycloak client secret is mandatory")
		return
	}

	httpClient, httpErr := newHTTPClient(b.caPool)
	if httpErr != nil {
		err = httpErr
		return
	}

	result = &ServiceTenantTokenSource{
		logger:                b.logger,
		vaultAddress:          b.vaultAddress,
		parentNamespace:       b.parentNamespace,
		keycloakTokenEndpoint: b.keycloakTokenEndpoint,
		keycloakClientID:      b.keycloakClientID,
		keycloakClientSecret:  b.keycloakClientSecret,
		httpClient:            httpClient,
		tenantTokens:          make(map[string]cachedToken),
	}
	return
}

func (s *ServiceTenantTokenSource) VaultToken(ctx context.Context, tenant string) (string, error) {
	if tenant == "" {
		return "", errors.New("tenant is required for service vault authentication")
	}

	s.mu.Lock()
	if cached, ok := s.tenantTokens[tenant]; ok && time.Until(cached.expiry) > 30*time.Second {
		token := cached.token
		s.mu.Unlock()
		return token, nil
	}
	s.mu.Unlock()

	result, err, _ := s.sfGroup.Do(tenant, func() (any, error) {
		keycloakJWT, kcErr := s.fetchKeycloakToken(ctx)
		if kcErr != nil {
			return "", fmt.Errorf("failed to obtain keycloak token: %w", kcErr)
		}

		namespace := path.Join(s.parentNamespace, tenant)
		vaultToken, leaseDuration, loginErr := loginToVault(
			ctx,
			s.httpClient,
			s.vaultAddress,
			namespace,
			TenantAuthMountPath,
			ServiceAuthRole,
			keycloakJWT,
		)
		if loginErr != nil {
			return "", fmt.Errorf("failed to login to vault for tenant %q: %w", tenant, loginErr)
		}

		s.mu.Lock()
		s.tenantTokens[tenant] = cachedToken{
			token:  vaultToken,
			expiry: time.Now().Add(time.Duration(leaseDuration) * time.Second),
		}
		s.mu.Unlock()

		s.logger.DebugContext(ctx, "Service authenticated to vault for tenant",
			slog.String("tenant", tenant),
		)

		return vaultToken, nil
	})
	if err != nil {
		return "", err
	}
	return result.(string), nil
}

func (s *ServiceTenantTokenSource) fetchKeycloakToken(ctx context.Context) (string, error) {
	s.kcMu.Lock()
	if s.cachedKCToken != "" && time.Until(s.kcTokenExpiry) > 30*time.Second {
		token := s.cachedKCToken
		s.kcMu.Unlock()
		return token, nil
	}
	s.kcMu.Unlock()

	token, expiresIn, err := fetchKeycloakToken(ctx, s.httpClient, s.keycloakTokenEndpoint, s.keycloakClientID, s.keycloakClientSecret)
	if err != nil {
		return "", err
	}

	s.kcMu.Lock()
	s.cachedKCToken = token
	s.kcTokenExpiry = time.Now().Add(time.Duration(expiresIn) * time.Second)
	s.kcMu.Unlock()

	return token, nil
}
