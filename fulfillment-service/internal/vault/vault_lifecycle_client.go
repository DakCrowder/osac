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

	vaultapi "github.com/hashicorp/vault/api"
)

// LifecycleClient manages tenant namespaces in a Vault-compatible secret store. It authenticates
// to the parent namespace via JWT and performs namespace creation/deletion, auth configuration,
// and policy management. Each operation is idempotent.
//
//go:generate mockgen -destination=vault_lifecycle_client_mock.go -package=vault . LifecycleClient
type LifecycleClient interface {
	CreateTenantNamespace(ctx context.Context, tenant string) error
	DeleteTenantNamespace(ctx context.Context, tenant string) error
}

type LifecycleClientBuilder struct {
	logger             *slog.Logger
	address            string
	parentNamespace    string
	kvMountPath        string
	authMountPath      string
	lifecycleMountPath string
	lifecycleRole      string
	discoveryURL       string
	audience           string
	jwtSource          func(ctx context.Context) (string, error)
	caPool             *x509.CertPool
	caPEM              string
}

type lifecycleClient struct {
	logger             *slog.Logger
	client             *vaultapi.Client
	parentNamespace    string
	kvMountPath        string
	authMountPath      string
	lifecycleMountPath string
	lifecycleRole      string
	discoveryURL       string
	audience           string
	jwtSource          func(ctx context.Context) (string, error)
	caPEM              string
	tokenCache         *TokenCache
}

func NewLifecycleClient() *LifecycleClientBuilder {
	return &LifecycleClientBuilder{
		kvMountPath:        "secret",
		authMountPath:      "jwt",
		lifecycleMountPath: "jwt",
		lifecycleRole:      "lifecycle",
		audience:           "osac-api",
	}
}

func (b *LifecycleClientBuilder) SetLogger(value *slog.Logger) *LifecycleClientBuilder {
	b.logger = value
	return b
}

func (b *LifecycleClientBuilder) SetAddress(value string) *LifecycleClientBuilder {
	b.address = value
	return b
}

func (b *LifecycleClientBuilder) SetParentNamespace(value string) *LifecycleClientBuilder {
	b.parentNamespace = value
	return b
}

func (b *LifecycleClientBuilder) SetKVMountPath(value string) *LifecycleClientBuilder {
	b.kvMountPath = value
	return b
}

func (b *LifecycleClientBuilder) SetAuthMountPath(value string) *LifecycleClientBuilder {
	b.authMountPath = value
	return b
}

func (b *LifecycleClientBuilder) SetLifecycleMountPath(value string) *LifecycleClientBuilder {
	b.lifecycleMountPath = value
	return b
}

func (b *LifecycleClientBuilder) SetLifecycleRole(value string) *LifecycleClientBuilder {
	b.lifecycleRole = value
	return b
}

func (b *LifecycleClientBuilder) SetDiscoveryURL(value string) *LifecycleClientBuilder {
	b.discoveryURL = value
	return b
}

func (b *LifecycleClientBuilder) SetAudience(value string) *LifecycleClientBuilder {
	b.audience = value
	return b
}

// SetJWTSource sets the function that provides a raw JWT for lifecycle auth. The fulfillment-service
// typically obtains this by using its Keycloak client credentials.
func (b *LifecycleClientBuilder) SetJWTSource(
	value func(ctx context.Context) (string, error)) *LifecycleClientBuilder {
	b.jwtSource = value
	return b
}

func (b *LifecycleClientBuilder) SetCaPool(value *x509.CertPool) *LifecycleClientBuilder {
	b.caPool = value
	return b
}

// SetCaPEM sets the CA certificate PEM string passed to Vault's JWT auth OIDC discovery
// configuration so that Vault can verify the Keycloak TLS certificate.
func (b *LifecycleClientBuilder) SetCaPEM(value string) *LifecycleClientBuilder {
	b.caPEM = value
	return b
}

func (b *LifecycleClientBuilder) Build() (LifecycleClient, error) {
	if b.logger == nil {
		return nil, errors.New("logger is mandatory")
	}
	if b.address == "" {
		return nil, errors.New("address is mandatory")
	}
	if b.parentNamespace == "" {
		return nil, errors.New("parent namespace is mandatory")
	}
	if b.jwtSource == nil {
		return nil, errors.New("JWT source is mandatory")
	}
	if b.discoveryURL == "" {
		return nil, errors.New("discovery URL is mandatory")
	}

	config := vaultapi.DefaultConfig()
	config.Address = b.address

	if b.caPool != nil {
		transport, ok := config.HttpClient.Transport.(*http.Transport)
		if !ok {
			return nil, errors.New("unexpected transport type from vault default config")
		}
		cloned := transport.Clone()
		cloned.TLSClientConfig.RootCAs = b.caPool
		config.HttpClient.Transport = cloned
	}

	client, err := vaultapi.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	return &lifecycleClient{
		logger:             b.logger,
		client:             client,
		parentNamespace:    b.parentNamespace,
		kvMountPath:        b.kvMountPath,
		authMountPath:      b.authMountPath,
		lifecycleMountPath: b.lifecycleMountPath,
		lifecycleRole:      b.lifecycleRole,
		discoveryURL:       b.discoveryURL,
		audience:           b.audience,
		jwtSource:          b.jwtSource,
		caPEM:              b.caPEM,
		tokenCache:         NewTokenCache(),
	}, nil
}

// CreateTenantNamespace creates a tenant's child namespace with KV v2 and JWT auth configured.
// Each step is idempotent (check-before-create).
func (c *lifecycleClient) CreateTenantNamespace(ctx context.Context, tenant string) error {
	if err := validatePathComponent(tenant, "tenant"); err != nil {
		return err
	}

	parentClient, err := c.authenticatedParentClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to authenticate for lifecycle operation: %w", err)
	}

	tenantNS := path.Join(c.parentNamespace, tenant)

	// Create the tenant namespace under the parent:
	_, err = parentClient.Logical().WriteWithContext(ctx,
		fmt.Sprintf("sys/namespaces/%s", tenant), nil)
	if err != nil && !isAlreadyExistsError(err) {
		return fmt.Errorf("failed to create tenant namespace %q: %w", tenant, err)
	}

	// Switch to the tenant namespace for remaining operations:
	tenantClient, err := c.client.Clone()
	if err != nil {
		return fmt.Errorf("failed to clone vault client: %w", err)
	}
	tenantClient.SetNamespace(tenantNS)
	tenantClient.SetToken(parentClient.Token())

	// Enable KV v2 at the configured mount path:
	_, err = tenantClient.Logical().WriteWithContext(ctx,
		fmt.Sprintf("sys/mounts/%s", c.kvMountPath),
		map[string]any{
			"type":    "kv",
			"options": map[string]any{"version": "2"},
		})
	if err != nil && !isAlreadyExistsError(err) {
		return fmt.Errorf("failed to enable KV v2 for tenant %q: %w", tenant, err)
	}

	// Enable JWT auth:
	_, err = tenantClient.Logical().WriteWithContext(ctx,
		fmt.Sprintf("sys/auth/%s", c.authMountPath),
		map[string]any{"type": "jwt"})
	if err != nil && !isAlreadyExistsError(err) {
		return fmt.Errorf("failed to enable JWT auth for tenant %q: %w", tenant, err)
	}

	// Configure JWT auth with Keycloak OIDC discovery:
	jwtConfig := map[string]any{
		"oidc_discovery_url": c.discoveryURL,
	}
	if c.caPEM != "" {
		jwtConfig["oidc_discovery_ca_pem"] = c.caPEM
	}
	_, err = tenantClient.Logical().WriteWithContext(ctx,
		fmt.Sprintf("auth/%s/config", c.authMountPath), jwtConfig)
	if err != nil {
		return fmt.Errorf("failed to configure JWT auth for tenant %q: %w", tenant, err)
	}

	// Create KV read/write/delete policy:
	kvPolicy := fmt.Sprintf(`
path "%s/data/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "%s/metadata/*" {
  capabilities = ["read", "delete", "list"]
}
`, c.kvMountPath, c.kvMountPath)
	_, err = tenantClient.Logical().WriteWithContext(ctx,
		"sys/policy/kv-readwrite",
		map[string]any{"policy": kvPolicy})
	if err != nil {
		return fmt.Errorf("failed to create KV policy for tenant %q: %w", tenant, err)
	}

	// Create JWT auth role with organization-bound claims:
	_, err = tenantClient.Logical().WriteWithContext(ctx,
		fmt.Sprintf("auth/%s/role/default", c.authMountPath),
		map[string]any{
			"role_type":       "jwt",
			"bound_audiences": []string{c.audience},
			"bound_claims": map[string]any{
				"organization": []string{tenant},
			},
			"user_claim":     "sub",
			"token_policies": []string{"kv-readwrite"},
		})
	if err != nil {
		return fmt.Errorf("failed to create JWT role for tenant %q: %w", tenant, err)
	}

	c.logger.InfoContext(ctx, "Created tenant vault namespace",
		slog.String("tenant", tenant),
		slog.String("namespace", tenantNS),
	)
	return nil
}

// DeleteTenantNamespace deletes a tenant's child namespace. This is a cascading operation that
// removes all secrets, policies, and auth methods within the namespace.
func (c *lifecycleClient) DeleteTenantNamespace(ctx context.Context, tenant string) error {
	if err := validatePathComponent(tenant, "tenant"); err != nil {
		return err
	}

	parentClient, err := c.authenticatedParentClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to authenticate for lifecycle operation: %w", err)
	}

	_, err = parentClient.Logical().DeleteWithContext(ctx,
		fmt.Sprintf("sys/namespaces/%s", tenant))
	if err != nil {
		return fmt.Errorf("failed to delete tenant namespace %q: %w", tenant, err)
	}

	c.logger.InfoContext(ctx, "Deleted tenant vault namespace",
		slog.String("tenant", tenant),
	)
	return nil
}

// authenticatedParentClient returns a Vault client authenticated to the parent namespace via
// lifecycle JWT auth.
func (c *lifecycleClient) authenticatedParentClient(ctx context.Context) (*vaultapi.Client, error) {
	if token, ok := c.tokenCache.Get("lifecycle"); ok {
		client, err := c.client.Clone()
		if err != nil {
			return nil, fmt.Errorf("failed to clone vault client: %w", err)
		}
		client.SetNamespace(c.parentNamespace)
		client.SetToken(token)
		return client, nil
	}

	rawJWT, err := c.jwtSource(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get lifecycle JWT: %w", err)
	}

	client, err := c.client.Clone()
	if err != nil {
		return nil, fmt.Errorf("failed to clone vault client: %w", err)
	}
	client.SetNamespace(c.parentNamespace)

	loginResult, err := jwtLogin(ctx, client, c.lifecycleMountPath, c.lifecycleRole, rawJWT)
	if err != nil {
		return nil, fmt.Errorf("lifecycle JWT auth failed: %w", err)
	}

	c.tokenCache.Put("lifecycle", loginResult.Token, loginResult.TTL)
	client.SetToken(loginResult.Token)
	return client, nil
}

// isAlreadyExistsError checks if a Vault API error indicates the resource already exists
// (HTTP 400 with "already exists" or "path is already in use").
func isAlreadyExistsError(err error) bool {
	var responseErr *vaultapi.ResponseError
	if errors.As(err, &responseErr) {
		return responseErr.StatusCode == http.StatusBadRequest
	}
	return false
}
