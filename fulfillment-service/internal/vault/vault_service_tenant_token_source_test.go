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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"

	. "github.com/onsi/ginkgo/v2/dsl/core"
	. "github.com/onsi/gomega"
)

var _ = Describe("ServiceTenantTokenSource", func() {
	var (
		ctx context.Context
	)

	BeforeEach(func() {
		ctx = context.Background()
	})

	newKeycloakHandler := func(expectedClientID, expectedSecret, returnToken string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			Expect(string(body)).To(ContainSubstring("grant_type=client_credentials"))
			Expect(string(body)).To(ContainSubstring(fmt.Sprintf("client_id=%s", expectedClientID)))
			Expect(string(body)).To(ContainSubstring(fmt.Sprintf("client_secret=%s", expectedSecret)))

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": returnToken,
				"expires_in":   300,
				"token_type":   "Bearer",
			})
		}
	}

	newVaultHandler := func(expectedJWT, expectedNamespace, returnToken string, leaseDuration int) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			Expect(r.URL.Path).To(Equal("/v1/auth/jwt/login"))
			Expect(r.Header.Get("X-Vault-Namespace")).To(Equal(expectedNamespace))

			var reqBody map[string]string
			json.NewDecoder(r.Body).Decode(&reqBody)
			Expect(reqBody["jwt"]).To(Equal(expectedJWT))
			Expect(reqBody["role"]).To(Equal(ServiceAuthRole))

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"auth": map[string]any{
					"client_token":   returnToken,
					"lease_duration": leaseDuration,
				},
			})
		}
	}

	Describe("Builder", func() {
		It("fails without logger", func() {
			_, err := NewServiceTenantTokenSource().
				SetVaultAddress("http://localhost:8200").
				SetParentNamespace("osac").
				SetKeycloakTokenEndpoint("http://keycloak/token").
				SetKeycloakClientID("client").
				SetKeycloakClientSecret("secret").
				Build()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("logger"))
		})

		It("fails without vault address", func() {
			_, err := NewServiceTenantTokenSource().
				SetLogger(logger).
				SetParentNamespace("osac").
				SetKeycloakTokenEndpoint("http://keycloak/token").
				SetKeycloakClientID("client").
				SetKeycloakClientSecret("secret").
				Build()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("vault address"))
		})

		It("fails without parent namespace", func() {
			_, err := NewServiceTenantTokenSource().
				SetLogger(logger).
				SetVaultAddress("http://localhost:8200").
				SetKeycloakTokenEndpoint("http://keycloak/token").
				SetKeycloakClientID("client").
				SetKeycloakClientSecret("secret").
				Build()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("parent namespace"))
		})

		It("fails without keycloak token endpoint", func() {
			_, err := NewServiceTenantTokenSource().
				SetLogger(logger).
				SetVaultAddress("http://localhost:8200").
				SetParentNamespace("osac").
				SetKeycloakClientID("client").
				SetKeycloakClientSecret("secret").
				Build()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("keycloak token endpoint"))
		})

		It("fails without keycloak client ID", func() {
			_, err := NewServiceTenantTokenSource().
				SetLogger(logger).
				SetVaultAddress("http://localhost:8200").
				SetParentNamespace("osac").
				SetKeycloakTokenEndpoint("http://keycloak/token").
				SetKeycloakClientSecret("secret").
				Build()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("keycloak client ID"))
		})

		It("fails without keycloak client secret", func() {
			_, err := NewServiceTenantTokenSource().
				SetLogger(logger).
				SetVaultAddress("http://localhost:8200").
				SetParentNamespace("osac").
				SetKeycloakTokenEndpoint("http://keycloak/token").
				SetKeycloakClientID("client").
				Build()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("keycloak client secret"))
		})
	})

	Describe("VaultToken", func() {
		It("performs keycloak and vault authentication for a tenant", func() {
			keycloakServer := httptest.NewServer(newKeycloakHandler("my-client", "my-secret", "kc-jwt-token"))
			DeferCleanup(keycloakServer.Close)

			vaultServer := httptest.NewServer(newVaultHandler("kc-jwt-token", "osac/tenant-a", "vault-tenant-token", 3600))
			DeferCleanup(vaultServer.Close)

			source, err := NewServiceTenantTokenSource().
				SetLogger(logger).
				SetVaultAddress(vaultServer.URL).
				SetParentNamespace("osac").
				SetKeycloakTokenEndpoint(keycloakServer.URL).
				SetKeycloakClientID("my-client").
				SetKeycloakClientSecret("my-secret").
				Build()
			Expect(err).ToNot(HaveOccurred())

			token, err := source.VaultToken(ctx, "tenant-a")
			Expect(err).ToNot(HaveOccurred())
			Expect(token).To(Equal("vault-tenant-token"))
		})

		It("caches token for the same tenant", func() {
			var vaultCalls atomic.Int32

			keycloakServer := httptest.NewServer(newKeycloakHandler("client", "secret", "kc-jwt"))
			DeferCleanup(keycloakServer.Close)

			vaultServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				vaultCalls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{
					"auth": map[string]any{
						"client_token":   "cached-token",
						"lease_duration": 3600,
					},
				})
			}))
			DeferCleanup(vaultServer.Close)

			source, err := NewServiceTenantTokenSource().
				SetLogger(logger).
				SetVaultAddress(vaultServer.URL).
				SetParentNamespace("osac").
				SetKeycloakTokenEndpoint(keycloakServer.URL).
				SetKeycloakClientID("client").
				SetKeycloakClientSecret("secret").
				Build()
			Expect(err).ToNot(HaveOccurred())

			token1, err := source.VaultToken(ctx, "tenant-a")
			Expect(err).ToNot(HaveOccurred())
			Expect(token1).To(Equal("cached-token"))

			token2, err := source.VaultToken(ctx, "tenant-a")
			Expect(err).ToNot(HaveOccurred())
			Expect(token2).To(Equal("cached-token"))

			Expect(vaultCalls.Load()).To(Equal(int32(1)))
		})

		It("produces separate tokens per tenant", func() {
			keycloakServer := httptest.NewServer(newKeycloakHandler("client", "secret", "kc-jwt"))
			DeferCleanup(keycloakServer.Close)

			var capturedNamespaces sync.Map
			vaultServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ns := r.Header.Get("X-Vault-Namespace")
				capturedNamespaces.Store(ns, true)
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{
					"auth": map[string]any{
						"client_token":   fmt.Sprintf("token-for-%s", ns),
						"lease_duration": 3600,
					},
				})
			}))
			DeferCleanup(vaultServer.Close)

			source, err := NewServiceTenantTokenSource().
				SetLogger(logger).
				SetVaultAddress(vaultServer.URL).
				SetParentNamespace("osac").
				SetKeycloakTokenEndpoint(keycloakServer.URL).
				SetKeycloakClientID("client").
				SetKeycloakClientSecret("secret").
				Build()
			Expect(err).ToNot(HaveOccurred())

			tokenA, err := source.VaultToken(ctx, "tenant-a")
			Expect(err).ToNot(HaveOccurred())
			Expect(tokenA).To(Equal("token-for-osac/tenant-a"))

			tokenB, err := source.VaultToken(ctx, "tenant-b")
			Expect(err).ToNot(HaveOccurred())
			Expect(tokenB).To(Equal("token-for-osac/tenant-b"))

			_, loadedA := capturedNamespaces.Load("osac/tenant-a")
			_, loadedB := capturedNamespaces.Load("osac/tenant-b")
			Expect(loadedA).To(BeTrue())
			Expect(loadedB).To(BeTrue())
		})

		It("returns error for empty tenant", func() {
			source, err := NewServiceTenantTokenSource().
				SetLogger(logger).
				SetVaultAddress("http://localhost:8200").
				SetParentNamespace("osac").
				SetKeycloakTokenEndpoint("http://keycloak/token").
				SetKeycloakClientID("client").
				SetKeycloakClientSecret("secret").
				Build()
			Expect(err).ToNot(HaveOccurred())

			_, err = source.VaultToken(ctx, "")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("tenant is required"))
		})

		It("returns error when keycloak fails", func() {
			keycloakServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"error": "invalid_client"}`))
			}))
			DeferCleanup(keycloakServer.Close)

			source, err := NewServiceTenantTokenSource().
				SetLogger(logger).
				SetVaultAddress("http://localhost:8200").
				SetParentNamespace("osac").
				SetKeycloakTokenEndpoint(keycloakServer.URL).
				SetKeycloakClientID("client").
				SetKeycloakClientSecret("secret").
				Build()
			Expect(err).ToNot(HaveOccurred())

			_, err = source.VaultToken(ctx, "tenant-a")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("keycloak"))
		})

		It("returns error when vault login fails", func() {
			keycloakServer := httptest.NewServer(newKeycloakHandler("client", "secret", "kc-jwt"))
			DeferCleanup(keycloakServer.Close)

			vaultServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"errors":["permission denied"]}`))
			}))
			DeferCleanup(vaultServer.Close)

			source, err := NewServiceTenantTokenSource().
				SetLogger(logger).
				SetVaultAddress(vaultServer.URL).
				SetParentNamespace("osac").
				SetKeycloakTokenEndpoint(keycloakServer.URL).
				SetKeycloakClientID("client").
				SetKeycloakClientSecret("secret").
				Build()
			Expect(err).ToNot(HaveOccurred())

			_, err = source.VaultToken(ctx, "tenant-a")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("vault"))
		})

		It("is safe for concurrent access", func() {
			keycloakServer := httptest.NewServer(newKeycloakHandler("client", "secret", "kc-jwt"))
			DeferCleanup(keycloakServer.Close)

			vaultServer := httptest.NewServer(newVaultHandler("kc-jwt", "osac/tenant-a", "concurrent-token", 3600))
			DeferCleanup(vaultServer.Close)

			source, err := NewServiceTenantTokenSource().
				SetLogger(logger).
				SetVaultAddress(vaultServer.URL).
				SetParentNamespace("osac").
				SetKeycloakTokenEndpoint(keycloakServer.URL).
				SetKeycloakClientID("client").
				SetKeycloakClientSecret("secret").
				Build()
			Expect(err).ToNot(HaveOccurred())

			var wg sync.WaitGroup
			errs := make([]error, 10)
			tokens := make([]string, 10)
			for i := 0; i < 10; i++ {
				wg.Add(1)
				go func(idx int) {
					defer wg.Done()
					tokens[idx], errs[idx] = source.VaultToken(ctx, "tenant-a")
				}(i)
			}
			wg.Wait()

			for i := 0; i < 10; i++ {
				Expect(errs[i]).ToNot(HaveOccurred())
				Expect(tokens[i]).To(Equal("concurrent-token"))
			}
		})
	})
})
