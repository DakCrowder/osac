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
	"net/http"
	"net/http/httptest"

	"github.com/golang-jwt/jwt/v5"
	. "github.com/onsi/ginkgo/v2/dsl/core"
	. "github.com/onsi/gomega"

	"github.com/osac-project/osac/fulfillment-service/internal/auth"
)

var _ = Describe("UserJWTTokenSource", func() {
	var (
		ctx context.Context
	)

	BeforeEach(func() {
		ctx = context.Background()
	})

	newVaultLoginHandler := func(
		expectedNamespace string,
		expectedJWT string,
		expectedRole string,
		returnToken string,
		leaseDuration int,
	) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			Expect(r.URL.Path).To(Equal("/v1/auth/jwt/login"))
			Expect(r.Header.Get("X-Vault-Namespace")).To(Equal(expectedNamespace))

			var reqBody map[string]string
			json.NewDecoder(r.Body).Decode(&reqBody)
			Expect(reqBody["jwt"]).To(Equal(expectedJWT))
			Expect(reqBody["role"]).To(Equal(expectedRole))

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"auth": map[string]any{
					"client_token":   returnToken,
					"lease_duration": leaseDuration,
				},
			})
		}
	}

	contextWithJWT := func(ctx context.Context, rawJWT string) context.Context {
		token := &jwt.Token{Raw: rawJWT}
		return auth.ContextWithToken(ctx, token)
	}

	Describe("Builder", func() {
		It("fails without logger", func() {
			_, err := NewUserJWTTokenSource().
				SetVaultAddress("http://localhost:8200").
				SetParentNamespace("osac").
				Build()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("logger"))
		})

		It("fails without vault address", func() {
			_, err := NewUserJWTTokenSource().
				SetLogger(logger).
				SetParentNamespace("osac").
				Build()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("vault address"))
		})

		It("fails without parent namespace", func() {
			_, err := NewUserJWTTokenSource().
				SetLogger(logger).
				SetVaultAddress("http://localhost:8200").
				Build()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("parent namespace"))
		})

		It("builds successfully with all required fields", func() {
			source, err := NewUserJWTTokenSource().
				SetLogger(logger).
				SetVaultAddress("http://localhost:8200").
				SetParentNamespace("osac").
				Build()
			Expect(err).ToNot(HaveOccurred())
			Expect(source).ToNot(BeNil())
		})
	})

	Describe("VaultToken", func() {
		It("authenticates with the user JWT to the tenant namespace", func() {
			vaultServer := httptest.NewServer(
				newVaultLoginHandler("osac/my-tenant", "user-jwt-token", TenantAuthRole, "vault-token-123", 300),
			)
			DeferCleanup(vaultServer.Close)

			source, err := NewUserJWTTokenSource().
				SetLogger(logger).
				SetVaultAddress(vaultServer.URL).
				SetParentNamespace("osac").
				Build()
			Expect(err).ToNot(HaveOccurred())

			ctx = contextWithJWT(ctx, "user-jwt-token")

			token, err := source.VaultToken(ctx, "my-tenant")
			Expect(err).ToNot(HaveOccurred())
			Expect(token).To(Equal("vault-token-123"))
		})

		It("uses the correct mount path and role from constants", func() {
			var capturedPath string
			var capturedRole string
			vaultServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedPath = r.URL.Path
				var reqBody map[string]string
				json.NewDecoder(r.Body).Decode(&reqBody)
				capturedRole = reqBody["role"]

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{
					"auth": map[string]any{
						"client_token":   "tok",
						"lease_duration": 300,
					},
				})
			}))
			DeferCleanup(vaultServer.Close)

			source, err := NewUserJWTTokenSource().
				SetLogger(logger).
				SetVaultAddress(vaultServer.URL).
				SetParentNamespace("osac").
				Build()
			Expect(err).ToNot(HaveOccurred())

			ctx = contextWithJWT(ctx, "some-jwt")

			_, err = source.VaultToken(ctx, "tenant-a")
			Expect(err).ToNot(HaveOccurred())
			Expect(capturedPath).To(Equal("/v1/auth/" + TenantAuthMountPath + "/login"))
			Expect(capturedRole).To(Equal(TenantAuthRole))
		})

		It("fails when no JWT token is in context", func() {
			source, err := NewUserJWTTokenSource().
				SetLogger(logger).
				SetVaultAddress("http://localhost:8200").
				SetParentNamespace("osac").
				Build()
			Expect(err).ToNot(HaveOccurred())

			_, err = source.VaultToken(ctx, "my-tenant")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("JWT token not found"))
		})

		It("fails when JWT token has empty Raw field", func() {
			source, err := NewUserJWTTokenSource().
				SetLogger(logger).
				SetVaultAddress("http://localhost:8200").
				SetParentNamespace("osac").
				Build()
			Expect(err).ToNot(HaveOccurred())

			ctx = contextWithJWT(ctx, "")

			_, err = source.VaultToken(ctx, "my-tenant")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("JWT token not found"))
		})

		It("fails when tenant is empty", func() {
			source, err := NewUserJWTTokenSource().
				SetLogger(logger).
				SetVaultAddress("http://localhost:8200").
				SetParentNamespace("osac").
				Build()
			Expect(err).ToNot(HaveOccurred())

			ctx = contextWithJWT(ctx, "user-jwt-token")

			_, err = source.VaultToken(ctx, "")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("tenant is required"))
		})

		It("returns error when vault login fails with 403", func() {
			vaultServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"errors":["permission denied"]}`))
			}))
			DeferCleanup(vaultServer.Close)

			source, err := NewUserJWTTokenSource().
				SetLogger(logger).
				SetVaultAddress(vaultServer.URL).
				SetParentNamespace("osac").
				Build()
			Expect(err).ToNot(HaveOccurred())

			ctx = contextWithJWT(ctx, "bad-jwt")

			_, err = source.VaultToken(ctx, "my-tenant")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("403"))
		})

		It("returns error when vault login fails with 500", func() {
			vaultServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"errors":["internal error"]}`))
			}))
			DeferCleanup(vaultServer.Close)

			source, err := NewUserJWTTokenSource().
				SetLogger(logger).
				SetVaultAddress(vaultServer.URL).
				SetParentNamespace("osac").
				Build()
			Expect(err).ToNot(HaveOccurred())

			ctx = contextWithJWT(ctx, "some-jwt")

			_, err = source.VaultToken(ctx, "my-tenant")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("500"))
		})

		It("constructs the correct namespace from parent and tenant", func() {
			var capturedNamespace string
			vaultServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedNamespace = r.Header.Get("X-Vault-Namespace")
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{
					"auth": map[string]any{
						"client_token":   "tok",
						"lease_duration": 300,
					},
				})
			}))
			DeferCleanup(vaultServer.Close)

			source, err := NewUserJWTTokenSource().
				SetLogger(logger).
				SetVaultAddress(vaultServer.URL).
				SetParentNamespace("my-parent-ns").
				Build()
			Expect(err).ToNot(HaveOccurred())

			ctx = contextWithJWT(ctx, "jwt")

			_, err = source.VaultToken(ctx, "tenant-xyz")
			Expect(err).ToNot(HaveOccurred())
			Expect(capturedNamespace).To(Equal("my-parent-ns/tenant-xyz"))
		})
	})
})
