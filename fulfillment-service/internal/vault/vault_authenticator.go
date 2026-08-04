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
	"fmt"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// RequestAuth contains the JWT information needed to authenticate a request to Vault.
type RequestAuth struct {
	RawJWT string
	JTI    string
}

// RequestAuthSource extracts JWT auth information from a request context. Implementations
// typically read the validated JWT placed in the context by the gRPC authentication interceptor.
type RequestAuthSource func(ctx context.Context) (*RequestAuth, error)

// VaultLoginResult contains the token and TTL returned by a Vault auth login.
type VaultLoginResult struct {
	Token string
	TTL   time.Duration
}

// jwtLogin authenticates to a Vault JWT auth mount and returns the client token and TTL.
func jwtLogin(ctx context.Context, client *vaultapi.Client, mountPath, role, rawJWT string) (
	*VaultLoginResult, error) {
	path := fmt.Sprintf("auth/%s/login", mountPath)
	secret, err := client.Logical().WriteWithContext(ctx, path, map[string]any{
		"jwt":  rawJWT,
		"role": role,
	})
	if err != nil {
		return nil, fmt.Errorf("vault JWT login failed: %w", err)
	}
	if secret == nil || secret.Auth == nil {
		return nil, fmt.Errorf("vault JWT login returned no auth data")
	}
	return &VaultLoginResult{
		Token: secret.Auth.ClientToken,
		TTL:   time.Duration(secret.Auth.LeaseDuration) * time.Second,
	}, nil
}
