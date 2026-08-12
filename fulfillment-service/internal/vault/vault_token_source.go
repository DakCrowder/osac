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

import "context"

// TokenSource provides Vault tokens on demand using service-level credentials.
// Implementations may cache tokens and handle renewal transparently.
//
//go:generate mockgen -destination=vault_token_source_mock.go -package=vault . TokenSource,TenantTokenSource
type TokenSource interface {
	VaultToken(ctx context.Context) (string, error)
}

// TenantTokenSource provides Vault tokens scoped to a specific tenant.
// The tenant parameter identifies the tenant namespace and must not be empty.
type TenantTokenSource interface {
	VaultToken(ctx context.Context, tenant string) (string, error)
}
