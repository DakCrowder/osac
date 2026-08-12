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

type vaultContextKey int

const (
	tenantContextKey vaultContextKey = iota
)

// ContextWithTenant returns a new context with the given tenant name stored for use by
// VaultTokenSource implementations that need tenant-scoped authentication.
func ContextWithTenant(parent context.Context, tenant string) context.Context {
	return context.WithValue(parent, tenantContextKey, tenant)
}

// TenantFromContext extracts the tenant name previously stored by ContextWithTenant.
// Returns empty string if no tenant is present.
func TenantFromContext(ctx context.Context) string {
	value := ctx.Value(tenantContextKey)
	if value == nil {
		return ""
	}
	tenant, ok := value.(string)
	if !ok {
		return ""
	}
	return tenant
}
