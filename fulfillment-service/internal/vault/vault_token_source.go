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

// VaultTokenSource provides Vault tokens on demand. Implementations may cache tokens and
// handle renewal transparently.
type VaultTokenSource interface {
	VaultToken(ctx context.Context) (string, error)
}

// StaticVaultTokenSource wraps a fixed token string. Intended for tests and dev environments.
type StaticVaultTokenSource struct {
	token string
}

func NewStaticVaultTokenSource(token string) *StaticVaultTokenSource {
	return &StaticVaultTokenSource{token: token}
}

func (s *StaticVaultTokenSource) VaultToken(_ context.Context) (string, error) {
	return s.token, nil
}
