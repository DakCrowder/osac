/*
Copyright (c) 2026 Red Hat Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License.
*/

package migrations

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
	. "github.com/onsi/ginkgo/v2/dsl/core"
	. "github.com/onsi/gomega"
)

var _ = DescribeMigration("Add Secret delete protection trigger", func() {
	BeforeEach(func(ctx context.Context) {
		err := tool.Migrate(ctx, 107)
		Expect(err).ToNot(HaveOccurred())

		_, err = conn.Exec(ctx, `
			insert into tenants (id, name, tenant, creator, data)
			values ('test-tenant', 'test-tenant', 'test-tenant', 'system', '{}')
			on conflict do nothing`)
		Expect(err).ToNot(HaveOccurred())
	})

	insertSecret := func(ctx context.Context, id, backend string) {
		_, err := conn.Exec(ctx,
			`insert into secrets (id, name, tenant, data) values ($1, $1, 'test-tenant', $2::jsonb)`,
			id, `{"backend":"`+backend+`"}`)
		Expect(err).ToNot(HaveOccurred())
	}

	deleteSecret := func(ctx context.Context, id string) error {
		_, err := conn.Exec(ctx, `update secrets set deletion_timestamp = now() where id = $1`, id)
		return err
	}

	expectInUse := func(err error) {
		Expect(err).To(HaveOccurred())
		var pgErr *pgconn.PgError
		Expect(errors.As(err, &pgErr)).To(BeTrue())
		Expect(pgErr.Code).To(Equal("Z0003"))
		Expect(pgErr.Message).ToNot(ContainSubstring("dependent-"))
	}

	It("creates indexes for every SecretLocalReference path", func(ctx context.Context) {
		indexNames := []string{
			"clusters_pull_secret_secret",
			"cluster_templates_pull_secret_secret",
			"hubs_kubeconfig_secret",
			"identity_providers_client_secret_secret",
			"storage_backends_password_secret",
		}

		for _, indexName := range indexNames {
			var exists bool
			err := conn.QueryRow(ctx, `
				select exists (
					select 1
					from pg_indexes
					where schemaname = current_schema()
					  and indexname = $1
				)`, indexName).Scan(&exists)
			Expect(err).ToNot(HaveOccurred())
			Expect(exists).To(BeTrue(), "expected index %q to exist", indexName)
		}
	})

	It("rejects deletion when an active Cluster references the Secret", func(ctx context.Context) {
		insertSecret(ctx, "secret-1", "SECRET_BACKEND_VAULT")
		_, err := conn.Exec(ctx, `insert into clusters (id, name, tenant, data) values ('dependent-cluster', 'dependent-cluster', 'test-tenant', '{"spec":{"pull_secret_secret":{"id":"secret-1"}}}')`)
		Expect(err).ToNot(HaveOccurred())
		expectInUse(deleteSecret(ctx, "secret-1"))
	})

	It("rejects deletion for every other active SecretLocalReference", func(ctx context.Context) {
		for index, test := range []struct {
			name  string
			table string
			data  string
		}{
			{"ClusterTemplate pull secret", "cluster_templates", `{"spec_defaults":{"pull_secret_secret":{"id":"secret-1"}}}`},
			{"Hub kubeconfig", "hubs", `{"spec":{"kubeconfig_secret":{"id":"secret-1"}}}`},
			{"IdentityProvider OIDC client secret", "identity_providers", `{"spec":{"open_id_connect":{"client_secret_secret":{"id":"secret-1"}}}}`},
			{"StorageBackend credential password", "storage_backends", `{"spec":{"credentials":{"password_secret":{"id":"secret-1"}}}}`},
		} {
			secretID := fmt.Sprintf("secret-%d", index)
			data := strings.ReplaceAll(test.data, "secret-1", secretID)
			insertSecret(ctx, secretID, "SECRET_BACKEND_VAULT")
			_, err := conn.Exec(ctx, `insert into `+test.table+` (id, name, tenant, data) values ($1, $1, 'test-tenant', $2::jsonb)`, fmt.Sprintf("dependent-resource-%d", index), data)
			Expect(err).ToNot(HaveOccurred(), test.name)
			expectInUse(deleteSecret(ctx, secretID))
		}
	})

	It("allows deletion of a system-managed Tenant break-glass Secret", func(ctx context.Context) {
		insertSecret(ctx, "secret-1", "SECRET_BACKEND_UNSPECIFIED")
		_, err := conn.Exec(ctx, `update tenants set data = '{"spec":{"break_glass_credentials_secret":{"id":"secret-1"}}}'::jsonb where id = 'test-tenant'`)
		Expect(err).ToNot(HaveOccurred())

		Expect(deleteSecret(ctx, "secret-1")).ToNot(HaveOccurred())
	})

	It("allows deletion when the Secret is unreferenced", func(ctx context.Context) {
		insertSecret(ctx, "secret-1", "SECRET_BACKEND_VAULT")
		Expect(deleteSecret(ctx, "secret-1")).ToNot(HaveOccurred())
	})

	It("allows deletion when its sole dependent is soft-deleted", func(ctx context.Context) {
		insertSecret(ctx, "secret-1", "SECRET_BACKEND_VAULT")
		_, err := conn.Exec(ctx, `insert into clusters (id, name, tenant, data) values ('dependent-cluster', 'dependent-cluster', 'test-tenant', '{"spec":{"pull_secret_secret":{"id":"secret-1"}}}')`)
		Expect(err).ToNot(HaveOccurred())
		_, err = conn.Exec(ctx, `update clusters set deletion_timestamp = now() where id = 'dependent-cluster'`)
		Expect(err).ToNot(HaveOccurred())

		Expect(deleteSecret(ctx, "secret-1")).ToNot(HaveOccurred())
	})

	It("allows deletion of a HUB-backed Secret referenced by an active Cluster", func(ctx context.Context) {
		insertSecret(ctx, "secret-1", "SECRET_BACKEND_HUB")
		_, err := conn.Exec(ctx, `insert into clusters (id, name, tenant, data) values ('dependent-cluster', 'dependent-cluster', 'test-tenant', '{"spec":{"pull_secret_secret":{"id":"secret-1"}}}')`)
		Expect(err).ToNot(HaveOccurred())

		Expect(deleteSecret(ctx, "secret-1")).ToNot(HaveOccurred())
	})
})
