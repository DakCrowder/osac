/*
Copyright (c) 2026 Red Hat Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License.
*/

package provisioners

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/osac-project/osac/fulfillment-service/internal/auth"
	"github.com/osac-project/osac/fulfillment-service/internal/database"
	privatev1 "github.com/osac-project/osac/proto/gen/osac/private/v1"
)

// UserProvisionerBuilder builds a UserProvisioner.
type UserProvisionerBuilder struct {
	logger              *slog.Logger
	usersServer         privatev1.UsersServer
	roleBindingsEnabled bool
}

// UserProvisioner implements auth.UserProvisioner using the PrivateUsersServer.
// The server handles event generation, so user creation automatically triggers events
// for the user controller to reconcile and populate keycloak_user_id in status.
type UserProvisioner struct {
	logger              *slog.Logger
	usersServer         privatev1.UsersServer
	roleBindingsEnabled bool
}

// NewUserProvisioner creates a new builder.
func NewUserProvisioner() *UserProvisionerBuilder {
	return &UserProvisionerBuilder{}
}

// SetLogger sets the logger.
func (b *UserProvisionerBuilder) SetLogger(value *slog.Logger) *UserProvisionerBuilder {
	b.logger = value
	return b
}

// SetUsersServer sets the users server (which handles event generation).
func (b *UserProvisionerBuilder) SetUsersServer(value privatev1.UsersServer) *UserProvisionerBuilder {
	b.usersServer = value
	return b
}

func (b *UserProvisionerBuilder) SetRoleBindingAuthorizationEnabled(value bool) *UserProvisionerBuilder {
	b.roleBindingsEnabled = value
	return b
}

// Build creates the provisioner.
func (b *UserProvisionerBuilder) Build() (result *UserProvisioner, err error) {
	if b.logger == nil {
		return nil, fmt.Errorf("logger is mandatory")
	}
	if b.usersServer == nil {
		return nil, fmt.Errorf("users server is mandatory")
	}
	result = &UserProvisioner{
		logger:              b.logger,
		usersServer:         b.usersServer,
		roleBindingsEnabled: b.roleBindingsEnabled,
	}
	return result, nil
}

// Provision creates a user record if it doesn't exist.
// The server handles event generation, so creating a user will trigger an event
// that the user controller watches. The controller will reconcile the user and
// populate the keycloak_user_id in the status.
func (p *UserProvisioner) Provision(ctx context.Context, username, tenant string, claims jwt.MapClaims) error {
	if p.roleBindingsEnabled {
		subject, _ := claims["sub"].(string)
		if subject == "" {
			return fmt.Errorf("the authenticated user has no identity subject")
		}
		tx, err := database.TxFromContext(ctx)
		if err != nil {
			return err
		}
		var needed, pendingIdentity bool
		err = tx.QueryRow(ctx, `
			with existing as (
				select deletion_timestamp, data from users where tenant = $1 and data #>> '{spec,username}' = $2
			)
			select exists (select 1 from tenants where id = $1 and deletion_timestamp = 'epoch')
			   and not exists (select 1 from existing)
			   and not exists (select 1 from archived_users where tenant = $1 and data #>> '{spec,username}' = $2),
			   exists (select 1 from existing where deletion_timestamp = 'epoch'
				   and data #> '{spec,enabled}' = 'true'::jsonb
				   and coalesce(data #>> '{status,keycloak_user_id}', '') = '')
		`, tenant, username).Scan(&needed, &pendingIdentity)
		if err != nil {
			return err
		}
		if needed {
			return p.create(ctx, username, tenant, claims)
		}
		if pendingIdentity {
			return linkUserIdentity(ctx, tx, tenant, username, subject)
		}
		return nil
	}
	// Check if user exists
	filter := fmt.Sprintf("this.spec.username==%q", username)
	limit := int32(1)
	listResponse, err := p.usersServer.List(ctx, &privatev1.UsersListRequest{
		Filter: &filter,
		Limit:  &limit,
	})
	if err != nil {
		return fmt.Errorf("failed to check if user exists: %w", err)
	}

	// User already exists
	if listResponse.GetSize() > 0 {
		return nil
	}
	return p.create(ctx, username, tenant, claims)
}

func (p *UserProvisioner) create(ctx context.Context, username, tenant string, claims jwt.MapClaims) error {
	// Extract claims
	email, _ := claims["email"].(string)

	// Sanitize username for use as metadata.name (must be DNS-1123 compliant).
	// DNS-1123 requires: lowercase letters, digits, and hyphens only, with no
	// leading or trailing hyphens. The original username is preserved in spec.username.
	sanitizedName := sanitizeForDNS1123(username)
	if p.roleBindingsEnabled && (sanitizedName != username || len(sanitizedName) > 63) {
		digest := sha256.Sum256([]byte(username))
		sanitizedName = fmt.Sprintf("user-%x", digest[:20])
	}

	p.logger.InfoContext(ctx, "Provisioning user",
		slog.String("username", username),
		slog.String("name", sanitizedName),
		slog.String("tenant", tenant),
	)

	// Create user via server (this will trigger events for the controller).
	// Wrap in a savepoint so that a concurrent unique constraint violation
	// (AlreadyExists) doesn't poison the outer PostgreSQL transaction.
	user := privatev1.User_builder{
		Metadata: privatev1.Metadata_builder{
			Name:   sanitizedName,
			Tenant: tenant,
		}.Build(),
		Spec: privatev1.UserSpec_builder{
			Username: username,
			Email:    email,
			Enabled:  true,
		}.Build(),
	}.Build()
	if p.roleBindingsEnabled {
		subject, _ := claims["sub"].(string)
		user.SetStatus(privatev1.UserStatus_builder{KeycloakUserId: subject}.Build())
	}

	tx, err := database.TxFromContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to get transaction: %w", err)
	}
	err = tx.Savepoint(ctx, func(spCtx context.Context) error {
		_, err := p.usersServer.Create(spCtx, &privatev1.UsersCreateRequest{
			Object: user,
		})
		return err
	})
	if err != nil {
		if status.Code(err) == codes.AlreadyExists {
			if p.roleBindingsEnabled {
				return linkUserIdentity(ctx, tx, tenant, username, user.GetStatus().GetKeycloakUserId())
			}
			return nil
		}
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

// Link an explicitly created User on first login. A concurrent request or the
// user reconciler may already have associated a verified identity.
func linkUserIdentity(ctx context.Context, tx database.Tx, tenant, username, subject string) error {
	_, err := tx.Exec(ctx, `
		update users set data = jsonb_set(data, '{status}',
			coalesce(nullif(data->'status', 'null'::jsonb), '{}'::jsonb)
			|| jsonb_build_object('keycloak_user_id', $3::text))
		where tenant = $1 and data #>> '{spec,username}' = $2 and deletion_timestamp = 'epoch'
		  and data #> '{spec,enabled}' = 'true'::jsonb
		  and coalesce(data #>> '{status,keycloak_user_id}', '') = ''
	`, tenant, username, subject)
	return err
}

// sanitizeForDNS1123 converts a username to a DNS-1123 compliant name.
// DNS-1123 names must:
// - Contain only lowercase letters (a-z), digits (0-9), and hyphens (-)
// - Not start or end with a hyphen
func sanitizeForDNS1123(username string) string {
	// Convert to lowercase
	result := strings.ToLower(username)

	// Replace any character that isn't [a-z0-9-] with a hyphen
	var sanitized strings.Builder
	for _, r := range result {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			sanitized.WriteRune(r)
		} else {
			sanitized.WriteRune('-')
		}
	}
	result = sanitized.String()

	// Trim leading and trailing hyphens
	result = strings.Trim(result, "-")

	return result
}

var _ auth.UserProvisioner = (*UserProvisioner)(nil)
