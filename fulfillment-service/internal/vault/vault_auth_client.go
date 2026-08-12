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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type keycloakTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

func fetchKeycloakToken(ctx context.Context, httpClient *http.Client, endpoint, clientID, clientSecret string) (string, int, error) {
	form := url.Values{
		"grant_type":    {oauth2ClientCredentials},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}

	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, endpoint,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return "", 0, fmt.Errorf("failed to create keycloak request: %w", err)
	}
	req.Header.Set(contentTypeHeader, applicationFormURLencoded)

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("keycloak token request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, fmt.Errorf("failed to read keycloak response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("keycloak returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var tokenResp keycloakTokenResponse
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return "", 0, fmt.Errorf("failed to decode keycloak response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return "", 0, errors.New("keycloak returned empty access token")
	}

	return tokenResp.AccessToken, tokenResp.ExpiresIn, nil
}
