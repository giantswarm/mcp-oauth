package oidc

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// RevokeAtEndpoint posts an RFC 7009 token revocation to endpoint. When
// clientID is non-empty the request authenticates via HTTP Basic
// (client_secret_basic); endpoints that do not require client authentication
// (e.g. Google's public revocation endpoint) leave clientID/clientSecret
// empty and skip the header.
//
// Per RFC 7009 §2.2 the server SHOULD respond 200 even for an unknown token,
// so anything other than 200 surfaces as an error to the caller.
func RevokeAtEndpoint(ctx context.Context, httpClient *http.Client, endpoint, token, clientID, clientSecret string) error {
	if endpoint == "" {
		return fmt.Errorf("revocation endpoint is empty")
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	form := url.Values{}
	form.Set("token", token)

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create revoke request: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if clientID != "" {
		// RFC 6749 §2.3.1 requires form encoding each Basic credential component.
		request.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(clientSecret))
	}

	response, err := httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("failed to revoke token: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("token revocation failed with status %d", response.StatusCode)
	}
	return nil
}
