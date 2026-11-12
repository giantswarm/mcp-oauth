package server

import (
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestFetchClientMetadataRequiredFieldsHTTP(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		field    string
		value    any
		remove   bool
		expected string
	}{
		{name: "valid public client"},
		{name: "default public authentication", field: "token_endpoint_auth_method", remove: true},
		{name: "missing name", field: "client_name", remove: true, expected: "client_name is required"},
		{name: "empty name", field: "client_name", value: "", expected: "client_name is required"},
		{name: "missing client ID", field: "client_id", remove: true, expected: "client_id mismatch"},
		{name: "different client ID", field: "client_id", value: "https://other.example.com/client.json", expected: "client_id mismatch"},
		{name: "missing redirects", field: "redirect_uris", remove: true, expected: "redirect_uri"},
		{name: "symmetric basic authentication", field: "token_endpoint_auth_method", value: "client_secret_basic", expected: "token_endpoint_auth_method"},
		{name: "symmetric post authentication", field: "token_endpoint_auth_method", value: "client_secret_post", expected: "token_endpoint_auth_method"},
		{name: "symmetric JWT authentication", field: "token_endpoint_auth_method", value: "client_secret_jwt", expected: "token_endpoint_auth_method"},
		{name: "unsupported asymmetric authentication", field: "token_endpoint_auth_method", value: "private_key_jwt", expected: "token_endpoint_auth_method"},
		{name: "forbidden secret property", field: "client_secret", value: nil, expected: "client_secret"},
		{name: "forbidden secret expiry", field: "client_secret_expires_at", value: 0, expected: "client_secret"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			transport := newTLSServerWithFreshCert(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				document := map[string]any{
					"client_id":                  "https://" + request.Host + request.URL.Path,
					"client_name":                "Example client",
					"redirect_uris":              []string{"https://app.example.com/callback"},
					"token_endpoint_auth_method": "none",
				}
				if testCase.field != "" {
					if testCase.remove {
						delete(document, testCase.field)
					} else {
						document[testCase.field] = testCase.value
					}
				}
				writer.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(writer).Encode(document)
			}))
			pool := x509.NewCertPool()
			pool.AddCert(transport.Certificate())
			authorizationServer := &Server{
				Config: &Config{
					ClientMetadataFetchTimeout:        time.Second,
					ClientMetadataRootCAs:             pool,
					AllowPrivateIPClientMetadataHosts: []string{"127.0.0.1"},
				},
				Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
				Instrumentation: testInstrumentation(t),
				Auditor:         testAuditor(),
			}
			metadata, _, err := authorizationServer.fetchClientMetadata(t.Context(), transport.URL+"/client.json")
			if testCase.expected != "" {
				require.ErrorContains(t, err, testCase.expected)
				require.Nil(t, metadata)
				return
			}
			require.NoError(t, err)
			require.Equal(t, "Example client", metadata.ClientName)
			require.Equal(t, "none", metadata.TokenEndpointAuthMethod)
		})
	}
}

func TestClientMetadataIdentifierRequirements(t *testing.T) {
	for _, identifier := range []string{
		"https://example.com",
		"https://example.com/./client.json",
		"https://example.com/path/../client.json",
		"https://example.com/%2e/client.json",
		"https://example.com/path/%2e%2e/client.json",
	} {
		t.Run(identifier, func(t *testing.T) {
			require.False(t, isURLClientID(identifier))
		})
	}
	for _, identifier := range []string{"https://example.com/", "https://example.com/client.json", "https://example.com/client%2Fmetadata.json"} {
		t.Run(identifier, func(t *testing.T) {
			require.True(t, isURLClientID(identifier))
		})
	}
}

func TestClientMetadataURLPreservesEscapedPath(t *testing.T) {
	identifier := "https://127.0.0.1/client%2Fmetadata.json"
	actual, err := validateAndSanitizeMetadataURL(identifier, false, []string{"127.0.0.1"})
	require.NoError(t, err)
	require.Equal(t, identifier, actual)
}
