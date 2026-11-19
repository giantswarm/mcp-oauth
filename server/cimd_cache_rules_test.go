package server

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/security"
)

func TestMetadataCacheLifetime(t *testing.T) {
	receivedAt := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	const defaultLifetime = 5 * time.Minute

	for _, testCase := range []struct {
		name     string
		header   http.Header
		expected time.Duration
	}{
		{name: "no freshness stated", header: http.Header{}, expected: defaultLifetime},
		{name: "unrelated directives", header: http.Header{"Cache-Control": {"public, must-revalidate"}}, expected: defaultLifetime},
		{name: "max-age", header: http.Header{"Cache-Control": {"public, max-age=600"}}, expected: 10 * time.Minute},
		{name: "quoted max-age", header: http.Header{"Cache-Control": {`max-age="600"`}}, expected: 10 * time.Minute},
		{name: "max-age above cap", header: http.Header{"Cache-Control": {"max-age=7200"}}, expected: time.Hour},
		{name: "max-age overflowing delta-seconds", header: http.Header{"Cache-Control": {"max-age=99999999999999999999"}}, expected: time.Hour},
		{name: "repeated max-age", header: http.Header{"Cache-Control": {"max-age=600", "max-age=60"}}, expected: 0},
		{name: "max-age zero", header: http.Header{"Cache-Control": {"max-age=0"}}, expected: 0},
		{name: "negative max-age", header: http.Header{"Cache-Control": {"max-age=-100"}}, expected: 0},
		{name: "invalid max-age", header: http.Header{"Cache-Control": {"max-age=abc"}}, expected: 0},
		{name: "no-store", header: http.Header{"Cache-Control": {"no-store, max-age=600"}}, expected: 0},
		{name: "no-cache", header: http.Header{"Cache-Control": {"max-age=600, No-Cache"}}, expected: 0},
		{name: "qualified no-cache", header: http.Header{"Cache-Control": {`no-cache="Set-Cookie"`}}, expected: 0},
		{name: "s-maxage ignored", header: http.Header{"Cache-Control": {"s-maxage=0, max-age=600"}}, expected: 10 * time.Minute},
		{name: "age subtracted", header: http.Header{"Cache-Control": {"max-age=600"}, "Age": {"540"}}, expected: time.Minute},
		{name: "age subtracted before cap", header: http.Header{"Cache-Control": {"max-age=86400"}, "Age": {"84600"}}, expected: 30 * time.Minute},
		{name: "age beyond lifetime", header: http.Header{"Cache-Control": {"max-age=600"}, "Age": {"600"}}, expected: 0},
		{name: "invalid age ignored", header: http.Header{"Cache-Control": {"max-age=600"}, "Age": {"soon"}}, expected: 10 * time.Minute},
		{
			name:     "time since date subtracted",
			header:   http.Header{"Cache-Control": {"max-age=600"}, "Date": {receivedAt.Add(-9 * time.Minute).Format(http.TimeFormat)}},
			expected: time.Minute,
		},
		{
			name:     "larger of age and time since date subtracted",
			header:   http.Header{"Cache-Control": {"max-age=600"}, "Date": {receivedAt.Add(-time.Minute).Format(http.TimeFormat)}, "Age": {"300"}},
			expected: 5 * time.Minute,
		},
		{
			name:     "date in the future ignored",
			header:   http.Header{"Cache-Control": {"max-age=600"}, "Date": {receivedAt.Add(time.Hour).Format(http.TimeFormat)}},
			expected: 10 * time.Minute,
		},
		{
			name:     "expires relative to date",
			header:   http.Header{"Date": {receivedAt.Add(-time.Minute).Format(http.TimeFormat)}, "Expires": {receivedAt.Add(2 * time.Minute).Format(http.TimeFormat)}},
			expected: 2 * time.Minute,
		},
		{
			name:     "expires relative to receipt without date",
			header:   http.Header{"Expires": {receivedAt.Add(3 * time.Minute).Format(http.TimeFormat)}},
			expected: 3 * time.Minute,
		},
		{
			name:     "max-age overrides expires",
			header:   http.Header{"Cache-Control": {"max-age=60"}, "Expires": {receivedAt.Add(time.Hour).Format(http.TimeFormat)}},
			expected: time.Minute,
		},
		{name: "expires in the past", header: http.Header{"Expires": {receivedAt.Add(-time.Minute).Format(http.TimeFormat)}}, expected: 0},
		{name: "invalid expires", header: http.Header{"Expires": {"0"}}, expected: 0},
		{
			name:     "expires reached before receipt",
			header:   http.Header{"Date": {receivedAt.Add(-time.Hour).Format(http.TimeFormat)}, "Expires": {receivedAt.Add(-time.Minute).Format(http.TimeFormat)}},
			expected: 0,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.expected, metadataCacheLifetime(testCase.header, receivedAt, defaultLifetime))
		})
	}
}

// metadataResponse is one response of a metadataFixture; zero values serve a
// valid document with status 200.
type metadataResponse struct {
	status       int
	cacheControl string
	expires      string
	invalid      bool
}

// metadataFixture serves its responses in order, repeating the last one. Each
// document's redirect URI carries the number of the request that served it.
type metadataFixture struct {
	clientID  string
	requests  atomic.Int64
	server    *Server
	audit     *bytes.Buffer
	responses []metadataResponse
}

// auditEvents counts the audit events of eventType logged so far.
func (fixture *metadataFixture) auditEvents(eventType string) int {
	return strings.Count(fixture.audit.String(), `"event_type":"`+eventType+`"`)
}

func newMetadataFixture(t *testing.T, rateLimiter *security.RateLimiter, responses ...metadataResponse) *metadataFixture {
	t.Helper()
	fixture := &metadataFixture{audit: &bytes.Buffer{}, responses: responses}
	transport := newTLSServerWithFreshCert(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		number := fixture.requests.Add(1)
		response := fixture.responses[min(int(number), len(fixture.responses))-1]
		if response.cacheControl != "" {
			writer.Header().Set("Cache-Control", response.cacheControl)
		}
		if response.expires != "" {
			writer.Header().Set("Expires", response.expires)
		}
		if response.status != 0 {
			writer.WriteHeader(response.status)
			return
		}
		document := map[string]any{
			"client_id":                  "https://" + request.Host + request.URL.EscapedPath(),
			"client_name":                "Example client",
			"redirect_uris":              []string{redirectURIForRequest(number)},
			"token_endpoint_auth_method": "none",
		}
		if response.invalid {
			delete(document, "client_name")
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(document)
	}))
	pool := x509.NewCertPool()
	pool.AddCert(transport.Certificate())
	config := &Config{
		EnableClientIDMetadataDocuments: true,
		ClientMetadataFetchTimeout:      time.Second,
		ClientMetadataRootCAs:           pool,
		AllowPrivateIPClientMetadata:    true,
	}
	fixture.clientID = transport.URL + "/client.json"
	fixture.server = &Server{
		Config:                   config,
		Logger:                   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Instrumentation:          testInstrumentation(t),
		Auditor:                  security.NewAuditor(slog.New(slog.NewJSONHandler(fixture.audit, nil)), true),
		metadataCache:            newClientMetadataCache(1000),
		metadataFetchRateLimiter: rateLimiter,
	}
	return fixture
}

func redirectURIForRequest(number int64) string {
	return "https://app.example.com/callback/" + strconv.FormatInt(number, 10)
}

func TestGetOrFetchClientHonoursMetadataCacheRules(t *testing.T) {
	past := time.Now().Add(-time.Minute).UTC().Format(http.TimeFormat)

	for _, testCase := range []struct {
		name             string
		first            metadataResponse
		second           metadataResponse
		firstFails       bool
		expectedRequests int64
	}{
		{name: "no-store refetched", first: metadataResponse{cacheControl: "no-store"}, expectedRequests: 2},
		{name: "no-cache refetched", first: metadataResponse{cacheControl: "no-cache"}, expectedRequests: 2},
		{name: "max-age zero refetched", first: metadataResponse{cacheControl: "max-age=0"}, expectedRequests: 2},
		{name: "expired document refetched", first: metadataResponse{expires: past}, expectedRequests: 2},
		{name: "error response not cached", first: metadataResponse{status: http.StatusInternalServerError}, firstFails: true, expectedRequests: 2},
		{name: "not found not cached", first: metadataResponse{status: http.StatusNotFound}, firstFails: true, expectedRequests: 2},
		{name: "invalid document not cached", first: metadataResponse{invalid: true}, firstFails: true, expectedRequests: 2},
		{name: "fresh document reused", first: metadataResponse{cacheControl: "max-age=60"}, expectedRequests: 1},
		{name: "document without freshness reused", first: metadataResponse{}, expectedRequests: 1},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newMetadataFixture(t, nil, testCase.first, testCase.second)

			client, err := fixture.server.getOrFetchClient(t.Context(), fixture.clientID)
			if testCase.firstFails {
				require.Error(t, err)
				require.Equal(t, 1, fixture.auditEvents("client_metadata_fetch_failed"))
			} else {
				require.NoError(t, err)
				require.Equal(t, []string{redirectURIForRequest(1)}, client.RedirectURIs)
			}

			client, err = fixture.server.getOrFetchClient(t.Context(), fixture.clientID)
			require.NoError(t, err)
			require.Equal(t, []string{redirectURIForRequest(testCase.expectedRequests)}, client.RedirectURIs)
			require.Equal(t, testCase.expectedRequests, fixture.requests.Load())
		})
	}
}

func TestGetOrFetchClientRateLimitsUncachedMetadata(t *testing.T) {
	rateLimiter := security.NewRateLimiter(1, 1, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(rateLimiter.Stop)
	fixture := newMetadataFixture(t, rateLimiter, metadataResponse{status: http.StatusInternalServerError})

	_, err := fixture.server.getOrFetchClient(t.Context(), fixture.clientID)
	require.ErrorContains(t, err, "HTTP 500")

	_, err = fixture.server.getOrFetchClient(t.Context(), fixture.clientID)
	require.ErrorContains(t, err, "rate limit exceeded")
	require.Equal(t, int64(1), fixture.requests.Load())
	require.Equal(t, 1, fixture.auditEvents("client_metadata_fetch_failed"))
	require.Equal(t, 1, fixture.auditEvents("client_metadata_rate_limited"))
}

func TestClientMetadataCacheSetWithoutLifetimeStoresNothing(t *testing.T) {
	cache := newClientMetadataCache(10)
	metadata := &ClientMetadata{ClientID: "https://example.com/client", RedirectURIs: []string{"https://app.example.com/callback"}}

	cache.Set(metadata.ClientID, metadata, metadataToClient(metadata), 0)

	_, found := cache.Get(metadata.ClientID)
	require.False(t, found)
	require.Zero(t, cache.Size())
}
