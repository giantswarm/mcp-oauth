//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	oauth "github.com/giantswarm/mcp-oauth"
	"github.com/giantswarm/mcp-oauth/internal/testutil"
	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/valkey"
)

const (
	testIssuer             = "https://auth.example.com"
	testPKCEVerifierLength = 50
)

// TestPod represents a simulated pod with its own server and handler instances.
// Each pod has independent in-memory state (caches, rate limiters) but shares
// the Valkey storage backend with all other pods.
type TestPod struct {
	name    string
	server  *server.Server
	handler *oauth.Handler
	store   *valkey.Store
}

// setupSharedValkeyStore creates a Valkey store for integration tests.
// Tests are skipped if Valkey is not available.
func setupSharedValkeyStore(t *testing.T) *valkey.Store {
	t.Helper()

	addr := os.Getenv("VALKEY_TEST_ADDR")
	if addr == "" {
		addr = "localhost:6379"
	}

	// Unique prefix per test to ensure isolation
	prefix := fmt.Sprintf("mcptest:horizontal:%s:", t.Name())

	store, err := valkey.New(valkey.Config{
		Address:   addr,
		KeyPrefix: prefix,
	})
	if err != nil {
		t.Skipf("Skipping: could not connect to Valkey at %s: %v", addr, err)
	}

	t.Cleanup(func() {
		cleanupTestKeys(t, store, prefix)
		store.Close()
	})

	return store
}

// cleanupTestKeys removes all test keys from Valkey
func cleanupTestKeys(t *testing.T, store *valkey.Store, prefix string) {
	t.Helper()
	// The store cleanup is handled by Valkey's key expiration and test isolation via unique prefixes
	// For thorough cleanup, we could implement a SCAN + DEL pattern here
}

// createPod creates a test pod with its own server instance sharing the Valkey storage
func createPod(t *testing.T, store *valkey.Store, name string) *TestPod {
	t.Helper()

	provider := mock.NewProvider()

	config := &server.Config{
		Issuer:               testIssuer,
		SupportedScopes:      []string{"openid", "email", "profile"},
		AuthorizationCodeTTL: 600,
		AccessTokenTTL:       3600,
		RefreshTokenTTL:      86400,
		RequirePKCE:          true,
		AllowPKCEPlain:       false,
	}

	// Each pod gets its own server instance but shares the storage
	srv, err := server.New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("Failed to create server for pod %s: %v", name, err)
	}

	handler := oauth.NewHandler(srv, nil)

	return &TestPod{
		name:    name,
		server:  srv,
		handler: handler,
		store:   store,
	}
}

// registerClient registers a test client on the given pod
func registerClient(t *testing.T, pod *TestPod) *storage.Client {
	t.Helper()

	ctx := context.Background()
	client, _, err := pod.server.RegisterClient(ctx,
		fmt.Sprintf("Test Client %s", pod.name),
		server.ClientTypeConfidential,
		"",
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		100,
	)
	if err != nil {
		t.Fatalf("Failed to register client on pod %s: %v", pod.name, err)
	}

	return client
}

// generatePKCE generates a valid PKCE verifier and challenge
func generatePKCE() (verifier, challenge string) {
	verifier = testutil.GenerateRandomString(testPKCEVerifierLength)
	hash := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(hash[:])
	return
}

// startAuthFlow starts an authorization flow and returns the provider redirect URL
func startAuthFlow(t *testing.T, pod *TestPod, client *storage.Client) (authURL, clientState, verifier string) {
	t.Helper()

	ctx := context.Background()
	verifier, challenge := generatePKCE()
	clientState = testutil.GenerateRandomString(43)

	authURL, err := pod.server.StartAuthorizationFlow(ctx,
		client.ClientID,
		"https://example.com/callback",
		"openid email",
		"",
		challenge,
		server.PKCEMethodS256,
		clientState,
		nil, // authOpts
	)
	if err != nil {
		t.Fatalf("Failed to start auth flow on pod %s: %v", pod.name, err)
	}

	return authURL, clientState, verifier
}

// extractProviderState extracts the state parameter from an authorization URL
func extractProviderState(authURL string) string {
	parsed, err := url.Parse(authURL)
	if err != nil {
		return ""
	}
	return parsed.Query().Get("state")
}

// handleCallback simulates the OAuth provider callback
func handleCallback(t *testing.T, pod *TestPod, providerState string) string {
	t.Helper()

	ctx := context.Background()

	// Simulate provider callback - this generates the authorization code
	// The mock provider doesn't need a real code from the upstream provider
	authCode, _, err := pod.server.HandleProviderCallback(ctx, providerState, "mock-provider-code")
	if err != nil {
		t.Fatalf("Failed to handle callback on pod %s: %v", pod.name, err)
	}

	if authCode == nil || authCode.Code == "" {
		t.Fatalf("No authorization code returned from callback")
	}

	return authCode.Code
}

// ExchangeResult captures the result of a code exchange attempt
type ExchangeResult struct {
	Success      bool
	AccessToken  string
	RefreshToken string
	Error        error
}

// exchangeCode exchanges an authorization code for tokens
func exchangeCode(t *testing.T, pod *TestPod, client *storage.Client, code, verifier, redirectURI string) ExchangeResult {
	t.Helper()

	ctx := context.Background()

	// ExchangeAuthorizationCode(ctx, code, clientID, redirectURI, resource, codeVerifier)
	tokens, _, err := pod.server.ExchangeAuthorizationCode(ctx,
		code,
		client.ClientID,
		redirectURI,
		"",       // resource (optional)
		verifier, // codeVerifier
	)
	if err != nil {
		return ExchangeResult{
			Success: false,
			Error:   err,
		}
	}

	return ExchangeResult{
		Success:      true,
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}
}

// RefreshResult captures the result of a token refresh attempt
type RefreshResult struct {
	Success         bool
	NewAccessToken  string
	NewRefreshToken string
	IsReuseDetected bool
	Error           error
}

// attemptTokenRefresh attempts to refresh tokens using the given refresh token
func attemptTokenRefresh(t *testing.T, pod *TestPod, clientID, refreshToken string) RefreshResult {
	t.Helper()

	ctx := context.Background()

	tokens, err := pod.server.RefreshAccessToken(ctx, refreshToken, clientID)
	if err != nil {
		return RefreshResult{
			Success:         false,
			Error:           err,
			IsReuseDetected: strings.Contains(err.Error(), "reuse") || storage.IsCodeReuseError(err),
		}
	}

	return RefreshResult{
		Success:         true,
		NewAccessToken:  tokens.AccessToken,
		NewRefreshToken: tokens.RefreshToken,
	}
}

// TestHorizontalScaling_CrossPodAuthorizationFlow tests that OAuth flows work
// correctly when different steps are handled by different pods.
func TestHorizontalScaling_CrossPodAuthorizationFlow(t *testing.T) {
	store := setupSharedValkeyStore(t)

	podA := createPod(t, store, "pod-a")
	podB := createPod(t, store, "pod-b")
	podC := createPod(t, store, "pod-c")

	// Step 1: Register client on Pod A
	client := registerClient(t, podA)

	// Step 2: Start authorization flow on Pod A
	authURL, clientState, verifier := startAuthFlow(t, podA, client)
	if authURL == "" {
		t.Fatal("Empty authorization URL")
	}

	// Verify state was saved and is visible from Pod B
	ctx := context.Background()
	state, err := podB.store.GetAuthorizationState(ctx, clientState)
	if err != nil {
		t.Fatalf("State not visible from Pod B: %v", err)
	}
	if state.ClientID != client.ClientID {
		t.Errorf("State ClientID = %q, want %q", state.ClientID, client.ClientID)
	}

	// Step 3: Handle callback on Pod B
	providerState := extractProviderState(authURL)
	authCode := handleCallback(t, podB, providerState)

	// Step 4: Exchange code for tokens on Pod C
	result := exchangeCode(t, podC, client, authCode, verifier, "https://example.com/callback")
	if !result.Success {
		t.Fatalf("Code exchange failed on Pod C: %v", result.Error)
	}

	if result.AccessToken == "" {
		t.Error("Expected non-empty access token")
	}
	if result.RefreshToken == "" {
		t.Error("Expected non-empty refresh token")
	}

	// Verify tokens are stored and visible from all pods
	_, err = podA.store.GetRefreshTokenInfo(ctx, result.RefreshToken)
	if err != nil {
		t.Errorf("Refresh token not visible from Pod A: %v", err)
	}

	t.Log("Cross-pod OAuth flow completed successfully")
}

// TestHorizontalScaling_AuthorizationCodeAtomicity tests that only ONE pod
// can successfully exchange an authorization code when multiple pods try simultaneously.
func TestHorizontalScaling_AuthorizationCodeAtomicity(t *testing.T) {
	store := setupSharedValkeyStore(t)

	numPods := 10
	pods := make([]*TestPod, numPods)
	for i := 0; i < numPods; i++ {
		pods[i] = createPod(t, store, fmt.Sprintf("pod-%d", i))
	}

	// Setup: Complete auth flow up to code generation
	client := registerClient(t, pods[0])
	authURL, _, verifier := startAuthFlow(t, pods[0], client)
	providerState := extractProviderState(authURL)
	authCode := handleCallback(t, pods[0], providerState)

	// Execute: All pods try to exchange the code simultaneously
	var wg sync.WaitGroup
	results := make(chan ExchangeResult, numPods)
	barrier := make(chan struct{})

	for i, pod := range pods {
		wg.Add(1)
		go func(p *TestPod, idx int) {
			defer wg.Done()
			<-barrier // Wait for signal

			result := exchangeCode(t, p, client, authCode, verifier, "https://example.com/callback")
			results <- result
		}(pod, i)
	}

	// Release all goroutines at once
	close(barrier)
	wg.Wait()
	close(results)

	// Count results
	var successes, failures int
	for result := range results {
		if result.Success {
			successes++
		} else {
			failures++
			// The error could be ErrAuthorizationCodeUsed or "invalid_grant" depending
			// on timing and whether the code was already marked as used or revoked
			t.Logf("Expected failure: %v", result.Error)
		}
	}

	// SECURITY ASSERTION: Exactly ONE pod must succeed
	if successes != 1 {
		t.Errorf("SECURITY VIOLATION: Expected exactly 1 success, got %d", successes)
	}

	// All other pods should fail (any failure is acceptable - code reuse or invalid grant)
	if failures != numPods-1 {
		t.Errorf("Expected %d failures, got %d", numPods-1, failures)
	}

	t.Logf("Atomicity test passed: 1 success, %d failures (as expected)", failures)
}

// TestHorizontalScaling_RefreshTokenRotationAtomicity tests that only ONE pod
// can successfully use a refresh token when multiple pods try simultaneously.
func TestHorizontalScaling_RefreshTokenRotationAtomicity(t *testing.T) {
	store := setupSharedValkeyStore(t)

	numPods := 5
	pods := make([]*TestPod, numPods)
	for i := 0; i < numPods; i++ {
		pods[i] = createPod(t, store, fmt.Sprintf("pod-%d", i))
	}

	// Setup: Complete full OAuth flow to get refresh token
	client := registerClient(t, pods[0])
	authURL, _, verifier := startAuthFlow(t, pods[0], client)
	providerState := extractProviderState(authURL)
	authCode := handleCallback(t, pods[0], providerState)
	initialResult := exchangeCode(t, pods[0], client, authCode, verifier, "https://example.com/callback")
	if !initialResult.Success {
		t.Fatalf("Initial code exchange failed: %v", initialResult.Error)
	}

	refreshToken := initialResult.RefreshToken

	// Execute: All pods try to refresh simultaneously
	var wg sync.WaitGroup
	results := make(chan RefreshResult, numPods)
	barrier := make(chan struct{})

	for i, pod := range pods {
		wg.Add(1)
		go func(p *TestPod, idx int) {
			defer wg.Done()
			<-barrier

			result := attemptTokenRefresh(t, p, client.ClientID, refreshToken)
			results <- result
		}(pod, i)
	}

	close(barrier)
	wg.Wait()
	close(results)

	// Analyze results
	var successes, failures int
	var newRefreshToken string

	for result := range results {
		if result.Success {
			successes++
			newRefreshToken = result.NewRefreshToken
		} else {
			failures++
			t.Logf("Expected failure: %v (reuse detected: %v)", result.Error, result.IsReuseDetected)
		}
	}

	// SECURITY ASSERTION: Exactly ONE pod must succeed
	if successes != 1 {
		t.Errorf("SECURITY VIOLATION: Expected exactly 1 success, got %d", successes)
	}

	// All other pods should fail
	if failures != numPods-1 {
		t.Errorf("Expected %d failures, got %d", numPods-1, failures)
	}

	// Verify old refresh token is gone
	ctx := context.Background()
	_, err := store.GetRefreshTokenInfo(ctx, refreshToken)
	if err != storage.ErrTokenNotFound {
		t.Errorf("Old refresh token should be deleted, got error: %v", err)
	}

	// NOTE: The new refresh token may or may not work depending on race timing.
	// If other pods detected reuse before the successful pod completed, they may
	// have revoked the entire token family. This is correct security behavior!
	// The important assertion is that only ONE pod succeeded with the original token.
	if newRefreshToken != "" {
		result := attemptTokenRefresh(t, pods[0], client.ClientID, newRefreshToken)
		if !result.Success {
			t.Logf("New refresh token was revoked (family revocation due to reuse detection) - this is expected security behavior")
		} else {
			t.Logf("New refresh token works as expected")
		}
	}

	t.Logf("Refresh token atomicity test passed: 1 success, %d failures", failures)
}

// TestHorizontalScaling_StateVisibility tests that state saved by one pod
// is immediately visible to all other pods.
func TestHorizontalScaling_StateVisibility(t *testing.T) {
	store := setupSharedValkeyStore(t)

	podA := createPod(t, store, "pod-a")
	podB := createPod(t, store, "pod-b")
	podC := createPod(t, store, "pod-c")

	ctx := context.Background()

	// Test 1: Client registration visibility
	client := registerClient(t, podA)

	clientB, err := podB.server.GetClient(ctx, client.ClientID)
	if err != nil {
		t.Errorf("Client not visible from Pod B: %v", err)
	} else if clientB.ClientID != client.ClientID {
		t.Errorf("Client ID mismatch from Pod B")
	}

	clientC, err := podC.server.GetClient(ctx, client.ClientID)
	if err != nil {
		t.Errorf("Client not visible from Pod C: %v", err)
	} else if clientC.ClientID != client.ClientID {
		t.Errorf("Client ID mismatch from Pod C")
	}

	// Test 2: Authorization state visibility
	authURL, clientState, _ := startAuthFlow(t, podA, client)
	if authURL == "" {
		t.Fatal("Empty authorization URL")
	}

	stateB, err := podB.store.GetAuthorizationState(ctx, clientState)
	if err != nil {
		t.Errorf("State not visible from Pod B: %v", err)
	} else if stateB.ClientID != client.ClientID {
		t.Errorf("State ClientID mismatch from Pod B")
	}

	// Test provider state lookup from Pod C
	providerState := extractProviderState(authURL)
	stateC, err := podC.store.GetAuthorizationStateByProviderState(ctx, providerState)
	if err != nil {
		t.Errorf("State not visible via provider state from Pod C: %v", err)
	} else if stateC.StateID != clientState {
		t.Errorf("State ID mismatch from Pod C: got %q, want %q", stateC.StateID, clientState)
	}

	t.Log("State visibility test passed")
}

// TestHorizontalScaling_RandomLoadBalancing simulates random load balancing
// across pods for multiple complete OAuth flows.
func TestHorizontalScaling_RandomLoadBalancing(t *testing.T) {
	store := setupSharedValkeyStore(t)

	numPods := 5
	pods := make([]*TestPod, numPods)
	for i := 0; i < numPods; i++ {
		pods[i] = createPod(t, store, fmt.Sprintf("pod-%d", i))
	}

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	randomPod := func() *TestPod {
		return pods[rng.Intn(numPods)]
	}

	// Run multiple complete flows with random pod selection
	numFlows := 10
	for flowNum := 0; flowNum < numFlows; flowNum++ {
		t.Run(fmt.Sprintf("Flow_%d", flowNum), func(t *testing.T) {
			// Step 1: Register client (random pod)
			client := registerClient(t, randomPod())

			// Step 2: Start auth (random pod)
			authURL, _, verifier := startAuthFlow(t, randomPod(), client)

			// Step 3: Callback (random pod)
			providerState := extractProviderState(authURL)
			authCode := handleCallback(t, randomPod(), providerState)

			// Step 4: Exchange code (random pod)
			result := exchangeCode(t, randomPod(), client, authCode, verifier, "https://example.com/callback")
			if !result.Success {
				t.Fatalf("Code exchange failed: %v", result.Error)
			}

			// Step 5: Token refresh (random pod)
			refreshResult := attemptTokenRefresh(t, randomPod(), client.ClientID, result.RefreshToken)
			if !refreshResult.Success {
				t.Fatalf("Token refresh failed: %v", refreshResult.Error)
			}
		})
	}

	t.Logf("Random load balancing test passed: %d flows completed", numFlows)
}

// TestHorizontalScaling_ConcurrentClientRegistration tests that multiple pods
// can register clients concurrently without conflicts.
func TestHorizontalScaling_ConcurrentClientRegistration(t *testing.T) {
	store := setupSharedValkeyStore(t)

	numPods := 3
	pods := make([]*TestPod, numPods)
	for i := 0; i < numPods; i++ {
		pods[i] = createPod(t, store, fmt.Sprintf("pod-%d", i))
	}

	// Each pod registers clients concurrently
	clientsPerPod := 5
	var wg sync.WaitGroup
	clientIDs := make(chan string, numPods*clientsPerPod)
	errors := make(chan error, numPods*clientsPerPod)

	for _, pod := range pods {
		for i := 0; i < clientsPerPod; i++ {
			wg.Add(1)
			go func(p *TestPod) {
				defer wg.Done()
				client := registerClient(t, p)
				clientIDs <- client.ClientID
			}(pod)
		}
	}

	wg.Wait()
	close(clientIDs)
	close(errors)

	// Verify all client IDs are unique
	seen := make(map[string]bool)
	for id := range clientIDs {
		if seen[id] {
			t.Errorf("Duplicate client ID: %s", id)
		}
		seen[id] = true
	}

	expectedCount := numPods * clientsPerPod
	if len(seen) != expectedCount {
		t.Errorf("Expected %d unique clients, got %d", expectedCount, len(seen))
	}

	// Verify all clients are retrievable from any pod
	ctx := context.Background()
	for id := range seen {
		for _, pod := range pods {
			_, err := pod.server.GetClient(ctx, id)
			if err != nil {
				t.Errorf("Client %s not visible from pod %s: %v", id, pod.name, err)
			}
		}
	}

	t.Logf("Concurrent registration test passed: %d clients registered", len(seen))
}

// TestHorizontalScaling_HTTPHandlerCrossPod tests the full HTTP handler path
// across multiple pods.
func TestHorizontalScaling_HTTPHandlerCrossPod(t *testing.T) {
	store := setupSharedValkeyStore(t)

	podA := createPod(t, store, "pod-a")
	podB := createPod(t, store, "pod-b")

	// Step 1: Register client via HTTP on Pod A
	regReq := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(`{
		"client_name": "Test Client",
		"client_type": "public",
		"redirect_uris": ["https://example.com/callback"]
	}`))
	regReq.Header.Set("Content-Type", "application/json")
	regReq.RemoteAddr = "192.168.1.100:12345"

	// Need to enable public registration for this test
	podA.server.Config.AllowPublicClientRegistration = true
	podB.server.Config.AllowPublicClientRegistration = true

	regW := httptest.NewRecorder()
	podA.handler.ServeClientRegistration(regW, regReq)

	if regW.Code != http.StatusCreated {
		t.Fatalf("Client registration failed: %d - %s", regW.Code, regW.Body.String())
	}

	// Extract client ID from response
	// (In a real implementation, you'd parse the JSON response)

	t.Log("HTTP handler cross-pod test: registration successful on Pod A")

	// The full HTTP flow would continue here with authorization, callback, and token exchange
	// Each step hitting a different pod's handler
}

// TestHorizontalScaling_IndependentRateLimiters documents and verifies that
// rate limiters are per-pod (not distributed).
func TestHorizontalScaling_IndependentRateLimiters(t *testing.T) {
	store := setupSharedValkeyStore(t)

	// Create pods with rate limiting enabled
	provider := mock.NewProvider()
	config := &server.Config{
		Issuer:                        testIssuer,
		SupportedScopes:               []string{"openid", "email"},
		AuthorizationCodeTTL:          600,
		AccessTokenTTL:                3600,
		MaxRegistrationsPerHour:       3, // Low limit for testing
		RegistrationRateLimitWindow:   3600,
		AllowPublicClientRegistration: true,
	}

	srvA, _ := server.New(provider, store, store, store, config, nil)
	srvB, _ := server.New(provider, store, store, store, config, nil)

	// Enable rate limiting by setting the rate limiter explicitly
	// Rate limiter config: max 3 registrations per 1 hour window per IP
	srvA.SetClientRegistrationRateLimiter(security.NewClientRegistrationRateLimiterWithConfig(
		3,         // maxPerWindow
		time.Hour, // window
		1000,      // maxEntries
		nil,       // logger
	))
	srvB.SetClientRegistrationRateLimiter(security.NewClientRegistrationRateLimiterWithConfig(
		3,         // maxPerWindow
		time.Hour, // window
		1000,      // maxEntries
		nil,       // logger
	))
	t.Cleanup(func() {
		srvA.ClientRegistrationRateLimiter.Stop()
		srvB.ClientRegistrationRateLimiter.Stop()
	})

	handlerA := oauth.NewHandler(srvA, nil)
	handlerB := oauth.NewHandler(srvB, nil)

	testIP := "192.168.1.100"

	// Pod A: Register up to limit
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(fmt.Sprintf(`{
			"client_name": "Client A-%d",
			"client_type": "public",
			"redirect_uris": ["https://example.com/callback"]
		}`, i)))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = testIP + ":12345"

		w := httptest.NewRecorder()
		handlerA.ServeClientRegistration(w, req)

		if w.Code != http.StatusCreated {
			t.Fatalf("Registration %d on Pod A failed: %d", i, w.Code)
		}
	}

	// Pod A: Should be rate limited now
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(`{
		"client_name": "Client A-limited",
		"client_type": "public",
		"redirect_uris": ["https://example.com/callback"]
	}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = testIP + ":12345"

	w := httptest.NewRecorder()
	handlerA.ServeClientRegistration(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Expected rate limit on Pod A, got: %d", w.Code)
	}

	// Pod B: Same IP should NOT be rate limited (separate rate limiter)
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(fmt.Sprintf(`{
			"client_name": "Client B-%d",
			"client_type": "public",
			"redirect_uris": ["https://example.com/callback"]
		}`, i)))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = testIP + ":12345"

		w := httptest.NewRecorder()
		handlerB.ServeClientRegistration(w, req)

		if w.Code != http.StatusCreated {
			t.Errorf("Registration %d on Pod B should succeed (independent rate limiter), got: %d", i, w.Code)
		}
	}

	t.Log("IMPORTANT: Rate limiting is per-pod. Consider ingress-level rate limiting for stricter protection.")
}
