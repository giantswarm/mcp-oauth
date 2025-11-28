package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/internal/testutil"
	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/providers/google"
	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

// TestServer_StartAuthorizationFlow_EmptyScope tests that when a client doesn't provide
// any scopes, the server should default to the provider's configured scopes and store
// them in the authorization state.
func TestServer_StartAuthorizationFlow_EmptyScope(t *testing.T) {
	ctx := context.Background()

	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	// Create Google provider with default scopes
	providerScopes := []string{"openid", "email", "profile"}
	provider, err := google.NewProvider(&google.Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "http://localhost:8080/oauth/callback",
		Scopes:       providerScopes,
	})
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}

	config := &Config{
		Issuer:               "https://auth.example.com",
		SupportedScopes:      []string{"openid", "email", "profile", "https://www.googleapis.com/auth/gmail.readonly"},
		AuthorizationCodeTTL: 600,
		AccessTokenTTL:       3600,
		RequirePKCE:          true,
		AllowPKCEPlain:       false,
		ClockSkewGracePeriod: 5,
	}

	srv, err := New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Register a test client
	client, _, err := srv.RegisterClient(ctx,
		"Test Client",
		ClientTypePublic, // MCP clients are typically public
		TokenEndpointAuthMethodNone,
		[]string{"http://localhost:3000/callback"},
		[]string{"openid", "email", "profile"}, // Client allowed scopes
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	validVerifier := testutil.GenerateRandomString(testPKCEVerifierLength)
	hash := sha256.Sum256([]byte(validVerifier))
	validChallenge := base64.RawURLEncoding.EncodeToString(hash[:])
	clientState := testutil.GenerateRandomString(43)

	// Start authorization flow WITHOUT providing any scope parameter (empty string)
	authURL, err := srv.StartAuthorizationFlow(ctx,
		client.ClientID,
		"http://localhost:3000/callback",
		"", // NO SCOPE PROVIDED - this is the key test case
		"", // resource parameter (optional)
		validChallenge,
		PKCEMethodS256,
		clientState,
	)
	if err != nil {
		t.Fatalf("StartAuthorizationFlow() error = %v", err)
	}

	if authURL == "" {
		t.Fatal("StartAuthorizationFlow() returned empty authorization URL")
	}

	// Verify the authorization URL contains the provider's default scopes
	// The Google provider should use its configured scopes when none are provided
	expectedScopeInURL := "scope=openid+email+profile"
	if !strings.Contains(authURL, expectedScopeInURL) {
		t.Errorf("Authorization URL should contain provider's default scopes %q, got: %s",
			expectedScopeInURL, authURL)
	}

	// Verify authorization state was saved WITH the provider's default scopes
	authState, err := store.GetAuthorizationState(ctx, clientState)
	if err != nil {
		t.Fatalf("Failed to get authorization state: %v", err)
	}

	// THIS IS THE CRITICAL CHECK - the scope should be stored in the auth state
	// so that tokens issued later have the correct scopes
	if authState.Scope == "" {
		t.Error("Authorization state has empty scope - should contain provider's default scopes")
		t.Error("This causes tokens to be issued with no scopes, leading to 401 errors when accessing resources")
	}

	expectedScopes := []string{"openid", "email", "profile"}
	storedScopes := strings.Fields(authState.Scope)

	if len(storedScopes) == 0 {
		t.Fatal("Authorization state should store provider's default scopes when client doesn't provide any")
	}

	// Verify all expected scopes are present
	for _, expectedScope := range expectedScopes {
		found := false
		for _, storedScope := range storedScopes {
			if storedScope == expectedScope {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected scope %q not found in stored scopes %v", expectedScope, storedScopes)
		}
	}
}

// TestServer_StartAuthorizationFlow_WithExplicitScopes tests that when a client
// provides explicit scopes, those scopes are used instead of provider defaults.
func TestServer_StartAuthorizationFlow_WithExplicitScopes(t *testing.T) {
	ctx := context.Background()

	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	// Create Google provider with default scopes
	providerScopes := []string{"openid", "email", "profile"}
	provider, err := google.NewProvider(&google.Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "http://localhost:8080/oauth/callback",
		Scopes:       providerScopes,
	})
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}

	config := &Config{
		Issuer:               "https://auth.example.com",
		SupportedScopes:      []string{"openid", "email", "profile", "https://www.googleapis.com/auth/gmail.readonly"},
		AuthorizationCodeTTL: 600,
		AccessTokenTTL:       3600,
		RequirePKCE:          true,
		AllowPKCEPlain:       false,
		ClockSkewGracePeriod: 5,
	}

	srv, err := New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Register a test client
	client, _, err := srv.RegisterClient(ctx,
		"Test Client",
		ClientTypePublic,
		TokenEndpointAuthMethodNone,
		[]string{"http://localhost:3000/callback"},
		[]string{"openid", "email", "profile", "https://www.googleapis.com/auth/gmail.readonly"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	validVerifier := testutil.GenerateRandomString(testPKCEVerifierLength)
	hash := sha256.Sum256([]byte(validVerifier))
	validChallenge := base64.RawURLEncoding.EncodeToString(hash[:])
	clientState := testutil.GenerateRandomString(43)

	// Start authorization flow WITH explicit scopes
	requestedScope := "openid email https://www.googleapis.com/auth/gmail.readonly"
	authURL, err := srv.StartAuthorizationFlow(ctx,
		client.ClientID,
		"http://localhost:3000/callback",
		requestedScope, // EXPLICIT SCOPES PROVIDED
		"",
		validChallenge,
		PKCEMethodS256,
		clientState,
	)
	if err != nil {
		t.Fatalf("StartAuthorizationFlow() error = %v", err)
	}

	if authURL == "" {
		t.Fatal("StartAuthorizationFlow() returned empty authorization URL")
	}

	// Verify authorization state contains the requested scopes
	authState, err := store.GetAuthorizationState(ctx, clientState)
	if err != nil {
		t.Fatalf("Failed to get authorization state: %v", err)
	}

	if authState.Scope != requestedScope {
		t.Errorf("Authorization state scope = %q, want %q", authState.Scope, requestedScope)
	}

	// Verify the requested scopes are in the authorization URL (not provider defaults)
	if !strings.Contains(authURL, "gmail.readonly") {
		t.Error("Authorization URL should contain requested Gmail scope")
	}
}

// TestServer_StartAuthorizationFlow_ScopeIntersection tests that when a client
// has restricted scopes and no explicit scopes are provided, the server uses the
// intersection of provider defaults and client's allowed scopes.
func TestServer_StartAuthorizationFlow_ScopeIntersection(t *testing.T) {
	ctx := context.Background()

	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	// Create Google provider with default scopes
	providerScopes := []string{"openid", "email", "profile", "https://www.googleapis.com/auth/gmail.readonly"}
	provider, err := google.NewProvider(&google.Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "http://localhost:8080/oauth/callback",
		Scopes:       providerScopes,
	})
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}

	config := &Config{
		Issuer:               "https://auth.example.com",
		SupportedScopes:      []string{"openid", "email", "profile", "https://www.googleapis.com/auth/gmail.readonly"},
		AuthorizationCodeTTL: 600,
		AccessTokenTTL:       3600,
		RequirePKCE:          true,
		AllowPKCEPlain:       false,
		ClockSkewGracePeriod: 5,
	}

	srv, err := New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Register a test client with RESTRICTED scopes (only openid and email)
	client, _, err := srv.RegisterClient(ctx,
		"Restricted Client",
		ClientTypePublic,
		TokenEndpointAuthMethodNone,
		[]string{"http://localhost:3000/callback"},
		[]string{"openid", "email"}, // Client only allowed openid and email
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	validVerifier := testutil.GenerateRandomString(testPKCEVerifierLength)
	hash := sha256.Sum256([]byte(validVerifier))
	validChallenge := base64.RawURLEncoding.EncodeToString(hash[:])
	clientState := testutil.GenerateRandomString(43)

	// Start authorization flow WITHOUT providing scopes
	// Server should use intersection: provider wants [openid, email, profile, gmail.readonly]
	// but client only allowed [openid, email] -> result should be [openid, email]
	authURL, err := srv.StartAuthorizationFlow(ctx,
		client.ClientID,
		"http://localhost:3000/callback",
		"", // NO SCOPE PROVIDED
		"",
		validChallenge,
		PKCEMethodS256,
		clientState,
	)
	if err != nil {
		t.Fatalf("StartAuthorizationFlow() error = %v", err)
	}

	if authURL == "" {
		t.Fatal("StartAuthorizationFlow() returned empty authorization URL")
	}

	// Verify authorization state contains only the intersection
	authState, err := store.GetAuthorizationState(ctx, clientState)
	if err != nil {
		t.Fatalf("Failed to get authorization state: %v", err)
	}

	storedScopes := strings.Fields(authState.Scope)
	expectedScopes := []string{"openid", "email"}

	if len(storedScopes) != len(expectedScopes) {
		t.Errorf("Expected %d scopes, got %d: %v", len(expectedScopes), len(storedScopes), storedScopes)
	}

	// Verify only expected scopes are present
	for _, expectedScope := range expectedScopes {
		found := false
		for _, storedScope := range storedScopes {
			if storedScope == expectedScope {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected scope %q not found in stored scopes %v", expectedScope, storedScopes)
		}
	}

	// Verify disallowed scopes are NOT present
	disallowedScopes := []string{"profile", "https://www.googleapis.com/auth/gmail.readonly"}
	for _, disallowedScope := range disallowedScopes {
		for _, storedScope := range storedScopes {
			if storedScope == disallowedScope {
				t.Errorf("Disallowed scope %q should not be in stored scopes %v", disallowedScope, storedScopes)
			}
		}
	}
}

// TestIntersectScopes tests the intersectScopes helper function
func TestIntersectScopes(t *testing.T) {
	tests := []struct {
		name     string
		a        []string
		b        []string
		expected []string
	}{
		{
			name:     "full intersection",
			a:        []string{"openid", "email", "profile"},
			b:        []string{"openid", "email", "profile"},
			expected: []string{"openid", "email", "profile"},
		},
		{
			name:     "partial intersection",
			a:        []string{"openid", "email", "profile"},
			b:        []string{"openid", "email"},
			expected: []string{"openid", "email"},
		},
		{
			name:     "no intersection",
			a:        []string{"openid", "email"},
			b:        []string{"profile", "phone"},
			expected: nil,
		},
		{
			name:     "empty first slice",
			a:        []string{},
			b:        []string{"openid", "email"},
			expected: nil,
		},
		{
			name:     "empty second slice",
			a:        []string{"openid", "email"},
			b:        []string{},
			expected: nil,
		},
		{
			name:     "both empty",
			a:        []string{},
			b:        []string{},
			expected: nil,
		},
		{
			name:     "preserves order from first slice",
			a:        []string{"profile", "email", "openid"},
			b:        []string{"openid", "email", "profile"},
			expected: []string{"profile", "email", "openid"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := intersectScopes(tt.a, tt.b)
			if len(result) != len(tt.expected) {
				t.Errorf("intersectScopes() = %v, want %v", result, tt.expected)
				return
			}
			for i, v := range result {
				if v != tt.expected[i] {
					t.Errorf("intersectScopes()[%d] = %v, want %v", i, v, tt.expected[i])
				}
			}
		})
	}
}

// TestResolveScopes tests the resolveScopes helper function
func TestResolveScopes(t *testing.T) {
	// Create a mock provider
	provider := &mockProviderForTest{
		defaultScopes: []string{"openid", "email", "profile"},
	}

	srv := &Server{
		provider: provider,
	}

	tests := []struct {
		name           string
		requestedScope string
		clientScopes   []string
		expected       string
	}{
		{
			name:           "requested scope provided",
			requestedScope: "openid email",
			clientScopes:   []string{"openid", "email", "profile"},
			expected:       "openid email",
		},
		{
			name:           "no scope, no client restrictions",
			requestedScope: "",
			clientScopes:   []string{},
			expected:       "openid email profile",
		},
		{
			name:           "no scope, client has restrictions - full intersection",
			requestedScope: "",
			clientScopes:   []string{"openid", "email", "profile"},
			expected:       "openid email profile",
		},
		{
			name:           "no scope, client has restrictions - partial intersection",
			requestedScope: "",
			clientScopes:   []string{"openid", "email"},
			expected:       "openid email",
		},
		{
			name:           "no scope, client has restrictions - no intersection",
			requestedScope: "",
			clientScopes:   []string{"phone", "address"},
			expected:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &storage.Client{
				Scopes: tt.clientScopes,
			}
			result := srv.resolveScopes(tt.requestedScope, client)
			if result != tt.expected {
				t.Errorf("resolveScopes() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// mockProviderForTest is a minimal mock provider for testing resolveScopes
type mockProviderForTest struct {
	defaultScopes []string
}

func (m *mockProviderForTest) Name() string {
	return "mock"
}

func (m *mockProviderForTest) DefaultScopes() []string {
	return m.defaultScopes
}

func (m *mockProviderForTest) AuthorizationURL(state, codeChallenge, codeChallengeMethod string, scopes []string) string {
	return ""
}

func (m *mockProviderForTest) ExchangeCode(ctx context.Context, code, codeVerifier string) (*oauth2.Token, error) {
	return nil, nil
}

func (m *mockProviderForTest) ValidateToken(ctx context.Context, accessToken string) (*providers.UserInfo, error) {
	return nil, nil
}

func (m *mockProviderForTest) RefreshToken(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	return nil, nil
}

func (m *mockProviderForTest) RevokeToken(ctx context.Context, token string) error {
	return nil
}

func (m *mockProviderForTest) HealthCheck(ctx context.Context) error {
	return nil
}
