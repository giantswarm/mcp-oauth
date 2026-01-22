package providers

import (
	"testing"
)

// TestUserInfo_IsSSO tests the IsSSO helper method.
func TestUserInfo_IsSSO(t *testing.T) {
	tests := []struct {
		name        string
		tokenSource TokenSource
		expected    bool
	}{
		{
			name:        "SSO token source returns true",
			tokenSource: TokenSourceSSO,
			expected:    true,
		},
		{
			name:        "OAuth token source returns false",
			tokenSource: TokenSourceOAuth,
			expected:    false,
		},
		{
			name:        "empty token source returns false",
			tokenSource: "",
			expected:    false,
		},
		{
			name:        "unknown token source returns false",
			tokenSource: "unknown",
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &UserInfo{
				ID:          "test-user",
				TokenSource: tt.tokenSource,
			}

			got := u.IsSSO()
			if got != tt.expected {
				t.Errorf("IsSSO() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestUserInfo_IsOAuth tests the IsOAuth helper method.
func TestUserInfo_IsOAuth(t *testing.T) {
	tests := []struct {
		name        string
		tokenSource TokenSource
		expected    bool
	}{
		{
			name:        "OAuth token source returns true",
			tokenSource: TokenSourceOAuth,
			expected:    true,
		},
		{
			name:        "empty token source returns true (backward compatibility)",
			tokenSource: "",
			expected:    true,
		},
		{
			name:        "SSO token source returns false",
			tokenSource: TokenSourceSSO,
			expected:    false,
		},
		{
			name:        "unknown token source returns false",
			tokenSource: "unknown",
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &UserInfo{
				ID:          "test-user",
				TokenSource: tt.tokenSource,
			}

			got := u.IsOAuth()
			if got != tt.expected {
				t.Errorf("IsOAuth() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestTokenSource_Constants verifies the token source constants.
func TestTokenSource_Constants(t *testing.T) {
	// Verify constant values are as expected
	if TokenSourceOAuth != "oauth" {
		t.Errorf("TokenSourceOAuth = %q, want %q", TokenSourceOAuth, "oauth")
	}
	if TokenSourceSSO != "sso" {
		t.Errorf("TokenSourceSSO = %q, want %q", TokenSourceSSO, "sso")
	}
}

// TestUserInfo_TokenSourceMutuallyExclusive verifies that IsSSO and IsOAuth are mutually exclusive.
func TestUserInfo_TokenSourceMutuallyExclusive(t *testing.T) {
	// SSO source: IsSSO=true, IsOAuth=false
	ssoUser := &UserInfo{TokenSource: TokenSourceSSO}
	if !ssoUser.IsSSO() || ssoUser.IsOAuth() {
		t.Error("SSO user should have IsSSO=true and IsOAuth=false")
	}

	// OAuth source: IsSSO=false, IsOAuth=true
	oauthUser := &UserInfo{TokenSource: TokenSourceOAuth}
	if oauthUser.IsSSO() || !oauthUser.IsOAuth() {
		t.Error("OAuth user should have IsSSO=false and IsOAuth=true")
	}

	// Empty source (backward compat): treated as OAuth
	emptyUser := &UserInfo{TokenSource: ""}
	if emptyUser.IsSSO() || !emptyUser.IsOAuth() {
		t.Error("Empty token source should be treated as OAuth for backward compatibility")
	}
}

// TestUserInfo_NilReceiver verifies that nil UserInfo is handled safely.
func TestUserInfo_NilReceiver(t *testing.T) {
	var nilUser *UserInfo

	t.Run("IsSSO returns false for nil receiver", func(t *testing.T) {
		if nilUser.IsSSO() {
			t.Error("IsSSO() should return false for nil receiver")
		}
	})

	t.Run("IsOAuth returns true for nil receiver (safe default)", func(t *testing.T) {
		if !nilUser.IsOAuth() {
			t.Error("IsOAuth() should return true for nil receiver as safe default")
		}
	})
}

// TestApplyAuthorizationURLOptions tests the ApplyAuthorizationURLOptions helper.
func TestApplyAuthorizationURLOptions(t *testing.T) {
	t.Run("nil options returns nil", func(t *testing.T) {
		result := ApplyAuthorizationURLOptions(nil)
		if result != nil {
			t.Errorf("ApplyAuthorizationURLOptions(nil) = %v, want nil", result)
		}
	})

	t.Run("empty options returns empty slice", func(t *testing.T) {
		result := ApplyAuthorizationURLOptions(&AuthorizationURLOptions{})
		if len(result) != 0 {
			t.Errorf("ApplyAuthorizationURLOptions(&AuthorizationURLOptions{}) returned %d options, want 0", len(result))
		}
	})

	t.Run("prompt option", func(t *testing.T) {
		opts := &AuthorizationURLOptions{Prompt: "none"}
		result := ApplyAuthorizationURLOptions(opts)
		if len(result) != 1 {
			t.Errorf("expected 1 option, got %d", len(result))
		}
	})

	t.Run("login_hint option", func(t *testing.T) {
		opts := &AuthorizationURLOptions{LoginHint: "user@example.com"}
		result := ApplyAuthorizationURLOptions(opts)
		if len(result) != 1 {
			t.Errorf("expected 1 option, got %d", len(result))
		}
	})

	t.Run("max_age option", func(t *testing.T) {
		maxAge := 3600
		opts := &AuthorizationURLOptions{MaxAge: &maxAge}
		result := ApplyAuthorizationURLOptions(opts)
		if len(result) != 1 {
			t.Errorf("expected 1 option, got %d", len(result))
		}
	})

	t.Run("acr_values option", func(t *testing.T) {
		opts := &AuthorizationURLOptions{ACRValues: "urn:mace:incommon:iap:silver"}
		result := ApplyAuthorizationURLOptions(opts)
		if len(result) != 1 {
			t.Errorf("expected 1 option, got %d", len(result))
		}
	})

	t.Run("id_token_hint option", func(t *testing.T) {
		opts := &AuthorizationURLOptions{IDTokenHint: "eyJhbGciOiJSUzI1NiJ9..."}
		result := ApplyAuthorizationURLOptions(opts)
		if len(result) != 1 {
			t.Errorf("expected 1 option, got %d", len(result))
		}
	})

	t.Run("extra parameters", func(t *testing.T) {
		opts := &AuthorizationURLOptions{
			Extra: map[string]string{
				"hd":         "example.com",
				"nonce":      "abc123",
				"ui_locales": "en",
			},
		}
		result := ApplyAuthorizationURLOptions(opts)
		if len(result) != 3 {
			t.Errorf("expected 3 options for 3 extra params, got %d", len(result))
		}
	})

	t.Run("all options combined", func(t *testing.T) {
		maxAge := 0
		opts := &AuthorizationURLOptions{
			Prompt:      "none",
			LoginHint:   "user@example.com",
			MaxAge:      &maxAge,
			ACRValues:   "urn:mace:incommon:iap:silver",
			IDTokenHint: "previous-token",
			Extra: map[string]string{
				"hd": "example.com",
			},
		}
		result := ApplyAuthorizationURLOptions(opts)
		// 5 standard options + 1 extra = 6
		if len(result) != 6 {
			t.Errorf("expected 6 options, got %d", len(result))
		}
	})
}

// Test scope values (avoid goconst warnings)
const (
	testScopeOpenID  = "openid"
	testScopeEmail   = "email"
	testScopeProfile = "profile"
)

// TestCopyScopes tests the CopyScopes helper.
func TestCopyScopes(t *testing.T) {
	t.Run("uses requested scopes when provided", func(t *testing.T) {
		requested := []string{testScopeOpenID, testScopeEmail}
		defaults := []string{testScopeOpenID, testScopeProfile, testScopeEmail}

		result := CopyScopes(requested, defaults)

		if len(result) != 2 {
			t.Errorf("expected 2 scopes, got %d", len(result))
		}
		if result[0] != testScopeOpenID || result[1] != testScopeEmail {
			t.Errorf("unexpected scopes: %v", result)
		}
	})

	t.Run("uses default scopes when requested is empty", func(t *testing.T) {
		var requested []string
		defaults := []string{testScopeOpenID, testScopeProfile, testScopeEmail}

		result := CopyScopes(requested, defaults)

		if len(result) != 3 {
			t.Errorf("expected 3 scopes, got %d", len(result))
		}
	})

	t.Run("uses default scopes when requested is nil", func(t *testing.T) {
		defaults := []string{testScopeOpenID, testScopeProfile}

		result := CopyScopes(nil, defaults)

		if len(result) != 2 {
			t.Errorf("expected 2 scopes, got %d", len(result))
		}
	})

	t.Run("returns empty when both are empty", func(t *testing.T) {
		result := CopyScopes(nil, nil)

		if len(result) != 0 {
			t.Errorf("expected 0 scopes, got %d", len(result))
		}
	})

	t.Run("creates deep copy - modifying input doesn't affect result", func(t *testing.T) {
		requested := []string{testScopeOpenID, testScopeEmail}
		defaults := []string{testScopeOpenID, testScopeProfile}

		result := CopyScopes(requested, defaults)

		// Modify input
		requested[0] = "MODIFIED"

		// Result should be unaffected
		if result[0] != testScopeOpenID {
			t.Errorf("result was modified when input changed: %v", result)
		}
	})

	t.Run("creates deep copy - modifying result doesn't affect input", func(t *testing.T) {
		requested := []string{testScopeOpenID, testScopeEmail}
		defaults := []string{testScopeOpenID, testScopeProfile}

		result := CopyScopes(requested, defaults)

		// Modify result
		result[0] = "MODIFIED"

		// Input should be unaffected
		if requested[0] != testScopeOpenID {
			t.Errorf("input was modified when result changed: %v", requested)
		}
	})
}

// TestAuthorizationURLOptions_Struct tests the AuthorizationURLOptions struct.
func TestAuthorizationURLOptions_Struct(t *testing.T) {
	t.Run("zero value is usable", func(t *testing.T) {
		opts := AuthorizationURLOptions{}
		if opts.Prompt != "" {
			t.Error("zero value Prompt should be empty")
		}
		if opts.LoginHint != "" {
			t.Error("zero value LoginHint should be empty")
		}
		if opts.MaxAge != nil {
			t.Error("zero value MaxAge should be nil")
		}
		if opts.ACRValues != "" {
			t.Error("zero value ACRValues should be empty")
		}
		if opts.IDTokenHint != "" {
			t.Error("zero value IDTokenHint should be empty")
		}
		if opts.Extra != nil {
			t.Error("zero value Extra should be nil")
		}
	})

	t.Run("all fields can be set", func(t *testing.T) {
		maxAge := 3600
		opts := AuthorizationURLOptions{
			Prompt:      "none",
			LoginHint:   "user@example.com",
			MaxAge:      &maxAge,
			ACRValues:   "urn:mace:incommon:iap:silver",
			IDTokenHint: "eyJhbGciOiJSUzI1NiJ9...",
			Extra: map[string]string{
				"hd": "example.com",
			},
		}

		if opts.Prompt != "none" {
			t.Errorf("Prompt = %q, want %q", opts.Prompt, "none")
		}
		if opts.LoginHint != "user@example.com" {
			t.Errorf("LoginHint = %q, want %q", opts.LoginHint, "user@example.com")
		}
		if *opts.MaxAge != 3600 {
			t.Errorf("MaxAge = %d, want %d", *opts.MaxAge, 3600)
		}
		if opts.ACRValues != "urn:mace:incommon:iap:silver" {
			t.Errorf("ACRValues = %q, want %q", opts.ACRValues, "urn:mace:incommon:iap:silver")
		}
		if opts.Extra["hd"] != "example.com" {
			t.Errorf("Extra[hd] = %q, want %q", opts.Extra["hd"], "example.com")
		}
	})
}
