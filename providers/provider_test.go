package providers

import "testing"

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
