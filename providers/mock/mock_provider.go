// Package mock provides mock implementations of the Provider interface for testing.
package mock

import (
	"context"
	"fmt"

	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/providers"
)

// MockProvider is a mock implementation of the Provider interface for testing
type MockProvider struct {
	// NameFunc is called when Name() is invoked
	NameFunc func() string

	// AuthorizationURLFunc is called when AuthorizationURL() is invoked
	AuthorizationURLFunc func(state string, codeChallenge string, codeChallengeMethod string) string

	// ExchangeCodeFunc is called when ExchangeCode() is invoked
	ExchangeCodeFunc func(ctx context.Context, code string, codeVerifier string) (*oauth2.Token, error)

	// ValidateTokenFunc is called when ValidateToken() is invoked
	ValidateTokenFunc func(ctx context.Context, accessToken string) (*providers.UserInfo, error)

	// RefreshTokenFunc is called when RefreshToken() is invoked
	RefreshTokenFunc func(ctx context.Context, refreshToken string) (*oauth2.Token, error)

	// RevokeTokenFunc is called when RevokeToken() is invoked
	RevokeTokenFunc func(ctx context.Context, token string) error

	// CallCounts tracks how many times each method was called
	CallCounts map[string]int
}

// NewMockProvider creates a new mock provider with default implementations
func NewMockProvider() *MockProvider {
	return &MockProvider{
		CallCounts: make(map[string]int),
		NameFunc: func() string {
			return "mock"
		},
		AuthorizationURLFunc: func(state string, codeChallenge string, codeChallengeMethod string) string {
			return fmt.Sprintf("https://mock.example.com/authorize?state=%s&code_challenge=%s&code_challenge_method=%s", state, codeChallenge, codeChallengeMethod)
		},
		ExchangeCodeFunc: func(ctx context.Context, code string, codeVerifier string) (*oauth2.Token, error) {
			return &oauth2.Token{
				AccessToken:  "mock-access-token",
				TokenType:    "Bearer",
				RefreshToken: "mock-refresh-token",
			}, nil
		},
		ValidateTokenFunc: func(ctx context.Context, accessToken string) (*providers.UserInfo, error) {
			return &providers.UserInfo{
				ID:            "mock-user-123",
				Email:         "mock@example.com",
				EmailVerified: true,
				Name:          "Mock User",
				GivenName:     "Mock",
				FamilyName:    "User",
			}, nil
		},
		RefreshTokenFunc: func(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
			return &oauth2.Token{
				AccessToken:  "new-mock-access-token",
				TokenType:    "Bearer",
				RefreshToken: "new-mock-refresh-token",
			}, nil
		},
		RevokeTokenFunc: func(ctx context.Context, token string) error {
			return nil
		},
	}
}

// Name returns the provider name
func (m *MockProvider) Name() string {
	m.CallCounts["Name"]++
	return m.NameFunc()
}

// AuthorizationURL generates the URL to redirect users for authentication
func (m *MockProvider) AuthorizationURL(state string, codeChallenge string, codeChallengeMethod string) string {
	m.CallCounts["AuthorizationURL"]++
	return m.AuthorizationURLFunc(state, codeChallenge, codeChallengeMethod)
}

// ExchangeCode exchanges an authorization code for tokens
func (m *MockProvider) ExchangeCode(ctx context.Context, code string, codeVerifier string) (*oauth2.Token, error) {
	m.CallCounts["ExchangeCode"]++
	return m.ExchangeCodeFunc(ctx, code, codeVerifier)
}

// ValidateToken validates an access token and returns user information
func (m *MockProvider) ValidateToken(ctx context.Context, accessToken string) (*providers.UserInfo, error) {
	m.CallCounts["ValidateToken"]++
	return m.ValidateTokenFunc(ctx, accessToken)
}

// RefreshToken refreshes an expired token using a refresh token
func (m *MockProvider) RefreshToken(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	m.CallCounts["RefreshToken"]++
	return m.RefreshTokenFunc(ctx, refreshToken)
}

// RevokeToken revokes a token at the provider
func (m *MockProvider) RevokeToken(ctx context.Context, token string) error {
	m.CallCounts["RevokeToken"]++
	return m.RevokeTokenFunc(ctx, token)
}

// ResetCallCounts resets all call counters
func (m *MockProvider) ResetCallCounts() {
	m.CallCounts = make(map[string]int)
}

// GetCallCount returns the number of times a method was called
func (m *MockProvider) GetCallCount(method string) int {
	return m.CallCounts[method]
}
