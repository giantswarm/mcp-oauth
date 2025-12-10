package valkey

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// TestSerializableTokenRoundTrip verifies that oauth2.Token can be serialized
// and deserialized through JSON without losing Extra fields (like id_token).
// This is critical because oauth2.Token stores Extra fields in a private 'raw'
// field that is not included in standard JSON marshaling.
func TestSerializableTokenRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		token *oauth2.Token
		extra map[string]interface{}
	}{
		{
			name: "token with id_token and scope",
			token: &oauth2.Token{
				AccessToken:  "access-token-123",
				TokenType:    "Bearer",
				RefreshToken: "refresh-token-456",
				Expiry:       time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC),
			},
			extra: map[string]interface{}{
				"id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.signature",
				"scope":    "openid profile email",
			},
		},
		{
			name: "token with id_token only",
			token: &oauth2.Token{
				AccessToken:  "access-token-789",
				TokenType:    "Bearer",
				RefreshToken: "",
				Expiry:       time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC),
			},
			extra: map[string]interface{}{
				"id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.claims.sig",
			},
		},
		{
			name: "token with expires_in",
			token: &oauth2.Token{
				AccessToken: "access-only",
				TokenType:   "Bearer",
			},
			extra: map[string]interface{}{
				"expires_in": float64(3600), // JSON numbers are float64
			},
		},
		{
			name: "token without extra fields",
			token: &oauth2.Token{
				AccessToken:  "simple-access-token",
				TokenType:    "Bearer",
				RefreshToken: "simple-refresh-token",
				Expiry:       time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			extra: nil,
		},
		{
			name: "token with empty string values",
			token: &oauth2.Token{
				AccessToken: "access-token",
				TokenType:   "",
				Expiry:      time.Time{}, // zero time
			},
			extra: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Apply Extra fields if provided
			original := tt.token
			if tt.extra != nil {
				original = original.WithExtra(tt.extra)
			}

			// Convert to serializableToken
			st := toSerializable(original)

			// Serialize to JSON
			data, err := json.Marshal(st)
			require.NoError(t, err, "failed to marshal serializableToken")

			// Deserialize from JSON
			var st2 serializableToken
			err = json.Unmarshal(data, &st2)
			require.NoError(t, err, "failed to unmarshal serializableToken")

			// Convert back to oauth2.Token
			reconstructed := st2.toOAuth2Token()

			// Verify core fields
			assert.Equal(t, original.AccessToken, reconstructed.AccessToken, "AccessToken mismatch")
			assert.Equal(t, original.TokenType, reconstructed.TokenType, "TokenType mismatch")
			assert.Equal(t, original.RefreshToken, reconstructed.RefreshToken, "RefreshToken mismatch")

			// Expiry needs special handling for zero time
			if original.Expiry.IsZero() {
				assert.True(t, reconstructed.Expiry.IsZero(), "Expiry should be zero")
			} else {
				assert.True(t, original.Expiry.Equal(reconstructed.Expiry), "Expiry mismatch")
			}

			// Verify Extra fields
			if tt.extra != nil {
				for key, expected := range tt.extra {
					actual := reconstructed.Extra(key)
					assert.Equal(t, expected, actual, "Extra field %q mismatch", key)
				}
			}
		})
	}
}

// TestToSerializableNilSafe verifies that toSerializable handles edge cases correctly.
func TestToSerializableNilSafe(t *testing.T) {
	// Token with no Extra fields should result in nil Extra in serializableToken
	token := &oauth2.Token{
		AccessToken: "test",
		TokenType:   "Bearer",
	}

	st := toSerializable(token)

	assert.Equal(t, "test", st.AccessToken)
	assert.Equal(t, "Bearer", st.TokenType)
	assert.Nil(t, st.Extra, "Extra should be nil when token has no extra fields")
}

// TestToOAuth2TokenNilExtra verifies that toOAuth2Token handles nil Extra correctly.
func TestToOAuth2TokenNilExtra(t *testing.T) {
	st := serializableToken{
		AccessToken:  "test-access",
		TokenType:    "Bearer",
		RefreshToken: "test-refresh",
		Extra:        nil,
	}

	token := st.toOAuth2Token()

	assert.Equal(t, "test-access", token.AccessToken)
	assert.Equal(t, "Bearer", token.TokenType)
	assert.Equal(t, "test-refresh", token.RefreshToken)

	// Extra() should return nil for non-existent keys
	assert.Nil(t, token.Extra("id_token"))
	assert.Nil(t, token.Extra("scope"))
}

// TestSerializableTokenJSONFormat verifies the JSON structure is as expected.
func TestSerializableTokenJSONFormat(t *testing.T) {
	token := (&oauth2.Token{
		AccessToken:  "access123",
		TokenType:    "Bearer",
		RefreshToken: "refresh456",
		Expiry:       time.Date(2025, 12, 10, 15, 30, 0, 0, time.UTC),
	}).WithExtra(map[string]interface{}{
		"id_token": "jwt.token.here",
		"scope":    "openid",
	})

	st := toSerializable(token)
	data, err := json.Marshal(st)
	require.NoError(t, err)

	// Verify JSON structure
	var parsed map[string]interface{}
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)

	assert.Equal(t, "access123", parsed["access_token"])
	assert.Equal(t, "Bearer", parsed["token_type"])
	assert.Equal(t, "refresh456", parsed["refresh_token"])
	assert.NotNil(t, parsed["expiry"])

	// Extra should be a nested object
	extra, ok := parsed["extra"].(map[string]interface{})
	require.True(t, ok, "extra should be a map")
	assert.Equal(t, "jwt.token.here", extra["id_token"])
	assert.Equal(t, "openid", extra["scope"])
}

// TestSerializableTokenOmitEmpty verifies that empty/zero fields are omitted from JSON.
func TestSerializableTokenOmitEmpty(t *testing.T) {
	st := serializableToken{
		AccessToken: "only-access",
		// All other fields are empty/zero
	}

	data, err := json.Marshal(st)
	require.NoError(t, err)

	var parsed map[string]interface{}
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)

	// Only access_token should be present
	assert.Equal(t, "only-access", parsed["access_token"])
	assert.NotContains(t, parsed, "token_type", "empty token_type should be omitted")
	assert.NotContains(t, parsed, "refresh_token", "empty refresh_token should be omitted")
	assert.NotContains(t, parsed, "extra", "nil extra should be omitted")
	// Note: expiry with zero time may or may not be omitted depending on JSON encoding
}
