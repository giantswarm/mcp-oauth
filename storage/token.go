package storage

import (
	"fmt"

	"github.com/giantswarm/mcp-oauth/security"
	"golang.org/x/oauth2"
)

// KnownExtraFields lists the OIDC extra fields that must be preserved through encryption.
// These fields are stored in oauth2.Token's private 'raw' field and are critical for
// downstream OIDC authentication (e.g., id_token for Kubernetes API auth).
//
// SECURITY: This allowlist approach ensures unknown extra fields are dropped, preventing
// potential injection of malicious data. Only explicitly listed fields are preserved.
//
// Note: If additional fields need to be preserved, add them here.
var KnownExtraFields = []string{
	"id_token",   // OIDC ID token (critical for downstream auth) - ENCRYPTED
	"scope",      // Granted scopes (may differ from requested)
	"expires_in", // Token lifetime in seconds (redundant with Expiry but some providers include it)
}

// SensitiveExtraFields lists extra fields that contain sensitive data and should be
// encrypted at rest. These fields contain PII or authentication credentials.
//
// SECURITY: The id_token is a signed JWT containing user identity claims (email, name,
// subject). While it cannot be used for impersonation (it's signed by the IdP and
// typically short-lived), it contains PII that should be protected at rest.
var SensitiveExtraFields = []string{
	"id_token", // Contains user identity claims (email, name, sub)
}

// ExtractTokenExtra extracts known extra fields from an oauth2.Token.
// The oauth2.Token.Extra() method is the only way to access the private raw field.
// We extract known OIDC fields that need to be preserved through encryption.
//
// Returns nil if the token is nil or has no known extra fields.
func ExtractTokenExtra(token *oauth2.Token) map[string]interface{} {
	if token == nil {
		return nil
	}

	extra := make(map[string]interface{}, len(KnownExtraFields))

	for _, field := range KnownExtraFields {
		if v := token.Extra(field); v != nil {
			extra[field] = v
		}
	}

	if len(extra) == 0 {
		return nil
	}
	return extra
}

// EncryptExtraFields encrypts sensitive fields in the extra map.
// Returns a new map with encrypted values for sensitive fields.
// Non-sensitive fields are copied as-is.
// If encryptor is nil or disabled, returns the original map unchanged.
func EncryptExtraFields(extra map[string]interface{}, encryptor *security.Encryptor) (map[string]interface{}, error) {
	if extra == nil {
		return nil, nil
	}
	if encryptor == nil || !encryptor.IsEnabled() {
		return extra, nil
	}

	// Build set of sensitive fields for O(1) lookup
	sensitiveSet := make(map[string]bool, len(SensitiveExtraFields))
	for _, field := range SensitiveExtraFields {
		sensitiveSet[field] = true
	}

	result := make(map[string]interface{}, len(extra))
	for key, value := range extra {
		if sensitiveSet[key] {
			// Encrypt sensitive string fields
			if strVal, ok := value.(string); ok && strVal != "" {
				encrypted, err := encryptor.Encrypt(strVal)
				if err != nil {
					return nil, fmt.Errorf("failed to encrypt extra field %s: %w", key, err)
				}
				result[key] = encrypted
			} else {
				// Non-string or empty values are copied as-is
				result[key] = value
			}
		} else {
			// Non-sensitive fields are copied as-is
			result[key] = value
		}
	}

	return result, nil
}

// DecryptExtraFields decrypts sensitive fields in the extra map.
// Returns a new map with decrypted values for sensitive fields.
// Non-sensitive fields are copied as-is.
// If encryptor is nil or disabled, returns the original map unchanged.
func DecryptExtraFields(extra map[string]interface{}, encryptor *security.Encryptor) (map[string]interface{}, error) {
	if extra == nil {
		return nil, nil
	}
	if encryptor == nil || !encryptor.IsEnabled() {
		return extra, nil
	}

	// Build set of sensitive fields for O(1) lookup
	sensitiveSet := make(map[string]bool, len(SensitiveExtraFields))
	for _, field := range SensitiveExtraFields {
		sensitiveSet[field] = true
	}

	result := make(map[string]interface{}, len(extra))
	for key, value := range extra {
		if sensitiveSet[key] {
			// Decrypt sensitive string fields
			if strVal, ok := value.(string); ok && strVal != "" {
				decrypted, err := encryptor.Decrypt(strVal)
				if err != nil {
					return nil, fmt.Errorf("failed to decrypt extra field %s: %w", key, err)
				}
				result[key] = decrypted
			} else {
				// Non-string or empty values are copied as-is
				result[key] = value
			}
		} else {
			// Non-sensitive fields are copied as-is
			result[key] = value
		}
	}

	return result, nil
}
