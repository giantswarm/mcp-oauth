package storage

import (
	"fmt"

	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/security"
)

// KnownExtraFields lists the OIDC extra fields that must be preserved through encryption.
// These fields are stored in oauth2.Token's private 'raw' field and are critical for
// downstream OIDC authentication (e.g., id_token for Kubernetes API auth).
//
// SECURITY: This allowlist approach ensures unknown extra fields are dropped, preventing
// potential injection of malicious data. Only explicitly listed fields are preserved.
//
// EXTENSIBILITY: Some OAuth/OIDC providers may include additional fields in token responses.
// If your provider returns custom extra fields that need to be preserved:
//  1. Add the field name to this list
//  2. If the field contains sensitive data (PII, secrets), also add it to SensitiveExtraFields
//  3. Test that the field survives the encrypt/decrypt roundtrip
//
// Common fields from various providers that may need to be added:
//   - "token_type": Usually "Bearer", already in oauth2.Token.TokenType
//   - "refresh_expires_in": Keycloak-specific refresh token lifetime
//   - "session_state": Keycloak session identifier
//   - "not-before-policy": Keycloak token validity timestamp
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
//
// When adding new fields to KnownExtraFields, evaluate whether they contain:
//   - PII (email, name, address, phone)
//   - Authentication credentials or secrets
//   - Session identifiers that could enable session hijacking
//
// If yes, add the field here to ensure it's encrypted at rest.
var SensitiveExtraFields = []string{
	"id_token", // Contains user identity claims (email, name, sub)
}

// sensitiveExtraFieldSet is pre-computed for O(1) lookup during encrypt/decrypt operations.
// This avoids rebuilding the set on every call to EncryptExtraFields/DecryptExtraFields.
var sensitiveExtraFieldSet = func() map[string]bool {
	set := make(map[string]bool, len(SensitiveExtraFields))
	for _, field := range SensitiveExtraFields {
		set[field] = true
	}
	return set
}()

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
	return transformExtraFields(extra, encryptor, encryptValue)
}

// DecryptExtraFields decrypts sensitive fields in the extra map.
// Returns a new map with decrypted values for sensitive fields.
// Non-sensitive fields are copied as-is.
// If encryptor is nil or disabled, returns the original map unchanged.
func DecryptExtraFields(extra map[string]interface{}, encryptor *security.Encryptor) (map[string]interface{}, error) {
	return transformExtraFields(extra, encryptor, decryptValue)
}

// transformFunc defines the signature for encrypt/decrypt operations.
type transformFunc func(encryptor *security.Encryptor, value string) (string, error)

// transformExtraFields applies a transformation to sensitive fields in the extra map.
func transformExtraFields(extra map[string]interface{}, encryptor *security.Encryptor, transform transformFunc) (map[string]interface{}, error) {
	if extra == nil {
		return nil, nil
	}
	if encryptor == nil || !encryptor.IsEnabled() {
		return extra, nil
	}

	result := make(map[string]interface{}, len(extra))
	for key, value := range extra {
		transformedValue, err := transformField(key, value, encryptor, transform)
		if err != nil {
			return nil, err
		}
		result[key] = transformedValue
	}

	return result, nil
}

// transformField transforms a single field if it's sensitive.
func transformField(key string, value interface{}, encryptor *security.Encryptor, transform transformFunc) (interface{}, error) {
	if !sensitiveExtraFieldSet[key] {
		return value, nil
	}

	strVal, ok := value.(string)
	if !ok || strVal == "" {
		return value, nil
	}

	transformed, err := transform(encryptor, strVal)
	if err != nil {
		return nil, fmt.Errorf("failed to transform extra field %s: %w", key, err)
	}
	return transformed, nil
}

// encryptValue encrypts a string value.
func encryptValue(encryptor *security.Encryptor, value string) (string, error) {
	return encryptor.Encrypt(value)
}

// decryptValue decrypts a string value.
func decryptValue(encryptor *security.Encryptor, value string) (string, error) {
	return encryptor.Decrypt(value)
}
