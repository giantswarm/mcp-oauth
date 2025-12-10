package storage

import "golang.org/x/oauth2"

// KnownExtraFields lists the OIDC extra fields that must be preserved through encryption.
// These fields are stored in oauth2.Token's private 'raw' field and are critical for
// downstream OIDC authentication (e.g., id_token for Kubernetes API auth).
//
// Note: This list is intentionally limited to known OIDC fields. Unknown extra fields
// will not be preserved. If additional fields need to be preserved, add them here.
var KnownExtraFields = []string{
	"id_token", // OIDC ID token (critical for downstream auth)
	"scope",    // Granted scopes (may differ from requested)
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
