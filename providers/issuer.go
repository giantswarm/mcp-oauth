package providers

// IssuerOf returns the upstream OIDC issuer URL for a provider that implements
// JWKSProvider, or "" otherwise.
//
// Not every Provider is an OIDC provider. GitHub's provider is OAuth 2.0 only —
// it has no OIDC issuer and no JWKS — so IssuerOf returns "" for it, which is
// the correct answer rather than a failure mode.
//
// Callers that require an issuer (for example, forwarded-ID-token validation)
// should check for a non-empty return value and reject the request with a clear
// error when it is empty.
func IssuerOf(p Provider) string {
	if j, ok := p.(JWKSProvider); ok {
		return j.IssuerURL()
	}
	return ""
}
