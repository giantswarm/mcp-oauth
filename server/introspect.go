package server

import (
	"context"

	"github.com/giantswarm/mcp-oauth/internal/helpers"
	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/storage"
)

// IntrospectToken returns the RFC 7662 token-introspection payload for the
// given bearer when the requesting client is authorized to learn it.
//
// Authorization (RFC 7662 §2.1): the requester must either be the client the
// token was issued to, or appear in Config.IntrospectionResourceServers.
// Cross-client probes return {"active": false} with no other fields populated
// so the endpoint cannot be used as an oracle for token / user enumeration.
//
// The response shape follows RFC 7662 §2.2: active, scope, client_id, sub,
// token_type, exp, iat, aud, iss. Email-related extras (email, email_verified,
// name) are included only on the authorized path so they do not leak through
// the gate.
func (s *Server) IntrospectToken(ctx context.Context, accessToken, requestingClient string) map[string]any {
	inactive := map[string]any{"active": false}

	if s.Config.IsJWTAccessTokenFormat() && s.looksLikeSelfIssuedJWT(accessToken) {
		return s.introspectSelfIssuedJWT(ctx, accessToken, requestingClient, inactive)
	}
	return s.introspectOpaqueToken(ctx, accessToken, requestingClient, inactive)
}

// introspectSelfIssuedJWT validates a self-issued JWT and projects its claims
// directly into the response. The metadata round-trip is skipped: the JWT
// carries iss/exp/iat/aud/scope/sub/client_id already and they have just been
// re-verified against the configured signing key.
func (s *Server) introspectSelfIssuedJWT(ctx context.Context, accessToken, requestingClient string, inactive map[string]any) map[string]any {
	userInfo, err := s.validateSelfIssuedJWT(ctx, accessToken)
	if err != nil || userInfo == nil {
		return inactive
	}

	_, claims, err := s.parseAndVerifyJWTSignature(accessToken)
	if err != nil {
		return inactive
	}

	tokenBoundClient, _ := claims["client_id"].(string)
	if !s.introspectionRequesterAllowed(requestingClient, tokenBoundClient) {
		return inactive
	}

	return introspectionResponseFromJWTClaims(claims, tokenBoundClient)
}

// introspectionResponseFromJWTClaims projects the JWT claim map into an
// RFC 7662 §2.2 response. Pulled out of introspectSelfIssuedJWT so the
// per-claim copying does not push the parent over the cyclomatic-complexity
// budget; the projection is mechanical and has no security state.
func introspectionResponseFromJWTClaims(claims map[string]any, tokenBoundClient string) map[string]any {
	response := map[string]any{
		"active":     true,
		"token_type": "Bearer",
	}
	if tokenBoundClient != "" {
		response["client_id"] = tokenBoundClient
	}
	copyClaimString(response, claims, "sub")
	copyClaimString(response, claims, "iss")
	copyClaimString(response, claims, "scope")
	copyClaimString(response, claims, "email")
	copyClaimUnixTime(response, claims, "exp")
	copyClaimUnixTime(response, claims, "iat")
	copyClaimUnixTime(response, claims, "nbf")
	if aud := audiencesFromClaim(claims["aud"]); len(aud) == 1 {
		response["aud"] = aud[0]
	} else if len(aud) > 1 {
		response["aud"] = aud
	}
	return response
}

func copyClaimString(dst, claims map[string]any, key string) {
	if v, ok := claims[key].(string); ok && v != "" {
		dst[key] = v
	}
}

func copyClaimUnixTime(dst, claims map[string]any, key string) {
	if v, ok := claims[key].(float64); ok {
		dst[key] = int64(v)
	}
}

// introspectOpaqueToken resolves an opaque token by consulting the
// TokenMetadata store for ownership / scope / audience / iat and the
// TokenStore for expiry (the upstream-bound provider token shares its
// expiry with the AS-issued bearer per capTokenExpiry). The cross-client
// gate runs before the provider userinfo round-trip so a denied probe
// reveals nothing — neither active state nor user attributes.
func (s *Server) introspectOpaqueToken(ctx context.Context, accessToken, requestingClient string, inactive map[string]any) map[string]any {
	metaGetter, ok := s.tokenStore.(storage.TokenMetadataGetter)
	if !ok {
		return inactive
	}
	tokenMetadata, err := metaGetter.GetTokenMetadata(accessToken)
	if err != nil || tokenMetadata == nil {
		return inactive
	}

	if !s.introspectionRequesterAllowed(requestingClient, tokenMetadata.ClientID) {
		return inactive
	}

	userInfo, err := s.ValidateToken(ctx, accessToken)
	if err != nil || userInfo == nil {
		return inactive
	}

	return s.introspectionResponseFromOpaqueToken(ctx, accessToken, tokenMetadata, userInfo)
}

func (s *Server) introspectionResponseFromOpaqueToken(ctx context.Context, accessToken string, tokenMetadata *storage.TokenMetadata, userInfo *providers.UserInfo) map[string]any {
	response := map[string]any{
		"active":     true,
		"token_type": "Bearer",
		"client_id":  tokenMetadata.ClientID,
		"sub":        userInfo.ID,
		"iss":        s.Config.Issuer,
	}
	if userInfo.Email != "" {
		response["email"] = userInfo.Email
		response["email_verified"] = userInfo.EmailVerified
	}
	if userInfo.Name != "" {
		response["name"] = userInfo.Name
	}
	if scope := helpers.JoinScopes(tokenMetadata.Scopes); scope != "" {
		response["scope"] = scope
	}
	if tokenMetadata.Audience != "" {
		response["aud"] = tokenMetadata.Audience
	}
	if !tokenMetadata.IssuedAt.IsZero() {
		response["iat"] = tokenMetadata.IssuedAt.Unix()
	}
	if storedToken, err := s.tokenStore.GetToken(ctx, accessToken); err == nil && storedToken != nil && !storedToken.Expiry.IsZero() {
		response["exp"] = storedToken.Expiry.Unix()
	}
	return response
}

// introspectionRequesterAllowed implements the RFC 7662 §2.1 authorization
// gate: the requester is allowed when it owns the token or when it has been
// enrolled in IntrospectionResourceServers. An empty tokenBoundClient (which
// should not occur on a well-formed token) denies by default.
func (s *Server) introspectionRequesterAllowed(requestingClient, tokenBoundClient string) bool {
	if tokenBoundClient == "" || requestingClient == "" {
		return false
	}
	if requestingClient == tokenBoundClient {
		return true
	}
	for _, allowed := range s.Config.IntrospectionResourceServers {
		if allowed == requestingClient {
			return true
		}
	}
	return false
}
