package server

import (
	"context"

	"github.com/giantswarm/mcp-oauth/internal/helpers"
	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/storage"
)

// IntrospectToken returns the RFC 7662 introspection payload for accessToken,
// or {"active": false} when requestingClient is not authorized to learn it.
// Denied probes return no other fields so the endpoint is not an oracle for
// token or user enumeration.
func (s *Server) IntrospectToken(ctx context.Context, accessToken, requestingClient string) map[string]any {
	inactive := map[string]any{"active": false}

	if s.Config.IsJWTAccessTokenFormat() && s.looksLikeSelfIssuedJWT(accessToken) {
		return s.introspectSelfIssuedJWT(ctx, accessToken, requestingClient, inactive)
	}
	return s.introspectOpaqueToken(ctx, accessToken, requestingClient, inactive)
}

// introspectSelfIssuedJWT skips the metadata store: a verified self-issued JWT
// already carries every RFC 7662 §2.2 claim signed by the AS.
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

// introspectOpaqueToken gates on the requester before fetching userinfo, so a
// denied probe never triggers a provider round-trip nor leaks user attributes.
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

// introspectionRequesterAllowed fails closed: an empty client ID on either
// side denies, even though a well-formed token always carries one.
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
