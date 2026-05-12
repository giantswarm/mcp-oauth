package server

import (
	"context"
	"encoding/json"

	"github.com/giantswarm/mcp-oauth/internal/helpers"
	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
)

// IntrospectToken returns the RFC 7662 introspection payload for accessToken,
// or {"active": false} when requestingClient is not authorized to learn it.
// Denied probes return no other fields so the endpoint is not an oracle for
// token or user enumeration.
func (s *Server) IntrospectToken(ctx context.Context, accessToken, requestingClient string) map[string]any {
	if s.Config.IsJWTAccessTokenFormat() && s.looksLikeSelfIssuedJWT(accessToken) {
		return s.introspectSelfIssuedJWT(ctx, accessToken, requestingClient)
	}
	return s.introspectOpaqueToken(ctx, accessToken, requestingClient)
}

// inactiveIntrospectionResponse is the RFC 7662 §2.2 response for any token
// the requester is not authorized to introspect or that fails validation.
// Constructed fresh per call so a caller mutating it cannot affect another.
func inactiveIntrospectionResponse() map[string]any {
	return map[string]any{"active": false}
}

// introspectSelfIssuedJWT runs the same verification pipeline as
// [Server.validateSelfIssuedJWT] and projects the verified claim set into the
// RFC 7662 §2.2 response — single pass, no re-verification, no drift between
// the two paths.
func (s *Server) introspectSelfIssuedJWT(ctx context.Context, accessToken, requestingClient string) map[string]any {
	userInfo, claims, err := s.validateSelfIssuedJWT(ctx, accessToken)
	if err != nil || userInfo == nil {
		return inactiveIntrospectionResponse()
	}

	tokenBoundClient, _ := claims["client_id"].(string)
	if !s.introspectionRequesterAllowed(ctx, requestingClient, tokenBoundClient) {
		return inactiveIntrospectionResponse()
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
	switch v := claims[key].(type) {
	case float64:
		dst[key] = int64(v)
	case json.Number:
		// jose's Claims decoder uses float64 by default but the underlying
		// json decoder can be configured for json.Number — accept both so a
		// future decode-mode change does not silently drop exp/iat/nbf.
		if n, err := v.Int64(); err == nil {
			dst[key] = n
		}
	}
}

// introspectOpaqueToken gates on the requester before fetching userinfo, so a
// denied probe never triggers a provider round-trip nor leaks user attributes.
func (s *Server) introspectOpaqueToken(ctx context.Context, accessToken, requestingClient string) map[string]any {
	metaGetter, ok := s.tokenStore.(storage.TokenMetadataGetter)
	if !ok {
		return inactiveIntrospectionResponse()
	}
	tokenMetadata, err := metaGetter.GetTokenMetadata(accessToken)
	if err != nil || tokenMetadata == nil {
		return inactiveIntrospectionResponse()
	}

	if !s.introspectionRequesterAllowed(ctx, requestingClient, tokenMetadata.ClientID) {
		return inactiveIntrospectionResponse()
	}

	userInfo, err := s.ValidateToken(ctx, accessToken)
	if err != nil || userInfo == nil {
		return inactiveIntrospectionResponse()
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

// introspectionRequesterAllowed fails closed. Denials emit
// EventIntrospectionRequesterDenied so cross-client probes are visible in the
// audit log even though the RFC 7662 §2.2 response hides them from the caller.
func (s *Server) introspectionRequesterAllowed(ctx context.Context, requestingClient, tokenBoundClient string) bool {
	if tokenBoundClient == "" || requestingClient == "" {
		s.logIntrospectionRequesterDenied(ctx, requestingClient, tokenBoundClient, "empty_client_id")
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
	s.logIntrospectionRequesterDenied(ctx, requestingClient, tokenBoundClient, "cross_client_probe")
	return false
}

func (s *Server) logIntrospectionRequesterDenied(ctx context.Context, requestingClient, tokenBoundClient, reason string) {
	if s.Auditor == nil {
		return
	}
	s.Auditor.LogEvent(ctx, security.Event{
		Type:     security.EventIntrospectionRequesterDenied,
		ClientID: requestingClient,
		Details: map[string]any{
			"severity":           "medium",
			"reason":             reason,
			"token_bound_client": tokenBoundClient,
		},
	})
}
