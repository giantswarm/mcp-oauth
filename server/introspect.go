package server

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/giantswarm/mcp-oauth/internal/helpers"
	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/providers/oidc"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
)

// validateIntrospectionAllowlistRegistered verifies every entry in
// Config.IntrospectionResourceServers resolves to a registered client. Catches
// operator typos that would otherwise silently deny every probe.
//
// A backend that returns transient errors during startup is treated as fatal
// here: bringing up a server with an unverifiable allowlist would leave the
// gate's correctness in an unknown state.
func (s *Server) validateIntrospectionAllowlistRegistered(ctx context.Context) error {
	for i, clientID := range s.config.IntrospectionResourceServers {
		_, err := s.clientStore.GetClient(ctx, clientID)
		if errors.Is(err, storage.ErrClientNotFound) {
			return fmt.Errorf("IntrospectionResourceServers[%d] %q is not a registered client", i, clientID)
		}
		if err != nil {
			return fmt.Errorf("IntrospectionResourceServers[%d] %q lookup failed: %w", i, clientID, err)
		}
	}
	return nil
}

// IntrospectToken returns the RFC 7662 introspection payload for accessToken,
// or {"active": false} when requestingClient is not authorized to learn it.
// Denied probes return no other fields so the endpoint is not an oracle for
// token or user enumeration.
//
// Callers MUST authenticate requestingClient before invoking this method.
// The cross-client gate trusts that identifier as-is; passing an attacker-
// supplied or unauthenticated value defeats the gate entirely.
func (s *Server) IntrospectToken(ctx context.Context, accessToken, requestingClient string) map[string]any {
	if s.config.IsJWTAccessTokenFormat() && s.looksLikeSelfIssuedJWT(accessToken) {
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

// introspectSelfIssuedJWT projects the verified claim set into the RFC 7662
// §2.2 response.
//
// Gate ordering: the cross-client check runs against the UNVERIFIED client_id
// claim first, so a probe for a JWT the requester does not own is rejected
// before the heavy validation pipeline runs. The verified claim is re-checked
// after validation; signature verification ensures an attacker cannot forge a
// matching unverified client_id to bypass the gate (signature would fail and
// the response stays inactive). This collapses the timing distinction between
// "valid JWT I don't own" and "garbage JWT" — both return inactive after a
// single unverified parse.
func (s *Server) introspectSelfIssuedJWT(ctx context.Context, accessToken, requestingClient string) map[string]any {
	unverifiedBoundClient := unverifiedClientIDClaim(accessToken)
	if !s.introspectionRequesterAllowed(ctx, requestingClient, unverifiedBoundClient) {
		return inactiveIntrospectionResponse()
	}

	userInfo, claims, err := s.validateSelfIssuedJWT(ctx, accessToken)
	if err != nil || userInfo == nil {
		return inactiveIntrospectionResponse()
	}

	verifiedBoundClient, _ := claims["client_id"].(string)
	if verifiedBoundClient != unverifiedBoundClient &&
		!s.introspectionRequesterAllowed(ctx, requestingClient, verifiedBoundClient) {
		return inactiveIntrospectionResponse()
	}

	return introspectionResponseFromJWTClaims(claims, verifiedBoundClient)
}

// unverifiedClientIDClaim returns the client_id claim from accessToken without
// verifying the signature. Used only for the introspection gate's early
// reject path; the verified claim is re-checked after full validation.
func unverifiedClientIDClaim(accessToken string) string {
	if !oidc.IsJWT(accessToken) {
		return ""
	}
	claims, err := oidc.ParseUnverifiedClaims(accessToken)
	if err != nil {
		return ""
	}
	v, _ := claims["client_id"].(string)
	return v
}

// jwtStandardClaims is the set of JWT claim names projected explicitly by
// introspectionResponseFromJWTClaims. Any claim not in this set is forwarded
// verbatim so that application-defined claims (e.g. allowed_backends, muster_sid)
// added to the JWT body reach the introspection caller without server changes.
var jwtStandardClaims = map[string]struct{}{
	"active": {}, "token_type": {}, "client_id": {},
	"sub": {}, "iss": {}, "aud": {}, "scope": {},
	"email": {}, "email_verified": {}, "name": {},
	"exp": {}, "iat": {}, "nbf": {}, "jti": {},
	"cnf": {}, "at_hash": {}, "nonce": {},
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
	copyClaimString(response, claims, "name")
	copyClaimBool(response, claims, "email_verified")
	copyClaimUnixTime(response, claims, "exp")
	copyClaimUnixTime(response, claims, "iat")
	copyClaimUnixTime(response, claims, "nbf")
	if aud := audiencesFromClaim(claims["aud"]); len(aud) == 1 {
		response["aud"] = aud[0]
	} else if len(aud) > 1 {
		response["aud"] = aud
	}
	if cnf, ok := claims["cnf"]; ok {
		response["cnf"] = cnf
	}
	// Forward any application-defined claims not in the standard set.
	for k, v := range claims {
		if _, known := jwtStandardClaims[k]; !known {
			response[k] = v
		}
	}
	return response
}

func copyClaimString(dst, claims map[string]any, key string) {
	if v, ok := claims[key].(string); ok && v != "" {
		dst[key] = v
	}
}

func copyClaimBool(dst, claims map[string]any, key string) {
	if v, ok := claims[key].(bool); ok {
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

func (s *Server) introspectionResponseFromOpaqueToken(_ context.Context, _ string, tokenMetadata *storage.TokenMetadata, userInfo *providers.UserInfo) map[string]any {
	response := map[string]any{
		"active":     true,
		"token_type": "Bearer",
		"client_id":  tokenMetadata.ClientID,
		"sub":        userInfo.ID,
		"iss":        s.config.Issuer,
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
	if !tokenMetadata.ExpiresAt.IsZero() {
		response["exp"] = tokenMetadata.ExpiresAt.Unix()
	}
	for k, v := range tokenMetadata.ExtraClaims {
		response[k] = v
	}
	return response
}

// introspectionRequesterAllowed fails closed. Denials emit
// EventIntrospectionRequesterDenied so cross-client probes are visible in the
// audit log even though the RFC 7662 §2.2 response hides them from the caller.
func (s *Server) introspectionRequesterAllowed(ctx context.Context, requestingClient, tokenBoundClient string) bool {
	if requestingClient == "" {
		s.logIntrospectionRequesterDenied(ctx, requestingClient, tokenBoundClient, "empty_requester")
		return false
	}
	if tokenBoundClient == "" {
		s.logIntrospectionRequesterDenied(ctx, requestingClient, tokenBoundClient, "empty_token_bound_client")
		return false
	}
	if requestingClient == tokenBoundClient {
		return true
	}
	if slices.Contains(s.config.IntrospectionResourceServers, requestingClient) {
		return true
	}
	s.logIntrospectionRequesterDenied(ctx, requestingClient, tokenBoundClient, "cross_client_probe")
	return false
}

func (s *Server) logIntrospectionRequesterDenied(ctx context.Context, requestingClient, tokenBoundClient, reason string) {
	s.auditor.LogEvent(ctx, security.Event{
		Type:     security.EventIntrospectionRequesterDenied,
		ClientID: requestingClient,
		Details: map[string]any{
			"severity":           "medium",
			"reason":             reason,
			"token_bound_client": tokenBoundClient,
		},
	})
}
