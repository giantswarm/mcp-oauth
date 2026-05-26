package handler

import (
	_ "embed"
	"encoding/json"
	"net/http"
	"time"

	oauth "github.com/giantswarm/mcp-oauth"
	"github.com/giantswarm/mcp-oauth/instrumentation"
	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/security"
)

// buildUserInfoClaims projects userInfo onto the OIDC §5.3 claim map, gated by
// the access token's granted scopes. `sub` is always emitted; `profile`,
// `email`, `groups` scopes admit their corresponding claim groups when the
// underlying field is non-empty. The returned `emitted` slice names the scope
// groups that contributed at least one claim — used for the audit record.
func buildUserInfoClaims(userInfo *providers.UserInfo, scopeSet map[string]struct{}) (map[string]any, []string) {
	emitted := []string{"sub"}
	claims := map[string]any{"sub": userInfo.ID}
	if _, ok := scopeSet["profile"]; ok {
		addProfileClaims(claims, userInfo)
		emitted = append(emitted, "profile")
	}
	if _, ok := scopeSet["email"]; ok && userInfo.Email != "" {
		claims["email"] = userInfo.Email
		claims["email_verified"] = userInfo.EmailVerified
		emitted = append(emitted, "email")
	}
	if _, ok := scopeSet["groups"]; ok && len(userInfo.Groups) > 0 {
		claims["groups"] = userInfo.Groups
		emitted = append(emitted, "groups")
	}
	return claims, emitted
}

// addProfileClaims copies the `profile`-scope claim group from userInfo into
// claims, skipping fields the upstream did not populate.
func addProfileClaims(claims map[string]any, userInfo *providers.UserInfo) {
	if userInfo.Name != "" {
		claims["name"] = userInfo.Name
	}
	if userInfo.GivenName != "" {
		claims["given_name"] = userInfo.GivenName
	}
	if userInfo.FamilyName != "" {
		claims["family_name"] = userInfo.FamilyName
	}
	if userInfo.Picture != "" {
		claims["picture"] = userInfo.Picture
	}
	if userInfo.Locale != "" {
		claims["locale"] = userInfo.Locale
	}
}

// ServeUserInfo handles the OIDC UserInfo endpoint (OIDC Core 1.0 §5.3).
// Accepts GET and POST. The [Handler.ValidateToken] middleware authenticates
// the bearer access token and stashes the resolved [providers.UserInfo] and
// granted scopes in the request context; this handler renders the claims
// gated by those scopes.
//
// The `openid` scope is REQUIRED to access the endpoint. The `sub` claim is
// always returned. `profile`, `email`, and `groups` scopes gate the
// corresponding claim groups.
func (h *Handler) ServeUserInfo(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	r, span, endSpan := h.startHandlerSpan(r, "oauth.http.userinfo")
	defer endSpan()

	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		instrumentation.SetSpanError(span, "method not allowed")
		w.Header().Set("Allow", "GET, POST")
		h.recordHTTPMetrics(r.Context(), endpointUserInfo, r.Method, http.StatusMethodNotAllowed, startTime)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	h.setCORSHeaders(w, r)
	security.SetSecurityHeaders(w, h.server.Config.Issuer)

	userInfo, ok := UserInfoFromContext(r.Context())
	if !ok || userInfo == nil {
		instrumentation.SetSpanError(span, "user info missing from context")
		h.recordHTTPMetrics(r.Context(), endpointUserInfo, r.Method, http.StatusUnauthorized, startTime)
		h.writeUnauthorizedError(w, r, oauth.ErrorCodeInvalidToken, "User information unavailable")
		return
	}

	// OIDC Core 1.0 §5.3.2 — `sub` is REQUIRED in the response. A token that
	// validated but carries no subject is an upstream bug; refuse rather than
	// emit a spec-violating claims set.
	if userInfo.ID == "" {
		instrumentation.SetSpanError(span, "user info missing sub")
		h.logger.Error("ServeUserInfo: resolved UserInfo has empty ID; refusing to emit sub-less response")
		h.recordHTTPMetrics(r.Context(), endpointUserInfo, r.Method, http.StatusInternalServerError, startTime)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	scopes, _ := ScopesFromContext(r.Context())
	scopeSet := make(map[string]struct{}, len(scopes))
	for _, s := range scopes {
		scopeSet[s] = struct{}{}
	}
	if _, ok := scopeSet["openid"]; !ok {
		instrumentation.SetSpanError(span, "openid scope missing")
		h.recordHTTPMetrics(r.Context(), endpointUserInfo, r.Method, http.StatusForbidden, startTime)
		h.writeInsufficientScopeError(w, []string{"openid"}, "openid scope is required to call /userinfo")
		return
	}

	claims, emitted := buildUserInfoClaims(userInfo, scopeSet)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(claims); err != nil {
		h.logger.Warn("Failed to encode userinfo response", "error", err)
		h.recordHTTPMetrics(r.Context(), endpointUserInfo, r.Method, http.StatusInternalServerError, startTime)
		return
	}

	h.recordHTTPMetrics(r.Context(), endpointUserInfo, r.Method, http.StatusOK, startTime)
	instrumentation.SetSpanSuccess(span)

	h.server.Auditor.LogEvent(r.Context(), security.Event{
		Type:      security.EventUserInfoServed,
		UserID:    userInfo.ID,
		IPAddress: h.clientIP(r),
		Details: map[string]any{
			"claim_groups": emitted,
		},
	})
}
