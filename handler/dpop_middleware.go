package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	oauth "github.com/giantswarm/mcp-oauth"
	"github.com/giantswarm/mcp-oauth/server"
)

// DPoPMiddleware returns an http.Handler middleware that enforces DPoP proof
// validation when the request carries an "Authorization: DPoP <token>" header
// (RFC 9449 §7).
//
// Requests with "Authorization: Bearer <token>" are passed through unchanged.
// Requests with no Authorization header are also passed through; authentication
// is the responsibility of the next handler.
//
// nonceProvider is optional: when non-nil, every DPoP proof must carry a
// currently-valid server-issued nonce (RFC 9449 §8). On failure the middleware
// responds 401 with error=use_dpop_nonce and a DPoP-Nonce response header.
//
// trustedProxies lists CIDRs whose X-Forwarded-Proto and X-Forwarded-Host
// headers are trusted for htu reconstruction. Pass nil when the server is
// directly exposed.
func DPoPMiddleware(replayCache server.DPoPReplayCache, nonceProvider server.DPoPNonceProvider, trustedProxies []*net.IPNet) func(http.Handler) http.Handler {
	if replayCache == nil {
		replayCache = server.NewMemoryDPoPReplayCache()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(strings.ToLower(auth), "dpop ") {
				next.ServeHTTP(w, r)
				return
			}
			accessToken := auth[len("DPoP "):] // preserve original token value
			proof := r.Header.Get("DPoP")
			if proof == "" {
				writeDPoPError(w,
					dpopWWWAuthenticate(oauth.ErrorCodeInvalidRequest, "DPoP proof required"),
					"",
					oauth.ErrorCodeInvalidRequest,
					"DPoP proof required",
					http.StatusUnauthorized,
				)
				return
			}
			htu := dpopHTU(r, trustedProxies)
			_, err := server.ValidateDPoPProof(r.Context(), proof, r.Method, htu, accessToken, replayCache, nonceProvider, time.Now())
			if err != nil {
				if errors.Is(err, server.ErrDPoPNonceInvalid) {
					nonce := ""
					if nonceProvider != nil {
						nonce = nonceProvider.Nonce(r.Context())
					}
					writeDPoPError(w,
						dpopWWWAuthenticate(oauth.ErrorCodeUseDPoPNonce, "Resource server requires nonce in DPoP proof"),
						nonce,
						oauth.ErrorCodeUseDPoPNonce,
						"Resource server requires nonce in DPoP proof",
						http.StatusUnauthorized,
					)
					return
				}
				writeDPoPError(w,
					dpopWWWAuthenticate(oauth.ErrorCodeInvalidDPoPProof, err.Error()),
					"",
					oauth.ErrorCodeInvalidDPoPProof,
					err.Error(),
					http.StatusUnauthorized,
				)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// dpopWWWAuthenticate formats the WWW-Authenticate header value for DPoP
// error responses per RFC 9449 §7.1. The algs attribute lists accepted proof
// signature algorithms.
func dpopWWWAuthenticate(code, description string) string {
	return fmt.Sprintf(`DPoP error="%s", error_description="%s", algs="%s"`,
		code, description, server.DPoPSupportedAlgs)
}

// writeDPoPError writes a JSON DPoP error response.
// wwwAuth is written as the WWW-Authenticate header when non-empty (RFC 9449 §7.1).
// dpopNonce is written as the DPoP-Nonce header when non-empty (RFC 9449 §8).
func writeDPoPError(w http.ResponseWriter, wwwAuth, dpopNonce, code, description string, status int) {
	if wwwAuth != "" {
		w.Header().Set("WWW-Authenticate", wwwAuth)
	}
	if dpopNonce != "" {
		w.Header().Set("DPoP-Nonce", dpopNonce)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	//nolint:errcheck — encoding map[string]string never fails
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
}
