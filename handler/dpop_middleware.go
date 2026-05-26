package handler

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/giantswarm/mcp-oauth/server"
)

// DPoPMiddleware returns an http.Handler middleware that enforces DPoP proof
// validation when the request carries an "Authorization: DPoP <token>" header.
// Requests with "Authorization: Bearer <token>" are passed through unchanged.
// Requests with no Authorization header are also passed through (authentication
// is the responsibility of the next handler).
//
// trustedProxies lists CIDRs whose X-Forwarded-Proto and X-Forwarded-Host
// headers are trusted for htu reconstruction. Pass nil when the server is
// directly exposed (no reverse proxy in front).
func DPoPMiddleware(replayCache server.DPoPReplayCache, trustedProxies []*net.IPNet) func(http.Handler) http.Handler {
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
				writeDPoPError(w, "invalid_request", "DPoP proof required", http.StatusUnauthorized)
				return
			}
			htu := dpopHTU(r, trustedProxies)
			_, err := server.ValidateDPoPProof(r.Context(), proof, r.Method, htu, accessToken, replayCache, time.Now())
			if err != nil {
				writeDPoPError(w, "invalid_dpop_proof", err.Error(), http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func writeDPoPError(w http.ResponseWriter, code, description string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
}
