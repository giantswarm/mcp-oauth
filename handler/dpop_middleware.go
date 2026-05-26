package handler

import (
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
func DPoPMiddleware(replayCache server.DPoPReplayCache) func(http.Handler) http.Handler {
	if replayCache == nil {
		replayCache = server.NewMemoryDPoPReplayCache()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "DPoP ") {
				next.ServeHTTP(w, r)
				return
			}
			accessToken := strings.TrimPrefix(auth, "DPoP ")
			proof := r.Header.Get("DPoP")
			if proof == "" {
				http.Error(w, `{"error":"invalid_request","error_description":"DPoP proof required"}`, http.StatusUnauthorized)
				return
			}
			htu := dpopHTU(r)
			_, err := server.ValidateDPoPProof(r.Context(), proof, r.Method, htu, accessToken, replayCache, time.Now())
			if err != nil {
				http.Error(w, `{"error":"invalid_dpop_proof","error_description":"`+err.Error()+`"}`, http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
