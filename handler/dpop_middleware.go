package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/giantswarm/mcp-oauth/internal/constants"
	"github.com/giantswarm/mcp-oauth/server"
)

type dpopProofJKTKeyType struct{}

// dpopProofJKTFromContext returns the DPoP proof JKT stored by DPoPMiddleware
// after successful proof validation. Empty string means no DPoP proof was validated
// for this request (Bearer scheme or no Authorization header).
func dpopProofJKTFromContext(ctx context.Context) string {
	jkt, _ := ctx.Value(dpopProofJKTKeyType{}).(string)
	return jkt
}

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
//
// When replayCache is nil the middleware falls back to an in-process cache and
// logs a warning. In multi-pod deployments this silently degrades to per-pod
// replay protection; pass a shared cache via WithDPoPReplayCache to avoid this.
// Prefer [Handler.DPoPMiddleware] when using handler.Handler — it reads the
// cache from the server so split-wiring is impossible.
func DPoPMiddleware(replayCache server.DPoPReplayCache, nonceProvider server.DPoPNonceProvider, trustedProxies []*net.IPNet) func(http.Handler) http.Handler {
	if replayCache == nil {
		slog.Warn("DPoPMiddleware: replayCache is nil; using in-process replay cache — not safe in multi-pod deployments")
		replayCache = server.NewMemoryDPoPReplayCache()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			serveDPoP(w, r, next, replayCache, nonceProvider, trustedProxies)
		})
	}
}

// DPoPMiddleware returns an http.Handler middleware that enforces DPoP proof
// validation, reading the replay cache, nonce provider, and trusted proxy CIDRs
// from the server. This eliminates the split-wiring problem of the package-level
// [DPoPMiddleware] function: both the issuance path and the resource path share
// the same cache instance automatically.
func (h *Handler) DPoPMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			serveDPoP(w, r, next,
				h.server.DPoPReplayCache(),
				h.server.DPoPNonceProvider(),
				h.server.TrustedProxyCIDRs(),
			)
		})
	}
}

func serveDPoP(w http.ResponseWriter, r *http.Request, next http.Handler, replayCache server.DPoPReplayCache, nonceProvider server.DPoPNonceProvider, trustedProxies []*net.IPNet) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(strings.ToLower(auth), "dpop ") {
		next.ServeHTTP(w, r)
		return
	}
	accessToken := auth[len("DPoP "):] // preserve original token value
	proof := r.Header.Get("DPoP")
	if proof == "" {
		writeDPoPError(w,
			dpopWWWAuthenticate(constants.ErrorCodeInvalidRequest, "DPoP proof required"),
			"",
			constants.ErrorCodeInvalidRequest,
			"DPoP proof required",
			http.StatusUnauthorized,
		)
		return
	}
	htu := dpopHTU(r, trustedProxies)
	proofClaims, err := server.ValidateDPoPProof(r.Context(), proof, r.Method, htu, accessToken, replayCache, nonceProvider, time.Now())
	if err != nil {
		writeDPoPValidationError(w, r, err, nonceProvider)
		return
	}

	// Normalize to Bearer and store proof JKT for sender-constraint enforcement (RFC 9449 §6.1).
	ctx := context.WithValue(r.Context(), dpopProofJKTKeyType{}, proofClaims.JKT)
	r2 := r.Clone(ctx)
	r2.Header.Set("Authorization", "Bearer "+accessToken)
	next.ServeHTTP(w, r2)
}

func writeDPoPValidationError(w http.ResponseWriter, r *http.Request, err error, nonceProvider server.DPoPNonceProvider) {
	if errors.Is(err, server.ErrDPoPNonceInvalid) {
		nonce := ""
		if nonceProvider != nil {
			nonce = nonceProvider.Nonce(r.Context())
		}
		writeDPoPError(w,
			dpopWWWAuthenticate(constants.ErrorCodeUseDPoPNonce, "Resource server requires nonce in DPoP proof"),
			nonce,
			constants.ErrorCodeUseDPoPNonce,
			"Resource server requires nonce in DPoP proof",
			http.StatusUnauthorized,
		)
		return
	}
	writeDPoPError(w,
		dpopWWWAuthenticate(constants.ErrorCodeInvalidDPoPProof, err.Error()),
		"",
		constants.ErrorCodeInvalidDPoPProof,
		err.Error(),
		http.StatusUnauthorized,
	)
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
