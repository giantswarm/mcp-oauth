package handler

import (
	"errors"
	"net"
	"net/http"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/giantswarm/mcp-oauth/instrumentation"
	"github.com/giantswarm/mcp-oauth/internal/constants"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/server"
)

// extractDPoPJKT validates a DPoP proof from the request header (if present)
// and returns the JKT to bind to the issued token. Returns ("", nil) when no
// DPoP header is present (DPoP is optional).
func (h *Handler) extractDPoPJKT(r *http.Request) (string, error) {
	proofHeaders := r.Header.Values("DPoP")
	if len(proofHeaders) > 1 {
		return "", errors.New("multiple DPoP proof headers")
	}
	proof := r.Header.Get("DPoP")
	if proof == "" {
		if len(proofHeaders) != 0 {
			return "", errors.New("empty DPoP proof header")
		}
		return "", nil
	}
	claims, err := server.ValidateDPoPProof(r.Context(), proof, r.Method, dpopHTU(r, h.server.TrustedProxyCIDRs()), "", h.server.DPoPReplayCache(), h.server.DPoPNonceProvider(), time.Now())
	if err != nil {
		return "", err
	}
	return claims.JKT, nil
}

func (h *Handler) writeTokenDPoPError(w http.ResponseWriter, r *http.Request, grant, clientID string, span trace.Span, startTime time.Time, err error) {
	var reasonPrefix string
	if grant == server.GrantTypeTokenExchange {
		reasonPrefix = "token_exchange_"
	}
	if errors.Is(err, server.ErrStorageUnavailable) {
		h.logAuthFailure(r.Context(), clientID, h.clientIP(r), reasonPrefix+"dpop_replay_store_unavailable", "DPoP replay store unavailable")
		h.writeTokenStorageUnavailable(w, r, grant, span, startTime, err)
		return
	}
	code, reason := constants.ErrorCodeInvalidDPoPProof, "dpop_proof_invalid"
	description := "DPoP proof validation failed"
	if errors.Is(err, server.ErrDPoPNonceInvalid) {
		code, reason = constants.ErrorCodeUseDPoPNonce, "dpop_nonce_required"
		description = "A DPoP nonce is required"
		if provider := h.server.DPoPNonceProvider(); provider != nil {
			w.Header().Set("DPoP-Nonce", provider.Nonce(r.Context()))
		}
	}
	h.logAuthFailure(r.Context(), clientID, h.clientIP(r), reasonPrefix+reason, description)
	h.recordTokenFailure(r.Context(), grant, code)
	h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
	instrumentation.RecordError(span, err)
	instrumentation.SetSpanError(span, description)
	h.writeError(w, code, description, http.StatusBadRequest)
}

// dpopHTU returns the URI for DPoP htu validation: path + host, no query, no fragment.
// When the direct connection originates from a trusted proxy CIDR, X-Forwarded-Proto
// and X-Forwarded-Host are used to reconstruct the external URL seen by the client.
func dpopHTU(r *http.Request, trustedProxies []*net.IPNet) string {
	u := *r.URL
	u.RawQuery = ""
	u.Fragment = ""

	if security.IsTrustedProxy(r.RemoteAddr, trustedProxies) {
		if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
			u.Scheme = proto
		}
		if host := r.Header.Get("X-Forwarded-Host"); host != "" {
			u.Host = host
		}
	}

	if u.Host == "" {
		u.Host = r.Host
	}
	if u.Scheme == "" {
		if r.TLS != nil {
			u.Scheme = server.SchemeHTTPS
		} else {
			u.Scheme = server.SchemeHTTP
		}
	}
	return u.String()
}
