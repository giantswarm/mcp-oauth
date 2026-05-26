package handler

import (
	"net/http"
	"time"

	"github.com/giantswarm/mcp-oauth/server"
)

// extractDPoPJKT validates a DPoP proof from the request header (if present)
// and returns the JKT to bind to the issued token. Returns ("", nil) when no
// DPoP header is present (DPoP is optional).
func (h *Handler) extractDPoPJKT(r *http.Request) (string, error) {
	proof := r.Header.Get("DPoP")
	if proof == "" {
		return "", nil
	}
	claims, err := server.ValidateDPoPProof(r.Context(), proof, r.Method, dpopHTU(r), "", h.server.DPoPReplayCache(), time.Now())
	if err != nil {
		return "", err
	}
	return claims.JKT, nil
}

// dpopHTU returns the URI for DPoP htu validation: path + host, no query, no fragment.
func dpopHTU(r *http.Request) string {
	u := *r.URL
	u.RawQuery = ""
	u.Fragment = ""
	if u.Host == "" {
		u.Host = r.Host
	}
	if u.Scheme == "" {
		if r.TLS != nil {
			u.Scheme = "https"
		} else {
			u.Scheme = "http"
		}
	}
	return u.String()
}
