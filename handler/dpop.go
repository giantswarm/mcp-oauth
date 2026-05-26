package handler

import (
	"net"
	"net/http"
	"time"

	"github.com/giantswarm/mcp-oauth/security"
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
	claims, err := server.ValidateDPoPProof(r.Context(), proof, r.Method, dpopHTU(r, h.server.TrustedProxyCIDRs()), "", h.server.DPoPReplayCache(), time.Now())
	if err != nil {
		return "", err
	}
	return claims.JKT, nil
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

