package handler

import (
	"errors"
	"net/http"

	oauth "github.com/giantswarm/mcp-oauth"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage"
)

func hasClientAssertion(r *http.Request) bool {
	return r.Form.Has("client_assertion") || r.Form.Has("client_assertion_type")
}

func (h *Handler) authenticateAssertion(r *http.Request, clientID, clientIP string) (*storage.Client, error) {
	auditClientID := ""
	reject := func(reason string) (*storage.Client, error) {
		h.logAuthFailure(r.Context(), auditClientID, clientIP, reason, "Client authentication failed")
		return nil, oauth.ErrInvalidClient("Client authentication failed")
	}
	if r.Header.Get("Authorization") != "" || r.Form.Has("client_secret") {
		return reject("assertion_mixed_credentials")
	}
	if len(r.PostForm["client_assertion"]) != 1 || len(r.PostForm["client_assertion_type"]) != 1 || len(r.Form["client_assertion"]) != 1 || len(r.Form["client_assertion_type"]) != 1 || len(r.Form["client_id"]) > 1 ||
		r.Form.Get("client_assertion_type") != server.ClientAssertionTypeJWTBearer {
		return reject("assertion_type")
	}
	issuer, err := server.ClientAssertionIssuer(r.Form.Get("client_assertion"))
	if err != nil {
		return reject(err.Error())
	}
	if r.Form.Has("client_id") && clientID != issuer {
		return reject("assertion_identity")
	}
	clientID = issuer
	client, err := h.server.GetRegisteredClient(r.Context(), clientID)
	if err != nil {
		if errors.Is(err, server.ErrStorageUnavailable) {
			return nil, err
		}
		return reject("assertion_unknown_client")
	}
	auditClientID = client.ClientID
	if err := h.server.ValidateClientAssertion(r.Context(), client, r.Form.Get("client_assertion")); err != nil {
		if errors.Is(err, server.ErrStorageUnavailable) {
			return nil, err
		}
		return reject(err.Error())
	}
	return client, nil
}
