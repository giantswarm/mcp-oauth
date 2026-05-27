package handler

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/giantswarm/mcp-oauth/internal/constants"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage"
)

// ServeClientManagement handles RFC 7592 client management requests:
//
//	GET    /oauth/register/{client_id}  — read registration
//	PUT    /oauth/register/{client_id}  — replace + rotate registration token
//	DELETE /oauth/register/{client_id}  — remove client
func (h *Handler) ServeClientManagement(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	r, span, endSpan := h.startHandlerSpan(r, "oauth.http.client_management")
	defer endSpan()

	clientIP, ok := h.gateIPRateLimit(w, r, span, endpointClientManagement, r.Method, startTime)
	if !ok {
		return
	}

	clientID := strings.TrimPrefix(r.URL.Path, server.EndpointPathClientManagement)
	if clientID == "" {
		h.writeError(w, constants.ErrorCodeInvalidRequest, "missing client_id in path", http.StatusBadRequest)
		return
	}

	client, ok := h.authenticateManagementRequest(w, r, clientID, clientIP)
	if !ok {
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.recordHTTPMetrics(r.Context(), endpointClientManagement, http.MethodGet, http.StatusOK, startTime)
		h.writeClientMetadata(w, client)
	case http.MethodPut:
		h.handleClientManagementPut(w, r, client, clientIP, startTime)
	case http.MethodDelete:
		h.handleClientManagementDelete(w, r, client, clientIP, startTime)
	default:
		h.recordHTTPMetrics(r.Context(), endpointClientManagement, r.Method, http.StatusMethodNotAllowed, startTime)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// authenticateManagementRequest extracts the client, looks up the stored hash,
// and constant-time-compares the Bearer token. Returns the client and true on
// success; writes the appropriate error response and returns false on failure.
func (h *Handler) authenticateManagementRequest(w http.ResponseWriter, r *http.Request, clientID, clientIP string) (*storage.Client, bool) {
	authHeader := r.Header.Get("Authorization")
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") || parts[1] == "" {
		h.logger.Warn("Client management: missing or malformed Bearer token", "ip", clientIP, "client_id", clientID)
		w.Header().Set("WWW-Authenticate", `Bearer realm="client_management"`)
		h.writeError(w, constants.ErrorCodeInvalidToken, "Bearer token required", http.StatusUnauthorized)
		return nil, false
	}
	bearerToken := parts[1]

	client, err := h.server.GetClient(r.Context(), clientID)
	if err != nil {
		if storage.IsNotFoundError(err) {
			// Perform a dummy bcrypt comparison to prevent timing-based enumeration.
			_ = bcrypt.CompareHashAndPassword([]byte(storage.DummyBcryptHash), []byte(bearerToken))
			h.logger.Warn("Client management: client not found", "ip", clientIP, "client_id", clientID)
			h.writeError(w, constants.ErrorCodeInvalidToken, "client not found", http.StatusNotFound)
			return nil, false
		}
		h.logger.Error("Client management: failed to retrieve client", "ip", clientIP, "client_id", clientID, "error", err)
		h.writeError(w, constants.ErrorCodeServerError, "failed to retrieve client", http.StatusInternalServerError)
		return nil, false
	}

	if client.RegistrationAccessTokenHash == "" {
		// Legacy client registered before RFC 7592 support — no token was issued.
		_ = bcrypt.CompareHashAndPassword([]byte(storage.DummyBcryptHash), []byte(bearerToken))
		h.logger.Warn("Client management: client not eligible for management", "ip", clientIP, "client_id", clientID)
		w.Header().Set("WWW-Authenticate", `Bearer realm="client_management"`)
		h.writeError(w, constants.ErrorCodeInvalidToken, "client not eligible for management", http.StatusUnauthorized)
		return nil, false
	}

	if err := bcrypt.CompareHashAndPassword([]byte(client.RegistrationAccessTokenHash), []byte(bearerToken)); err != nil {
		h.logger.Warn("Client management: invalid registration_access_token", "ip", clientIP, "client_id", clientID)
		w.Header().Set("WWW-Authenticate", `Bearer realm="client_management"`)
		h.writeError(w, constants.ErrorCodeInvalidToken, "invalid registration_access_token", http.StatusUnauthorized)
		return nil, false
	}

	return client, true
}

// buildClientResponseBody returns the RFC 7592 §3 fields common to GET and PUT
// responses. Callers append method-specific fields before writing.
func (h *Handler) buildClientResponseBody(client *storage.Client) map[string]any {
	body := map[string]any{
		"client_id":                  client.ClientID,
		"client_id_issued_at":        client.CreatedAt.Unix(),
		"client_name":                client.ClientName,
		"client_type":                client.ClientType,
		"redirect_uris":              client.RedirectURIs,
		"token_endpoint_auth_method": client.TokenEndpointAuthMethod,
		"grant_types":                client.GrantTypes,
		"response_types":             client.ResponseTypes,
		"registration_client_uri":    h.server.Config().Issuer + server.EndpointPathClientManagement + client.ClientID,
	}
	if !client.UpdatedAt.IsZero() {
		body["client_updated_at"] = client.UpdatedAt.Unix()
	}
	if len(client.Scopes) > 0 {
		body["scope"] = strings.Join(client.Scopes, " ")
	}
	return body
}

// writeClientMetadata serialises the stored client to the RFC 7592 §3 shape.
func (h *Handler) writeClientMetadata(w http.ResponseWriter, client *storage.Client) {
	security.SetSecurityHeaders(w, h.server.Config().Issuer)
	body := h.buildClientResponseBody(client)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

// handleClientManagementPut handles PUT /oauth/register/{client_id}.
// It validates the request body (same rules as DCR), replaces mutable fields,
// and rotates the registration access token per RFC 7592 §2.3.
func (h *Handler) handleClientManagementPut(w http.ResponseWriter, r *http.Request, existing *storage.Client, clientIP string, startTime time.Time) {
	r.Body = http.MaxBytesReader(w, r.Body, h.server.Config().MaxRequestBodySize)

	var req clientRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if isMaxBytesError(err) {
			h.recordHTTPMetrics(r.Context(), endpointClientManagement, http.MethodPut, http.StatusRequestEntityTooLarge, startTime)
			h.writeError(w, constants.ErrorCodeInvalidRequest, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		h.writeError(w, constants.ErrorCodeInvalidRequest, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.TokenEndpointAuthMethod != "" && !isValidAuthMethod(req.TokenEndpointAuthMethod) {
		h.writeError(w, constants.ErrorCodeInvalidRequest,
			"unsupported token_endpoint_auth_method", http.StatusBadRequest)
		return
	}

	newToken, newHash, err := server.GenerateRegistrationAccessToken()
	if err != nil {
		h.logger.Error("Client management: failed to rotate registration token", "ip", clientIP, "client_id", existing.ClientID, "error", err)
		h.writeError(w, constants.ErrorCodeServerError, "failed to rotate registration token", http.StatusInternalServerError)
		return
	}

	now := time.Now()
	updated := *existing
	if req.ClientName != "" {
		updated.ClientName = req.ClientName
	}
	if len(req.RedirectURIs) > 0 {
		updated.RedirectURIs = req.RedirectURIs
	}
	if len(req.Scopes) > 0 {
		updated.Scopes = req.Scopes
	}
	if req.TokenEndpointAuthMethod != "" {
		updated.TokenEndpointAuthMethod = req.TokenEndpointAuthMethod
	}
	updated.UpdatedAt = now
	updated.RegistrationAccessTokenHash = newHash

	if err := h.server.SaveClient(r.Context(), &updated); err != nil {
		h.logger.Error("Client management: failed to update client", "ip", clientIP, "client_id", existing.ClientID, "error", err)
		h.recordHTTPMetrics(r.Context(), endpointClientManagement, http.MethodPut, http.StatusInternalServerError, startTime)
		h.writeError(w, constants.ErrorCodeServerError, "failed to update client", http.StatusInternalServerError)
		return
	}

	h.recordHTTPMetrics(r.Context(), endpointClientManagement, http.MethodPut, http.StatusOK, startTime)
	security.SetSecurityHeaders(w, h.server.Config().Issuer)
	body := h.buildClientResponseBody(&updated)
	body["registration_access_token"] = newToken
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

// handleClientManagementDelete handles DELETE /oauth/register/{client_id}.
func (h *Handler) handleClientManagementDelete(w http.ResponseWriter, r *http.Request, client *storage.Client, clientIP string, startTime time.Time) {
	if err := h.server.DeleteClient(r.Context(), client.ClientID); err != nil {
		if storage.IsNotFoundError(err) {
			h.recordHTTPMetrics(r.Context(), endpointClientManagement, http.MethodDelete, http.StatusNotFound, startTime)
			h.writeError(w, constants.ErrorCodeInvalidRequest, "client not found", http.StatusNotFound)
			return
		}
		h.logger.Error("Client management: failed to delete client", "ip", clientIP, "client_id", client.ClientID, "error", err)
		h.recordHTTPMetrics(r.Context(), endpointClientManagement, http.MethodDelete, http.StatusInternalServerError, startTime)
		h.writeError(w, constants.ErrorCodeServerError, "failed to delete client", http.StatusInternalServerError)
		return
	}

	h.recordHTTPMetrics(r.Context(), endpointClientManagement, http.MethodDelete, http.StatusNoContent, startTime)
	w.WriteHeader(http.StatusNoContent)
}
