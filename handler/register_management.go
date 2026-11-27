package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"go.opentelemetry.io/otel/trace"
	"golang.org/x/crypto/bcrypt"

	"github.com/giantswarm/mcp-oauth/internal/constants"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage"
)

// ServeClientManagement handles RFC 7592 client management requests:
//
//	GET    /oauth/register/{client_id}  — read registration
//	PUT    /oauth/register/{client_id}  — replace + rotate registration access token
//	DELETE /oauth/register/{client_id}  — remove client
func (h *Handler) ServeClientManagement(w http.ResponseWriter, r *http.Request) {
	if h.notFoundWhen(w, r, !h.server.Config.RegistrationEnabled()) {
		return
	}
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
		status := h.writeClientMetadata(w, r, client)
		h.recordHTTPMetrics(r.Context(), endpointClientManagement, http.MethodGet, status, startTime)
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
	if len(r.Header.Values("Authorization")) > 1 {
		h.writeError(w, constants.ErrorCodeInvalidRequest, "Multiple Authorization credentials", http.StatusBadRequest)
		return nil, false
	}
	authHeader := r.Header.Get("Authorization")
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") || parts[1] == "" {
		h.logger.Warn("Client management: missing or malformed Bearer token", "ip", clientIP, "client_id", clientID)
		w.Header().Set("WWW-Authenticate", `Bearer realm="client_management"`)
		h.writeError(w, constants.ErrorCodeInvalidToken, "Bearer token required", http.StatusUnauthorized)
		return nil, false
	}
	bearerToken := parts[1]

	client, err := h.server.GetRegisteredClient(r.Context(), clientID)
	if err != nil {
		if storage.IsNotFoundError(err) {
			// Perform a dummy bcrypt comparison to prevent timing-based enumeration.
			_ = bcrypt.CompareHashAndPassword([]byte(storage.DummyBcryptHash), []byte(bearerToken))
			h.logger.Warn("Client management: client not found", "ip", clientIP, "client_id", clientID)
			w.Header().Set("WWW-Authenticate", `Bearer realm="client_management"`)
			h.writeError(w, constants.ErrorCodeInvalidToken, "invalid registration_access_token", http.StatusUnauthorized)
			return nil, false
		}
		if errors.Is(err, server.ErrStorageUnavailable) {
			h.writeStorageUnavailable(w, r, endpointClientManagement, r.Method, trace.SpanFromContext(r.Context()), time.Now(), err)
			return nil, false
		}
		h.logger.Error("Client management: failed to retrieve client", "ip", clientIP, "client_id", clientID, paramError, err)
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
		fieldClientType:              client.ClientType,
		fieldRedirectURIs:            client.RedirectURIs,
		"token_endpoint_auth_method": client.TokenEndpointAuthMethod,
		"grant_types":                client.GrantTypes,
		"response_types":             client.ResponseTypes,
		"registration_client_uri":    h.server.Config.Issuer + server.EndpointPathClientManagement + client.ClientID,
	}
	if len(client.JWKS) > 0 {
		body["jwks"] = client.JWKS
		body["token_endpoint_auth_signing_alg"] = client.TokenEndpointAuthSigningAlg
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
func (h *Handler) writeClientMetadata(w http.ResponseWriter, r *http.Request, client *storage.Client) int {
	registrationToken := strings.SplitN(r.Header.Get("Authorization"), " ", 2)[1]
	clientSecret, err := h.server.DecryptClientSecret(client, registrationToken)
	if err != nil {
		h.writeError(w, constants.ErrorCodeServerError, "current credential unavailable; PUT the existing client_secret to enable credential retrieval", http.StatusInternalServerError)
		return http.StatusInternalServerError
	}
	security.SetSecurityHeaders(w, h.server.Config.Issuer)
	body := h.buildClientResponseBody(client)
	body["registration_access_token"] = registrationToken
	addClientSecretResponse(body, clientSecret)
	w.Header().Set("Content-Type", "application/json")
	h.writeJSON(w, body)
	return http.StatusOK
}

func addClientSecretResponse(body map[string]any, clientSecret string) {
	if clientSecret != "" {
		body["client_secret"] = clientSecret
		body["client_secret_expires_at"] = int64(0)
	}
}

// readClientManagementUpdate validates replacement metadata before mutation.
func (h *Handler) readClientManagementUpdate(w http.ResponseWriter, r *http.Request, existing *storage.Client, clientIP string, startTime time.Time) (*clientRegistrationRequest, string) {
	r.Body = http.MaxBytesReader(w, r.Body, h.server.Config.MaxRequestBodySize)

	var metadata clientRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&metadata); err != nil {
		if isMaxBytesError(err) {
			h.recordHTTPMetrics(r.Context(), endpointClientManagement, http.MethodPut, http.StatusRequestEntityTooLarge, startTime)
			h.writeError(w, constants.ErrorCodeInvalidRequest, "Request body too large", http.StatusRequestEntityTooLarge)
			return nil, ""
		}
		h.writeError(w, constants.ErrorCodeInvalidRequest, "Invalid JSON", http.StatusBadRequest)
		return nil, ""
	}

	if metadata.ClientID != existing.ClientID {
		h.writeError(w, "invalid_client_metadata", "client_id must match the authenticated registration", http.StatusBadRequest)
		return nil, ""
	}
	var clientSecret string
	if len(metadata.ClientSecret) != 0 {
		if json.Unmarshal(metadata.ClientSecret, &clientSecret) != nil || bcrypt.CompareHashAndPassword([]byte(existing.ClientSecretHash), []byte(clientSecret)) != nil {
			h.writeError(w, "invalid_client_metadata", "client_secret must match the registered credential", http.StatusBadRequest)
			return nil, ""
		}
	}
	if metadata.TokenEndpointAuthMethod == "" {
		metadata.TokenEndpointAuthMethod = server.TokenEndpointAuthMethodBasic
	}
	if err := h.validateClientMetadata(w, &metadata, clientIP); err != nil {
		return nil, ""
	}
	if err := h.server.ValidateRedirectURIsForRegistration(r.Context(), metadata.RedirectURIs); err != nil {
		h.writeError(w, constants.ErrorCodeInvalidRedirectURI, "redirect_uris refused", http.StatusBadRequest)
		return nil, ""
	}
	return &metadata, clientSecret
}

func (h *Handler) handleClientManagementPut(w http.ResponseWriter, r *http.Request, existing *storage.Client, clientIP string, startTime time.Time) {
	metadata, clientSecret := h.readClientManagementUpdate(w, r, existing, clientIP, startTime)
	if metadata == nil {
		return
	}
	updated := *existing
	updated.ClientName = metadata.ClientName
	updated.RedirectURIs = metadata.RedirectURIs
	updated.Scopes = metadata.Scopes
	updated.TokenEndpointAuthMethod = metadata.TokenEndpointAuthMethod
	updated.JWKS = metadata.JWKS
	updated.TokenEndpointAuthSigningAlg = metadata.TokenEndpointAuthSigningAlg
	switch updated.TokenEndpointAuthMethod {
	case server.TokenEndpointAuthMethodPrivateKeyJWT:
		updated.ClientType = server.ClientTypeConfidential
		updated.ClientSecretHash = ""
		updated.ClientSecretEncrypted = ""
		clientSecret = ""
	case server.TokenEndpointAuthMethodNone:
		updated.ClientType = server.ClientTypePublic
		updated.ClientSecretHash = ""
		updated.ClientSecretEncrypted = ""
		clientSecret = ""
	default:
		if updated.ClientSecretHash == "" {
			h.writeError(w, "invalid_client_metadata", "Register a replacement client to obtain a client secret", http.StatusBadRequest)
			return
		}
		updated.ClientType = server.ClientTypeConfidential
	}
	if updated.ClientSecretHash != "" && clientSecret == "" {
		var err error
		clientSecret, err = h.server.DecryptClientSecret(existing, strings.SplitN(r.Header.Get("Authorization"), " ", 2)[1])
		if err != nil {
			h.writeError(w, "invalid_client_metadata", "include the existing client_secret to enable credential retrieval", http.StatusBadRequest)
			return
		}
	}
	newToken, newHash, err := server.GenerateRegistrationAccessToken()
	if err != nil {
		h.logger.Error("Client management: failed to rotate registration access token", "ip", clientIP, "client_id", existing.ClientID, paramError, err)
		h.writeError(w, constants.ErrorCodeServerError, "failed to rotate registration access token", http.StatusInternalServerError)
		return
	}
	updated.UpdatedAt = time.Now()
	updated.RegistrationAccessTokenHash = newHash
	if err := h.server.EncryptClientSecret(&updated, clientSecret, newToken); err != nil {
		h.writeError(w, constants.ErrorCodeServerError, "failed to protect client credential", http.StatusInternalServerError)
		return
	}

	if err := h.server.UpdateClientRegistration(r.Context(), &updated, existing); err != nil {
		if errors.Is(err, storage.ErrInvalidClientCredentials) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="client_management"`)
			h.writeError(w, constants.ErrorCodeInvalidToken, "registration changed; use its current registration access token", http.StatusUnauthorized)
			return
		}
		if errors.Is(err, server.ErrStorageUnavailable) {
			h.writeStorageUnavailable(w, r, endpointClientManagement, r.Method, trace.SpanFromContext(r.Context()), startTime, err)
			return
		}
		h.logger.Error("Client management: failed to update client", "ip", clientIP, "client_id", existing.ClientID, paramError, err)
		h.recordHTTPMetrics(r.Context(), endpointClientManagement, http.MethodPut, http.StatusInternalServerError, startTime)
		h.writeError(w, constants.ErrorCodeServerError, "failed to update client", http.StatusInternalServerError)
		return
	}

	h.recordHTTPMetrics(r.Context(), endpointClientManagement, http.MethodPut, http.StatusOK, startTime)
	security.SetSecurityHeaders(w, h.server.Config.Issuer)
	body := h.buildClientResponseBody(&updated)
	body["registration_access_token"] = newToken
	addClientSecretResponse(body, clientSecret)
	w.Header().Set("Content-Type", "application/json")
	h.writeJSON(w, body)
}

// handleClientManagementDelete handles DELETE /oauth/register/{client_id}.
func (h *Handler) handleClientManagementDelete(w http.ResponseWriter, r *http.Request, client *storage.Client, clientIP string, startTime time.Time) {
	if err := h.server.DeleteClient(r.Context(), client.ClientID); err != nil {
		if storage.IsNotFoundError(err) {
			h.recordHTTPMetrics(r.Context(), endpointClientManagement, http.MethodDelete, http.StatusNotFound, startTime)
			h.writeError(w, constants.ErrorCodeInvalidRequest, "client not found", http.StatusNotFound)
			return
		}
		h.logger.Error("Client management: failed to delete client", "ip", clientIP, "client_id", client.ClientID, paramError, err)
		h.recordHTTPMetrics(r.Context(), endpointClientManagement, http.MethodDelete, http.StatusInternalServerError, startTime)
		h.writeError(w, constants.ErrorCodeServerError, "failed to delete client", http.StatusInternalServerError)
		return
	}

	h.recordHTTPMetrics(r.Context(), endpointClientManagement, http.MethodDelete, http.StatusNoContent, startTime)
	w.WriteHeader(http.StatusNoContent)
}
