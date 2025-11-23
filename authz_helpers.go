package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"regexp"
	"time"

	"golang.org/x/oauth2"
)

// authCodeRequest holds parsed authorization code grant request parameters
type authCodeRequest struct {
	Code         string
	RedirectURI  string
	ClientID     string
	CodeVerifier string
}

// parseAuthCodeRequest extracts and validates authorization code grant parameters
func (h *Handler) parseAuthCodeRequest(r *http.Request) (*authCodeRequest, *OAuthError) {
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	clientID := r.FormValue("client_id")
	codeVerifier := r.FormValue("code_verifier")

	if code == "" {
		return nil, ErrInvalidRequest("code is required")
	}

	return &authCodeRequest{
		Code:         code,
		RedirectURI:  redirectURI,
		ClientID:     clientID,
		CodeVerifier: codeVerifier,
	}, nil
}

// validateAndRetrieveAuthCode retrieves and validates the authorization code
func (h *Handler) validateAndRetrieveAuthCode(params *authCodeRequest) (*AuthorizationCode, *OAuthError) {
	authCode, err := h.flowStore.GetAuthorizationCode(params.Code)
	if err != nil {
		h.logger.Warn("Invalid authorization code", "error", err)
		return nil, ErrInvalidGrant("Invalid or expired authorization code")
	}

	// OAuth 2.1: For public clients using PKCE, client_id is optional
	// If not provided, use the client_id from the authorization code
	clientID := params.ClientID
	if clientID == "" {
		clientID = authCode.ClientID
		h.logger.Debug("Using client_id from authorization code", "client_id", clientID)
	} else {
		// If client_id is provided, validate it matches
		if authCode.ClientID != clientID {
			h.logger.Warn("Client ID mismatch",
				"expected", authCode.ClientID,
				"got", clientID)
			return nil, ErrInvalidGrant("Client ID mismatch")
		}
	}

	// Validate redirect_uri matches
	if authCode.RedirectURI != params.RedirectURI {
		h.logger.Warn("Redirect URI mismatch",
			"expected", authCode.RedirectURI,
			"got", params.RedirectURI)
		return nil, ErrInvalidGrant("Redirect URI mismatch")
	}

	return authCode, nil
}

// validatePKCE validates the PKCE code_verifier against the code_challenge
func (h *Handler) validatePKCE(authCode *AuthorizationCode, codeVerifier string, clientID string) *OAuthError {
	if authCode.CodeChallenge == "" {
		return nil // No PKCE required for this authorization
	}

	if codeVerifier == "" {
		return ErrInvalidRequest("code_verifier is required")
	}

	// Validate code_verifier length (RFC 7636: min 43 chars, max 128 chars)
	if len(codeVerifier) < MinCodeVerifierLength {
		h.logger.Warn("code_verifier too short (insufficient entropy)",
			"client_id", clientID,
			"length", len(codeVerifier))
		return ErrInvalidRequest("code_verifier must be at least 43 characters (RFC 7636)")
	}
	if len(codeVerifier) > MaxCodeVerifierLength {
		h.logger.Warn("code_verifier too long",
			"client_id", clientID,
			"length", len(codeVerifier))
		return ErrInvalidRequest("code_verifier must be at most 128 characters (RFC 7636)")
	}

	// Validate code_verifier characters (RFC 7636: unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~")
	// Security: Prevents injection of null bytes, control characters, or Unicode that could cause issues
	validCharsPattern := regexp.MustCompile(`^[A-Za-z0-9\-._~]+$`)
	if !validCharsPattern.MatchString(codeVerifier) {
		h.logger.Warn("code_verifier contains invalid characters",
			"client_id", clientID,
			"length", len(codeVerifier))
		return ErrInvalidRequest("code_verifier contains invalid characters (RFC 7636: must be [A-Za-z0-9-._~])")
	}

	// Verify code_verifier against code_challenge
	var computedChallenge string
	if authCode.CodeChallengeMethod == "S256" {
		hash := sha256.Sum256([]byte(codeVerifier))
		computedChallenge = base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hash[:])
	} else {
		computedChallenge = codeVerifier
	}

	if computedChallenge != authCode.CodeChallenge {
		h.logger.Warn("PKCE verification failed", "client_id", clientID)
		return ErrInvalidGrant("Invalid code_verifier")
	}

	return nil
}

// authenticateClient validates client credentials
func (h *Handler) authenticateClient(r *http.Request, clientID string) (*RegisteredClient, *OAuthError) {
	client, err := h.clientStore.GetClient(clientID)
	if err != nil {
		h.logger.Error("Failed to get client", "client_id", clientID, "error", err)
		return nil, ErrInvalidClient("Invalid client")
	}

	if client.TokenEndpointAuthMethod == "none" {
		// Public client - no secret authentication, PKCE provides security
		h.logger.Info("Public client authentication (PKCE required)",
			"client_id", clientID,
			"client_name", client.ClientName)
		return client, nil
	}

	// Confidential client - validate client secret
	clientSecret := r.FormValue("client_secret")
	if clientSecret == "" {
		// Try Basic Auth
		username, password, ok := r.BasicAuth()
		if !ok || username != clientID {
			return nil, ErrInvalidClient("Client authentication required")
		}
		clientSecret = password
	}

	if err := h.clientStore.ValidateClientSecret(clientID, clientSecret); err != nil {
		h.logger.Warn("Client authentication failed", "client_id", clientID)
		return nil, ErrInvalidClient("Client authentication failed")
	}

	return client, nil
}

// ensureFreshGoogleToken ensures the Google token is fresh, refreshing if needed
func (h *Handler) ensureFreshGoogleToken(ctx context.Context, authCode *AuthorizationCode) (*oauth2.Token, *OAuthError) {
	// Build Google token from authorization code
	googleToken := &oauth2.Token{
		AccessToken:  authCode.GoogleAccessToken,
		RefreshToken: authCode.GoogleRefreshToken,
		Expiry:       time.Unix(authCode.GoogleTokenExpiry, 0),
	}

	// Calculate token expiry
	expiresIn := authCode.GoogleTokenExpiry - time.Now().Unix()

	// If token is expired or expiring very soon (< 60 seconds), try to refresh
	if expiresIn < TokenExpiringThreshold {
		if h.CanRefreshTokens() && authCode.GoogleRefreshToken != "" {
			h.logger.Info("Google token expired or expiring soon, attempting refresh",
				"email", authCode.UserEmail,
				"expires_in", expiresIn)

			// Attempt immediate refresh
			newToken, refreshErr := refreshGoogleToken(ctx, googleToken, h.googleConfig, h.httpClient)
			if refreshErr == nil {
				// Successfully refreshed - use the new token
				h.logger.Info("Google token refreshed during code exchange",
					"email", authCode.UserEmail)
				return newToken, nil
			}

			// Refresh failed - authorization code is too old
			h.logger.Warn("Failed to refresh expired token during code exchange",
				"email", authCode.UserEmail,
				"error", refreshErr)
			return nil, ErrInvalidGrant("Authorization code expired and token refresh failed. Please re-authenticate.")
		}

		// Can't refresh - authorization code is too old
		h.logger.Warn("Authorization code expired and refresh not available",
			"email", authCode.UserEmail,
			"expires_in", expiresIn)
		return nil, ErrInvalidGrant("Authorization code expired. Please re-authenticate.")
	}

	return googleToken, nil
}

// storeTokens stores the Google token and creates the access token mapping
func (h *Handler) storeTokens(authCode *AuthorizationCode, googleToken *oauth2.Token, accessToken string) *OAuthError {
	// Store the Google token for this user so we can use it to access Google APIs
	if err := h.store.SaveGoogleToken(authCode.UserEmail, googleToken); err != nil {
		h.logger.Error("Failed to store Google token", "error", err)
		return ErrServerError("Failed to store token")
	}

	// Map the access token to the user's Google token
	// We use the access token as the key so when requests come in with the Bearer token,
	// we can look up the associated Google token
	if err := h.store.SaveGoogleToken(accessToken, googleToken); err != nil {
		h.logger.Error("Failed to map access token", "error", err)
		return ErrServerError("Failed to store token")
	}

	return nil
}

// issueRefreshToken generates and stores a refresh token if available
func (h *Handler) issueRefreshToken(authCode *AuthorizationCode) (string, error) {
	if authCode.GoogleRefreshToken == "" {
		return "", nil // No refresh token available
	}

	// Generate refresh token
	refreshToken, err := generateSecureToken(RefreshTokenLength)
	if err != nil {
		return "", err
	}

	// Calculate refresh token expiry
	refreshTokenExpiresAt := time.Now().Add(h.config.Security.RefreshTokenTTL).Unix()

	// Store refresh token mapping to user email with expiry
	if err := h.store.SaveRefreshToken(refreshToken, authCode.UserEmail, refreshTokenExpiresAt); err != nil {
		h.logger.Warn("Failed to store refresh token",
			"email", authCode.UserEmail,
			"error", err)
		return "", err
	}

	h.logger.Info("Issued refresh token",
		"email", authCode.UserEmail,
		"expires_at", time.Unix(refreshTokenExpiresAt, 0),
		"ttl", h.config.Security.RefreshTokenTTL)

	return refreshToken, nil
}
