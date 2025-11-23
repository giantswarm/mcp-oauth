package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// contextKey is the type for context keys
type contextKey string

const (
	// userContextKey is the key for storing the user info in the request context
	userContextKey contextKey = "oauth_user"

	// tokenContextKey is the key for storing the Google token in the request context
	tokenContextKey contextKey = "google_token"
)

// ValidateGoogleToken is middleware that validates Google OAuth tokens
// It validates the token with Google's userinfo endpoint and stores user info in context
func (h *Handler) ValidateGoogleToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			// Return 401 with WWW-Authenticate header pointing to resource metadata
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(
				`Bearer realm="%s", resource_metadata="/.well-known/oauth-protected-resource"`,
				h.config.Resource,
			))
			h.writeUnauthorizedError(w, "missing_token", "Missing Authorization header")
			return
		}

		// Check for Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(
				`Bearer realm="%s", resource_metadata="/.well-known/oauth-protected-resource", error="invalid_token", error_description="Invalid Authorization header format"`,
				h.config.Resource,
			))
			h.writeUnauthorizedError(w, "invalid_token", "Invalid Authorization header format")
			return
		}

		accessToken := parts[1]

		// Try to resolve the token (could be access token or Google token)
		var userEmail string
		var googleToken *oauth2.Token
		var userInfo *GoogleUserInfo

		// First, try to look up the token as an access token
		cachedToken, err := h.store.GetGoogleToken(accessToken)
		if err == nil && cachedToken != nil {
			// This is an access token - we have the mapped Google token
			h.logger.Debug("Found access token mapping", "token_prefix", accessToken[:min(8, len(accessToken))]+"...")

			// Security: Check if cached token is expired and can't be refreshed
			// If token is expired without refresh capability, fall through to direct validation
			// (which will fail appropriately with actionable error message)
			if !cachedToken.Expiry.IsZero() && cachedToken.Expiry.Before(time.Now()) && cachedToken.RefreshToken == "" {
				h.logger.Warn("Cached token expired without refresh token",
					"token_prefix", accessToken[:min(8, len(accessToken))]+"...")
				// Fall through to direct validation (will fail appropriately)
			} else {
				googleToken = cachedToken

				// Validate the Google token to get user info
				userInfo, err = h.getUserInfoFromGoogle(r.Context(), googleToken)
				if err != nil {
					errorDesc := getActionableErrorMessage(err)
					h.logger.Warn("Google token validation failed for access token",
						"error", err,
						"error_description", errorDesc)
					w.Header().Set("WWW-Authenticate", fmt.Sprintf(
						`Bearer realm="%s", resource_metadata="/.well-known/oauth-protected-resource", error="invalid_token", error_description="%s"`,
						h.config.Resource,
						errorDesc,
					))
					h.writeUnauthorizedError(w, "invalid_token", errorDesc)
					return
				}
				userEmail = userInfo.Email
			}
		}

		// If we didn't get a valid token from cache, try direct validation
		if googleToken == nil {
			// Not an access token - try to validate directly with Google
			// This provides backward compatibility for clients that have Google tokens
			h.logger.Debug("Validating token directly with Google")
			googleToken = &oauth2.Token{
				AccessToken: accessToken,
				TokenType:   "Bearer",
			}

			// Validate with Google
			userInfo, err = h.getUserInfoFromGoogle(r.Context(), googleToken)
			if err != nil {
				errorDesc := getActionableErrorMessage(err)
				h.logger.Warn("Token validation failed",
					"error", err,
					"error_description", errorDesc)
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(
					`Bearer realm="%s", resource_metadata="/.well-known/oauth-protected-resource", error="invalid_token", error_description="%s"`,
					h.config.Resource,
					errorDesc,
				))
				h.writeUnauthorizedError(w, "invalid_token", errorDesc)
				return
			}
			userEmail = userInfo.Email
		}

		h.logger.Debug("Token validated", "email", userEmail)

		// Apply per-user rate limiting (after authentication)
		if h.userRateLimiter != nil {
			if !h.userRateLimiter.Allow(userEmail) {
				h.logger.Warn("User rate limit exceeded",
					"email", userEmail,
					"rate_limit_type", "per_user")
				w.Header().Set("Retry-After", "1")
				h.writeUnauthorizedError(w, "rate_limit_exceeded",
					fmt.Sprintf("Rate limit exceeded for user %s. Please try again later.", userEmail))
				return
			}
		}

		// Check if Google token needs refresh
		if h.CanRefreshTokens() && googleToken != nil {
			// Check if cached token needs refresh (expires within TokenRefreshThreshold)
			if isTokenExpired(googleToken, TokenRefreshThreshold) && googleToken.RefreshToken != "" {
				h.logger.Info("Token expiring soon, attempting refresh", "email", userEmail)
				// Attempt to refresh the token
				newToken, refreshErr := refreshGoogleToken(r.Context(), googleToken, h.googleConfig, h.httpClient)
				if refreshErr == nil {
					// Successfully refreshed - use the new token
					h.logger.Info("Token refreshed successfully", "email", userEmail)
					googleToken = newToken
					// Save refreshed Google token
					if saveErr := h.store.SaveGoogleToken(userEmail, newToken); saveErr != nil {
						h.logger.Warn("Failed to save refreshed token",
							"email", userEmail,
							"error", saveErr)
					}
					// Also update the access token mapping
					if saveErr := h.store.SaveGoogleToken(accessToken, newToken); saveErr != nil {
						h.logger.Warn("Failed to update token mapping",
							"error", saveErr)
					}
				} else {
					// Refresh failed - log but continue with existing token
					h.logger.Warn("Failed to refresh token",
						"email", userEmail,
						"error", refreshErr)
				}
			}
		}

		// Store user info and Google token in context
		ctx := context.WithValue(r.Context(), userContextKey, userInfo)
		ctx = context.WithValue(ctx, tokenContextKey, googleToken)

		// Save the Google token for this user so we can use it to access Google APIs
		// Store by BOTH email and access token for lookup flexibility
		if err := h.store.SaveGoogleToken(userEmail, googleToken); err != nil {
			// Log but don't fail - we can still process the request
			h.logger.Warn("Failed to save Google token by email",
				"email", userEmail,
				"error", err)
		}

		// IMPORTANT: Also store by access token so the TokenProvider can find it
		// The mcp-go library doesn't pass HTTP context to tool handlers, so we can't
		// rely on context.WithValue. Instead, we store the token by the access token
		// and modify the TokenProvider to look it up using "default" -> access token mapping
		if err := h.store.SaveGoogleToken(accessToken, googleToken); err != nil {
			h.logger.Warn("Failed to save Google token by access token",
				"error", err)
		}

		h.logger.Info("Authenticated user for MCP session",
			"email", userEmail,
			"token_prefix", accessToken[:min(10, len(accessToken))])

		// Call next handler
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ValidateGoogleTokenFunc is a function-based middleware that validates Google OAuth tokens
func (h *Handler) ValidateGoogleTokenFunc(next http.HandlerFunc) http.HandlerFunc {
	return h.ValidateGoogleToken(next).ServeHTTP
}

// OptionalGoogleToken is middleware that optionally validates Google OAuth tokens
// If a token is present, it validates it; if not, it continues without authentication
func (h *Handler) OptionalGoogleToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			// No token provided, continue without authentication
			next.ServeHTTP(w, r)
			return
		}

		// Token provided, validate it
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			h.writeUnauthorizedError(w, "invalid_token", "Invalid Authorization header format")
			return
		}

		accessToken := parts[1]

		// Create OAuth2 token
		token := &oauth2.Token{
			AccessToken: accessToken,
			TokenType:   "Bearer",
		}

		// Validate token by calling Google's userinfo endpoint
		userInfo, err := h.getUserInfoFromGoogle(r.Context(), token)
		if err != nil {
			h.writeUnauthorizedError(w, "invalid_token", fmt.Sprintf("Token validation failed: %v", err))
			return
		}

		// Store user info and token in context
		ctx := context.WithValue(r.Context(), userContextKey, userInfo)
		ctx = context.WithValue(ctx, tokenContextKey, token)

		// Save the token for this user
		if err := h.store.SaveGoogleToken(userInfo.Email, token); err != nil {
			h.logger.Warn("Failed to save Google token",
				"email", userInfo.Email,
				"error", err)
		}

		// Call next handler
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// getUserInfoFromGoogle validates a token by calling Google's userinfo endpoint
func (h *Handler) getUserInfoFromGoogle(ctx context.Context, token *oauth2.Token) (*GoogleUserInfo, error) {
	// Create HTTP client with the token
	client := oauth2.NewClient(ctx, oauth2.StaticTokenSource(token))

	// Call Google's userinfo endpoint
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo request failed with status %d", resp.StatusCode)
	}

	// Parse user info
	var userInfo GoogleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	return &userInfo, nil
}

// GetUserFromContext retrieves the Google user info from the request context.
// Returns the user info and true if found, nil and false otherwise.
//
// This is typically used within HTTP handlers that are wrapped with
// ValidateGoogleToken middleware to access authenticated user information.
//
// Example:
//
//	func handler(w http.ResponseWriter, r *http.Request) {
//	    userInfo, ok := oauth.GetUserFromContext(r.Context())
//	    if !ok {
//	        http.Error(w, "Unauthorized", http.StatusUnauthorized)
//	        return
//	    }
//	    fmt.Fprintf(w, "Hello, %s!", userInfo.Email)
//	}
func GetUserFromContext(ctx context.Context) (*GoogleUserInfo, bool) {
	userInfo, ok := ctx.Value(userContextKey).(*GoogleUserInfo)
	return userInfo, ok
}

// UserInfoFromContext is an alias for GetUserFromContext for better naming consistency.
// It retrieves the Google user info from the request context.
func UserInfoFromContext(ctx context.Context) (*GoogleUserInfo, bool) {
	return GetUserFromContext(ctx)
}

// GetGoogleTokenFromContext retrieves the Google OAuth token from the request context.
// Returns the token and true if found, nil and false otherwise.
//
// This token can be used to make authenticated requests to Google APIs on behalf
// of the user.
//
// Example:
//
//	func handler(w http.ResponseWriter, r *http.Request) {
//	    token, ok := oauth.GetGoogleTokenFromContext(r.Context())
//	    if !ok {
//	        http.Error(w, "Unauthorized", http.StatusUnauthorized)
//	        return
//	    }
//	    // Use token to call Google APIs
//	    client := oauth2.NewClient(r.Context(), oauth2.StaticTokenSource(token))
//	    // ...
//	}
func GetGoogleTokenFromContext(ctx context.Context) (*oauth2.Token, bool) {
	token, ok := ctx.Value(tokenContextKey).(*oauth2.Token)
	return token, ok
}

// AccessTokenFromContext is an alias for GetGoogleTokenFromContext.
func AccessTokenFromContext(ctx context.Context) (*oauth2.Token, bool) {
	return GetGoogleTokenFromContext(ctx)
}

// writeUnauthorizedError writes an OAuth error response with 401 status
func (h *Handler) writeUnauthorizedError(w http.ResponseWriter, errorCode, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(ErrorResponse{
		Error:            errorCode,
		ErrorDescription: description,
	})
}

// getActionableErrorMessage converts technical errors into user-friendly, actionable messages
func getActionableErrorMessage(err error) string {
	errStr := err.Error()

	// Check for common error patterns and provide actionable guidance
	if strings.Contains(errStr, "401") || strings.Contains(errStr, "Unauthorized") {
		return "Google token is invalid or expired. Please re-authenticate through your MCP client to continue."
	}

	if strings.Contains(errStr, "403") || strings.Contains(errStr, "Forbidden") {
		return "Access denied by Google. Please ensure your token has the required scopes and re-authenticate through your MCP client."
	}

	if strings.Contains(errStr, "network") || strings.Contains(errStr, "connection") ||
		strings.Contains(errStr, "timeout") || strings.Contains(errStr, "dial") {
		return "Unable to verify token with Google due to network issues. Please try again in a moment."
	}

	if strings.Contains(errStr, "429") || strings.Contains(errStr, "rate limit") {
		return "Google API rate limit exceeded. Please wait a moment and try again."
	}

	if strings.Contains(errStr, "500") || strings.Contains(errStr, "502") ||
		strings.Contains(errStr, "503") || strings.Contains(errStr, "504") {
		return "Google authentication service is temporarily unavailable. Please try again in a few minutes."
	}

	// Default message with error details
	return fmt.Sprintf("Token validation failed: %v. Please re-authenticate through your MCP client.", err)
}

// CacheGoogleToken caches a Google token for future use
// This can be called by endpoints that receive tokens through other means
func (h *Handler) CacheGoogleToken(email string, token *oauth2.Token) error {
	return h.store.SaveGoogleToken(email, token)
}

// GetCachedGoogleToken retrieves a cached Google token for a user
func (h *Handler) GetCachedGoogleToken(email string) (*oauth2.Token, error) {
	return h.store.GetGoogleToken(email)
}
