package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/internal/testutil"
	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

// captureLogger creates a logger that writes to a buffer for testing
func captureLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	return logger, &buf
}

// containsAuditEvent checks if log output contains an audit event of given type
func containsAuditEvent(logOutput, eventType string) bool {
	return strings.Contains(logOutput, "security_audit") && strings.Contains(logOutput, eventType)
}

// containsAuthFailure checks if log output contains an auth failure with given reason
func containsAuthFailure(logOutput, reason string) bool {
	return strings.Contains(logOutput, "security_audit") &&
		strings.Contains(logOutput, "auth_failure") &&
		strings.Contains(logOutput, reason)
}

// TestServer_AuditLoggingClientIDMismatch tests audit logging for client ID mismatch
// P1: Security monitoring
func TestServer_AuditLoggingClientIDMismatch(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()
	logger, logBuf := captureLogger()

	config := &Config{
		Issuer: "https://auth.example.com",
	}

	srv, err := New(provider, store, store, store, config, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Set auditor with captured logger
	auditor := security.NewAuditor(logger, true)
	srv.SetAuditor(auditor)

	// Register a client
	client, _, err := srv.RegisterClient(ctx,
		"Test Client",
		ClientTypeConfidential,
		"", // tokenEndpointAuthMethod
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}
	clientID := client.ClientID

	// Generate PKCE
	codeVerifier := testutil.GenerateRandomString(50)
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	// Get authorization code
	clientState := testutil.GenerateRandomString(43)
	_, err = srv.StartAuthorizationFlow(ctx,
		clientID,
		"https://example.com/callback",
		"openid email",
		"", // resource parameter (optional)
		codeChallenge,
		PKCEMethodS256,
		clientState,
	)
	if err != nil {
		t.Fatalf("StartAuthorizationFlow() error = %v", err)
	}

	authState, err := store.GetAuthorizationState(ctx, clientState)
	if err != nil {
		t.Fatalf("GetAuthorizationState() error = %v", err)
	}

	authCodeObj, _, err := srv.HandleProviderCallback(
		context.Background(),
		authState.ProviderState,
		"provider-code-"+testutil.GenerateRandomString(10),
	)
	if err != nil {
		t.Fatalf("HandleProviderCallback() error = %v", err)
	}

	validCode := authCodeObj.Code

	// Attempt to exchange with WRONG client ID
	wrongClientID := "wrong-client-id"
	_, _, err = srv.ExchangeAuthorizationCode(
		context.Background(),
		validCode,
		wrongClientID,
		"https://example.com/callback",
		"", // resource parameter (optional)
		codeVerifier,
	)

	if err == nil {
		t.Fatal("Expected error for client ID mismatch")
	}

	// Verify audit logging in captured output
	logOutput := logBuf.String()
	if !containsAuthFailure(logOutput, "client_id_mismatch") {
		t.Errorf("Expected audit log for client_id_mismatch in output: %s", logOutput)
	}

	t.Log("Audit logging for client ID mismatch test passed")
}

// TestServer_AuditLoggingRedirectURIMismatch tests audit logging for redirect URI mismatch
// P1: Security monitoring
func TestServer_AuditLoggingRedirectURIMismatch(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()
	logger, logBuf := captureLogger()

	config := &Config{
		Issuer: "https://auth.example.com",
	}

	srv, err := New(provider, store, store, store, config, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Set auditor with captured logger
	auditor := security.NewAuditor(logger, true)
	srv.SetAuditor(auditor)

	// Register a client
	client, _, err := srv.RegisterClient(ctx,
		"Test Client",
		ClientTypeConfidential,
		"", // tokenEndpointAuthMethod
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}
	clientID := client.ClientID

	// Generate PKCE
	codeVerifier := testutil.GenerateRandomString(50)
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	// Get authorization code
	clientState := testutil.GenerateRandomString(43)
	_, err = srv.StartAuthorizationFlow(ctx,
		clientID,
		"https://example.com/callback",
		"openid email",
		"", // resource parameter (optional)
		codeChallenge,
		PKCEMethodS256,
		clientState,
	)
	if err != nil {
		t.Fatalf("StartAuthorizationFlow() error = %v", err)
	}

	authState, err := store.GetAuthorizationState(ctx, clientState)
	if err != nil {
		t.Fatalf("GetAuthorizationState() error = %v", err)
	}

	authCodeObj, _, err := srv.HandleProviderCallback(
		context.Background(),
		authState.ProviderState,
		"provider-code-"+testutil.GenerateRandomString(10),
	)
	if err != nil {
		t.Fatalf("HandleProviderCallback() error = %v", err)
	}

	validCode := authCodeObj.Code

	// Attempt to exchange with WRONG redirect URI
	wrongRedirectURI := "https://evil.com/callback"
	_, _, err = srv.ExchangeAuthorizationCode(
		context.Background(),
		validCode,
		clientID,
		wrongRedirectURI,
		"", // resource parameter (optional)
		codeVerifier,
	)

	if err == nil {
		t.Fatal("Expected error for redirect URI mismatch")
	}

	// Verify audit logging in captured output
	logOutput := logBuf.String()
	if !containsAuthFailure(logOutput, "redirect_uri_mismatch") {
		t.Errorf("Expected audit log for redirect_uri_mismatch in output: %s", logOutput)
	}

	t.Log("Audit logging for redirect URI mismatch test passed")
}

// TestServer_AuditEventProviderRevocationThresholdExceeded tests audit event structure
// P1: Security monitoring
func TestServer_AuditEventProviderRevocationThresholdExceeded(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()
	logger, logBuf := captureLogger()

	config := &Config{
		Issuer:                             "https://auth.example.com",
		ProviderRevocationMaxRetries:       0,
		ProviderRevocationFailureThreshold: 0.5,
	}

	srv, err := New(provider, store, store, store, config, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Set auditor with captured logger
	auditor := security.NewAuditor(logger, true)
	srv.SetAuditor(auditor)

	userID := "test_user_audit"
	clientID := "test_client_audit"

	// Configure provider to fail ALL attempts (100% failure)
	provider.RevokeTokenFunc = func(ctx context.Context, token string) error {
		return fmt.Errorf("provider revocation failed")
	}

	// Save 3 test tokens
	for i := 0; i < 3; i++ {
		tokenID := fmt.Sprintf("access_token_%d", i)
		token := &oauth2.Token{
			AccessToken: tokenID,
			Expiry:      time.Now().Add(time.Hour),
			TokenType:   "Bearer",
		}
		if err := store.SaveToken(ctx, tokenID, token); err != nil {
			t.Fatalf("SaveToken() error = %v", err)
		}
		if err := store.SaveTokenMetadata(tokenID, userID, clientID, "access"); err != nil {
			t.Fatalf("SaveTokenMetadata() error = %v", err)
		}
	}

	// Revoke - should fail and log audit event
	err = srv.RevokeAllTokensForUserClient(context.Background(), userID, clientID)
	if err == nil {
		t.Fatal("Expected error when threshold exceeded")
	}

	// Verify audit event in captured output
	logOutput := logBuf.String()
	if !containsAuditEvent(logOutput, "provider_revocation_threshold_exceeded") {
		t.Errorf("Expected provider_revocation_threshold_exceeded audit event in output: %s", logOutput)
	}

	// Verify critical fields are logged
	if !strings.Contains(logOutput, "critical") {
		t.Error("Expected 'critical' severity in audit log")
	}

	if !strings.Contains(logOutput, "failure_rate") {
		t.Error("Expected 'failure_rate' in audit log")
	}

	if !strings.Contains(logOutput, "threshold") {
		t.Error("Expected 'threshold' in audit log")
	}

	t.Log("Provider revocation threshold exceeded audit event test passed")
}

// TestServer_AuditEventProviderRevocationCompleteFailure tests 100% failure audit event
// P1: Security monitoring
func TestServer_AuditEventProviderRevocationCompleteFailure(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()
	logger, logBuf := captureLogger()

	config := &Config{
		Issuer:                       "https://auth.example.com",
		ProviderRevocationMaxRetries: 0,
	}

	srv, err := New(provider, store, store, store, config, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Set auditor with captured logger
	auditor := security.NewAuditor(logger, true)
	srv.SetAuditor(auditor)

	userID := "test_user_complete_fail"
	clientID := "test_client_complete_fail"

	// Configure provider to fail ALL attempts (100% failure)
	provider.RevokeTokenFunc = func(ctx context.Context, token string) error {
		return fmt.Errorf("provider revocation failed")
	}

	// Save 2 test tokens
	for i := 0; i < 2; i++ {
		tokenID := fmt.Sprintf("access_token_%d", i)
		token := &oauth2.Token{
			AccessToken: tokenID,
			Expiry:      time.Now().Add(time.Hour),
			TokenType:   "Bearer",
		}
		if err := store.SaveToken(ctx, tokenID, token); err != nil {
			t.Fatalf("SaveToken() error = %v", err)
		}
		if err := store.SaveTokenMetadata(tokenID, userID, clientID, "access"); err != nil {
			t.Fatalf("SaveTokenMetadata() error = %v", err)
		}
	}

	// Revoke - should fail completely
	err = srv.RevokeAllTokensForUserClient(context.Background(), userID, clientID)
	if err == nil {
		t.Fatal("Expected error when all provider revocations fail")
	}

	// Verify audit event in captured output
	logOutput := logBuf.String()
	hasProviderRevocationEvent := strings.Contains(logOutput, "security_audit") &&
		strings.Contains(logOutput, "provider_revocation")

	if !hasProviderRevocationEvent {
		t.Errorf("Expected provider revocation audit event in output: %s", logOutput)
	}

	// Verify critical severity
	if !strings.Contains(logOutput, "critical") {
		t.Error("Expected 'critical' severity in audit log")
	}

	t.Log("Provider revocation complete failure audit event test passed")
}

// TestServer_AuditEventAuthorizationCodeReuse tests audit logging for code reuse
// P1: Security monitoring
func TestServer_AuditEventAuthorizationCodeReuse(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	defer store.Stop()

	provider := mock.NewMockProvider()
	logger, logBuf := captureLogger()

	config := &Config{
		Issuer: "https://auth.example.com",
	}

	srv, err := New(provider, store, store, store, config, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Set auditor with captured logger
	auditor := security.NewAuditor(logger, true)
	srv.SetAuditor(auditor)

	// Register a client
	client, _, err := srv.RegisterClient(ctx,
		"Test Client",
		ClientTypeConfidential,
		"", // tokenEndpointAuthMethod
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}
	clientID := client.ClientID

	// Generate PKCE
	codeVerifier := testutil.GenerateRandomString(50)
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	// Get authorization code
	clientState := testutil.GenerateRandomString(43)
	_, err = srv.StartAuthorizationFlow(ctx,
		clientID,
		"https://example.com/callback",
		"openid email",
		"", // resource parameter (optional)
		codeChallenge,
		PKCEMethodS256,
		clientState,
	)
	if err != nil {
		t.Fatalf("StartAuthorizationFlow() error = %v", err)
	}

	authState, err := store.GetAuthorizationState(ctx, clientState)
	if err != nil {
		t.Fatalf("GetAuthorizationState() error = %v", err)
	}

	authCodeObj, _, err := srv.HandleProviderCallback(
		context.Background(),
		authState.ProviderState,
		"provider-code-"+testutil.GenerateRandomString(10),
	)
	if err != nil {
		t.Fatalf("HandleProviderCallback() error = %v", err)
	}

	authCode := authCodeObj.Code

	// First exchange should succeed
	_, _, err = srv.ExchangeAuthorizationCode(
		context.Background(),
		authCode,
		clientID,
		"https://example.com/callback",
		"", // resource parameter (optional)
		codeVerifier,
	)
	if err != nil {
		t.Fatalf("First ExchangeAuthorizationCode() error = %v", err)
	}

	// Second exchange should detect reuse
	_, _, err = srv.ExchangeAuthorizationCode(
		context.Background(),
		authCode,
		clientID,
		"https://example.com/callback",
		"", // resource parameter (optional)
		codeVerifier,
	)
	if err == nil {
		t.Fatal("Second exchange should fail (code reuse)")
	}

	// Verify audit event in captured output
	logOutput := logBuf.String()
	if !containsAuditEvent(logOutput, "authorization_code_reuse_detected") {
		t.Errorf("Expected authorization_code_reuse_detected audit event in output: %s", logOutput)
	}

	// Verify critical fields
	if !strings.Contains(logOutput, "critical") {
		t.Error("Expected 'critical' severity in audit log")
	}

	if !strings.Contains(logOutput, "revoked") {
		t.Error("Expected 'revoked' action in audit log")
	}

	// Verify auth failure was logged
	if !containsAuthFailure(logOutput, "authorization_code_reuse") {
		t.Error("Expected auth failure log for authorization_code_reuse")
	}

	t.Log("Authorization code reuse audit event test passed")
}
