package oauthconfig_test

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/giantswarm/mcp-oauth/oauthconfig"
)

// validKeyB64 is a 32-byte key encoded as base64, the shape
// security.KeyFromBase64 requires for both ENCRYPTION_KEY and
// SESSION_ID_HMAC_KEY.
var validKeyB64 = base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))

// validKeyHex is the same 32-byte key encoded as hex — the form produced by
// `openssl rand -hex 32`. NewEncryptorFromEnv accepts both encodings.
var validKeyHex = hex.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))

// writeSecretFile writes v to a temp file and returns its path. The file is
// cleaned up automatically at test end via t.TempDir.
func writeSecretFile(t *testing.T, v string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "secret")
	if err := os.WriteFile(p, []byte(v), 0o600); err != nil {
		t.Fatalf("write secret file: %v", err)
	}
	return p
}

// setRequired clears every OAUTH_* var this package touches so tests inherit a
// clean baseline instead of whatever the CI job's shell left behind. Each test
// then calls t.Setenv for the vars it actually exercises.
func setRequired(t *testing.T, issuer string) {
	t.Helper()
	for _, v := range []string{
		"OAUTH_ISSUER",
		"OAUTH_ALLOW_INSECURE_HTTP",
		"OAUTH_ALLOW_PUBLIC_CLIENT_REGISTRATION",
		"OAUTH_TRUST_PROXY",
		"OAUTH_ACCESS_TOKEN_TTL",
		"OAUTH_REFRESH_TOKEN_TTL",
		"OAUTH_MAX_CLIENTS_PER_IP",
		"OAUTH_REGISTRATION_ACCESS_TOKEN",
		"OAUTH_REGISTRATION_ACCESS_TOKEN_FILE",
		"OAUTH_ENCRYPTION_KEY",
		"OAUTH_ENCRYPTION_KEY_FILE",
		"OAUTH_SESSION_ID_HMAC_KEY",
		"OAUTH_SESSION_ID_HMAC_KEY_FILE",
		"OAUTH_TRUSTED_AUDIENCES",
		"OAUTH_ALLOW_LOCALHOST_REDIRECT_URIS",
		"OAUTH_TRUSTED_REDIRECT_SCHEMES",
	} {
		t.Setenv(v, "")
	}
	if issuer != "" {
		t.Setenv("OAUTH_ISSUER", issuer)
	}
}

func TestFromEnv_HappyPath(t *testing.T) {
	setRequired(t, "https://auth.example")
	t.Setenv("OAUTH_ALLOW_PUBLIC_CLIENT_REGISTRATION", "true")
	t.Setenv("OAUTH_TRUST_PROXY", "true")
	t.Setenv("OAUTH_ACCESS_TOKEN_TTL", "1h")
	t.Setenv("OAUTH_REFRESH_TOKEN_TTL", "24h")
	t.Setenv("OAUTH_MAX_CLIENTS_PER_IP", "5")
	t.Setenv("OAUTH_REGISTRATION_ACCESS_TOKEN", "reg-token")
	t.Setenv("OAUTH_ENCRYPTION_KEY", validKeyB64)
	t.Setenv("OAUTH_SESSION_ID_HMAC_KEY", validKeyB64)
	t.Setenv("OAUTH_TRUSTED_AUDIENCES", "muster-client, second-aud ,")
	t.Setenv("OAUTH_ALLOW_LOCALHOST_REDIRECT_URIS", "true")
	t.Setenv("OAUTH_TRUSTED_REDIRECT_SCHEMES", "cursor, vscode ,, vscode-insiders")

	cfg, err := oauthconfig.FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.Issuer != "https://auth.example" {
		t.Errorf("Issuer = %q", cfg.Issuer)
	}
	if !cfg.AllowPublicClientRegistration {
		t.Errorf("AllowPublicClientRegistration = false")
	}
	if !cfg.TrustProxy {
		t.Errorf("TrustProxy = false")
	}
	if cfg.AccessTokenTTL != 3600 {
		t.Errorf("AccessTokenTTL = %d, want 3600", cfg.AccessTokenTTL)
	}
	if cfg.RefreshTokenTTL != 86400 {
		t.Errorf("RefreshTokenTTL = %d, want 86400", cfg.RefreshTokenTTL)
	}
	if cfg.MaxClientsPerIP != 5 {
		t.Errorf("MaxClientsPerIP = %d, want 5", cfg.MaxClientsPerIP)
	}
	if cfg.RegistrationAccessToken != "reg-token" {
		t.Errorf("RegistrationAccessToken = %q", cfg.RegistrationAccessToken)
	}
	if len(cfg.SessionIDHMACKey) != 32 {
		t.Errorf("SessionIDHMACKey length = %d, want 32", len(cfg.SessionIDHMACKey))
	}
	want := []string{"muster-client", "second-aud"}
	if !reflect.DeepEqual(cfg.TrustedAudiences, want) {
		t.Errorf("TrustedAudiences = %v, want %v", cfg.TrustedAudiences, want)
	}
	if !cfg.AllowLocalhostRedirectURIs {
		t.Errorf("AllowLocalhostRedirectURIs = false")
	}
	wantSchemes := []string{"cursor", "vscode", "vscode-insiders"}
	if !reflect.DeepEqual(cfg.TrustedPublicRegistrationSchemes, wantSchemes) {
		t.Errorf("TrustedPublicRegistrationSchemes = %v, want %v", cfg.TrustedPublicRegistrationSchemes, wantSchemes)
	}
}

func TestFromEnv_MissingIssuer(t *testing.T) {
	setRequired(t, "")
	_, err := oauthconfig.FromEnv()
	if err == nil || !strings.Contains(err.Error(), "OAUTH_ISSUER") {
		t.Fatalf("expected OAUTH_ISSUER error, got %v", err)
	}
}

func TestFromEnv_InsecureHTTPGate(t *testing.T) {
	t.Run("refused-by-default", func(t *testing.T) {
		setRequired(t, "http://auth.example")
		_, err := oauthconfig.FromEnv()
		if err == nil || !strings.Contains(err.Error(), "ALLOW_INSECURE_HTTP") {
			t.Fatalf("expected insecure-HTTP refusal, got %v", err)
		}
	})

	t.Run("allowed-with-opt-in", func(t *testing.T) {
		setRequired(t, "http://auth.example")
		t.Setenv("OAUTH_ALLOW_INSECURE_HTTP", "true")
		cfg, err := oauthconfig.FromEnv()
		if err != nil {
			t.Fatalf("FromEnv: %v", err)
		}
		if !cfg.AllowInsecureHTTP {
			t.Error("AllowInsecureHTTP should be true")
		}
	})

	// RFC 3986 §3.1: URL schemes are case-insensitive. A mixed-case scheme
	// must still trip the gate; otherwise operators silently bypass the check
	// with "HTTP://". An earlier iteration of this loader used
	// strings.HasPrefix(issuer, "http://") and missed these cases.
	t.Run("refused-for-uppercase-scheme", func(t *testing.T) {
		setRequired(t, "HTTP://auth.example")
		_, err := oauthconfig.FromEnv()
		if err == nil || !strings.Contains(err.Error(), "ALLOW_INSECURE_HTTP") {
			t.Fatalf("expected insecure-HTTP refusal for HTTP://, got %v", err)
		}
	})

	t.Run("refused-for-mixedcase-scheme", func(t *testing.T) {
		setRequired(t, "Http://auth.example")
		_, err := oauthconfig.FromEnv()
		if err == nil || !strings.Contains(err.Error(), "ALLOW_INSECURE_HTTP") {
			t.Fatalf("expected insecure-HTTP refusal for Http://, got %v", err)
		}
	})

	t.Run("https-uppercase-accepted", func(t *testing.T) {
		setRequired(t, "HTTPS://auth.example")
		if _, err := oauthconfig.FromEnv(); err != nil {
			t.Fatalf("HTTPS uppercase should be accepted, got %v", err)
		}
	})

	t.Run("unparseable-url-rejected", func(t *testing.T) {
		setRequired(t, "://broken")
		_, err := oauthconfig.FromEnv()
		if err == nil || !strings.Contains(err.Error(), "valid URL") {
			t.Fatalf("expected URL parse error, got %v", err)
		}
	})
}

// TestFromEnv_LoopbackIssuerException locks down the RFC 8252 loopback
// bypass: http:// is permitted without OAUTH_ALLOW_INSECURE_HTTP when the
// hostname is localhost / 127.0.0.1 / [::1]. Required for local dev loops
// (`http://localhost:5556`) that should NOT need to flip the global insecure
// flag — which would weaken every other http:// check at the same time.
func TestFromEnv_LoopbackIssuerException(t *testing.T) {
	cases := []struct {
		name    string
		issuer  string
		wantErr bool
	}{
		{name: "localhost with port", issuer: "http://localhost:5556"},
		{name: "localhost without port", issuer: "http://localhost"},
		{name: "127.0.0.1 with port", issuer: "http://127.0.0.1:5556"},
		{name: "ipv6 loopback with port", issuer: "http://[::1]:5556"},
		{name: "Localhost mixed case", issuer: "http://Localhost:5556"},
		{name: "https on loopback still fine", issuer: "https://localhost:5556"},
		{name: "non-loopback http rejected", issuer: "http://auth.example", wantErr: true},
		{name: "lookalike 127.0.0.1.evil rejected", issuer: "http://127.0.0.1.evil.com", wantErr: true},
		{name: "lookalike localhost.evil rejected", issuer: "http://localhost.evil.com", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setRequired(t, tc.issuer)
			_, err := oauthconfig.FromEnv()
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "ALLOW_INSECURE_HTTP") {
					t.Fatalf("expected ALLOW_INSECURE_HTTP refusal, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("FromEnv: %v", err)
			}
		})
	}
}

func TestFromEnv_FilePrecedence(t *testing.T) {
	setRequired(t, "https://auth.example")
	t.Setenv("OAUTH_REGISTRATION_ACCESS_TOKEN", "from-env")
	t.Setenv("OAUTH_REGISTRATION_ACCESS_TOKEN_FILE", writeSecretFile(t, "from-file"))

	cfg, err := oauthconfig.FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.RegistrationAccessToken != "from-file" {
		t.Errorf("RegistrationAccessToken = %q, want from-file (FILE precedence)", cfg.RegistrationAccessToken)
	}
}

func TestFromEnv_FileTrimsTrailingNewline(t *testing.T) {
	setRequired(t, "https://auth.example")

	// One trailing newline: trimmed. Multiple: preserve all but the last.
	p := writeSecretFile(t, "secret-token\n\n")
	t.Setenv("OAUTH_REGISTRATION_ACCESS_TOKEN_FILE", p)

	cfg, err := oauthconfig.FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.RegistrationAccessToken != "secret-token\n" {
		t.Errorf("RegistrationAccessToken = %q, want exactly one trailing newline trimmed", cfg.RegistrationAccessToken)
	}
}

func TestFromEnv_FileNotFound(t *testing.T) {
	setRequired(t, "https://auth.example")
	t.Setenv("OAUTH_REGISTRATION_ACCESS_TOKEN_FILE", "/nonexistent/mcp-oauth/secret")
	_, err := oauthconfig.FromEnv()
	if err == nil || !strings.Contains(err.Error(), "REGISTRATION_ACCESS_TOKEN_FILE") {
		t.Fatalf("expected file-not-found error for REGISTRATION_ACCESS_TOKEN_FILE, got %v", err)
	}
}

func TestFromEnv_InvalidBase64(t *testing.T) {
	setRequired(t, "https://auth.example")
	t.Setenv("OAUTH_ENCRYPTION_KEY", "!!!not-base64!!!")
	// FromEnv doesn't decode ENCRYPTION_KEY (that belongs to NewEncryptorFromEnv),
	// so the malformed value should surface there instead. Verify the loader
	// boundary.
	if _, err := oauthconfig.FromEnv(); err != nil {
		t.Fatalf("FromEnv should not touch ENCRYPTION_KEY; got %v", err)
	}
	if _, err := oauthconfig.NewEncryptorFromEnv(); err == nil || !strings.Contains(err.Error(), "ENCRYPTION_KEY") {
		t.Fatalf("NewEncryptorFromEnv should reject malformed base64, got %v", err)
	}
}

func TestFromEnv_InvalidSessionIDHMACKey(t *testing.T) {
	setRequired(t, "https://auth.example")
	t.Setenv("OAUTH_SESSION_ID_HMAC_KEY", "!!!not-base64!!!")
	_, err := oauthconfig.FromEnv()
	if err == nil || !strings.Contains(err.Error(), "SESSION_ID_HMAC_KEY") {
		t.Fatalf("expected SESSION_ID_HMAC_KEY base64 error, got %v", err)
	}
}

func TestFromEnv_BadBool(t *testing.T) {
	setRequired(t, "https://auth.example")
	t.Setenv("OAUTH_TRUST_PROXY", "maybe")
	_, err := oauthconfig.FromEnv()
	if err == nil || !strings.Contains(err.Error(), "TRUST_PROXY") {
		t.Fatalf("expected bool parse error on TRUST_PROXY, got %v", err)
	}
}

func TestFromEnv_BadDuration(t *testing.T) {
	setRequired(t, "https://auth.example")
	t.Setenv("OAUTH_ACCESS_TOKEN_TTL", "not-a-duration")
	_, err := oauthconfig.FromEnv()
	if err == nil || !strings.Contains(err.Error(), "ACCESS_TOKEN_TTL") {
		t.Fatalf("expected duration parse error on ACCESS_TOKEN_TTL, got %v", err)
	}
}

func TestFromEnv_NegativeDuration(t *testing.T) {
	setRequired(t, "https://auth.example")
	t.Setenv("OAUTH_ACCESS_TOKEN_TTL", "-1h")
	_, err := oauthconfig.FromEnv()
	if err == nil || !strings.Contains(err.Error(), "non-negative") {
		t.Fatalf("expected non-negative rejection, got %v", err)
	}
}

func TestFromEnv_BadInt(t *testing.T) {
	setRequired(t, "https://auth.example")
	t.Setenv("OAUTH_MAX_CLIENTS_PER_IP", "12.5")
	_, err := oauthconfig.FromEnv()
	if err == nil || !strings.Contains(err.Error(), "MAX_CLIENTS_PER_IP") {
		t.Fatalf("expected int parse error on MAX_CLIENTS_PER_IP, got %v", err)
	}
}

func TestFromEnvWithPrefix(t *testing.T) {
	// Clear the default prefix so a leaked OAUTH_ISSUER wouldn't accidentally
	// satisfy the test, then set everything under MUSTER_OAUTH_.
	setRequired(t, "")
	t.Setenv("MUSTER_OAUTH_ISSUER", "https://muster.example")
	t.Setenv("MUSTER_OAUTH_TRUSTED_AUDIENCES", "agentcore-runtime")
	t.Setenv("MUSTER_OAUTH_ALLOW_LOCALHOST_REDIRECT_URIS", "true")
	t.Setenv("MUSTER_OAUTH_TRUSTED_REDIRECT_SCHEMES", "cursor")

	cfg, err := oauthconfig.FromEnvWithPrefix("MUSTER_OAUTH_")
	if err != nil {
		t.Fatalf("FromEnvWithPrefix: %v", err)
	}
	if cfg.Issuer != "https://muster.example" {
		t.Errorf("Issuer = %q", cfg.Issuer)
	}
	if want := []string{"agentcore-runtime"}; !reflect.DeepEqual(cfg.TrustedAudiences, want) {
		t.Errorf("TrustedAudiences = %v, want %v", cfg.TrustedAudiences, want)
	}
	if !cfg.AllowLocalhostRedirectURIs {
		t.Errorf("AllowLocalhostRedirectURIs = false")
	}
	if want := []string{"cursor"}; !reflect.DeepEqual(cfg.TrustedPublicRegistrationSchemes, want) {
		t.Errorf("TrustedPublicRegistrationSchemes = %v, want %v", cfg.TrustedPublicRegistrationSchemes, want)
	}
}

func TestNewEncryptorFromEnv(t *testing.T) {
	t.Run("unset-returns-nil", func(t *testing.T) {
		setRequired(t, "")
		enc, err := oauthconfig.NewEncryptorFromEnv()
		if err != nil {
			t.Fatalf("NewEncryptorFromEnv: %v", err)
		}
		if enc != nil {
			t.Error("expected nil Encryptor when ENCRYPTION_KEY unset")
		}
	})

	t.Run("happy-path", func(t *testing.T) {
		setRequired(t, "")
		t.Setenv("OAUTH_ENCRYPTION_KEY", validKeyB64)
		enc, err := oauthconfig.NewEncryptorFromEnv()
		if err != nil {
			t.Fatalf("NewEncryptorFromEnv: %v", err)
		}
		if enc == nil {
			t.Fatal("expected non-nil Encryptor")
		}
	})

	t.Run("file-variant", func(t *testing.T) {
		setRequired(t, "")
		t.Setenv("OAUTH_ENCRYPTION_KEY_FILE", writeSecretFile(t, validKeyB64+"\n"))
		enc, err := oauthconfig.NewEncryptorFromEnv()
		if err != nil {
			t.Fatalf("NewEncryptorFromEnv: %v", err)
		}
		if enc == nil {
			t.Fatal("expected non-nil Encryptor from _FILE variant")
		}
	})

	t.Run("bad-encoding", func(t *testing.T) {
		setRequired(t, "")
		t.Setenv("OAUTH_ENCRYPTION_KEY", "not-base64-!!")
		_, err := oauthconfig.NewEncryptorFromEnv()
		if err == nil || !strings.Contains(err.Error(), "ENCRYPTION_KEY") {
			t.Fatalf("expected ENCRYPTION_KEY decode error, got %v", err)
		}
	})
}

// TestNewEncryptorFromEnv_KeyEncodings exercises the base64/hex acceptance
// matrix introduced when hex support was reinstated. Operators historically
// generated keys with `openssl rand -hex 32`; dropping hex broke those
// deployments. Base64 stays canonical (and is tried first), hex is the
// documented fallback.
func TestNewEncryptorFromEnv_KeyEncodings(t *testing.T) {
	tooShortB64 := base64.StdEncoding.EncodeToString([]byte("too-short"))
	tooShortHex := hex.EncodeToString([]byte("too-short"))

	cases := []struct {
		name    string
		envKey  string
		fileKey string
		wantErr bool
		wantEnc bool
	}{
		{name: "base64", envKey: validKeyB64, wantEnc: true},
		{name: "hex", envKey: validKeyHex, wantEnc: true},
		{name: "base64 via _FILE", fileKey: validKeyB64 + "\n", wantEnc: true},
		{name: "hex via _FILE", fileKey: validKeyHex + "\n", wantEnc: true},
		{name: "neither base64 nor hex rejected", envKey: "definitely-neither-!!", wantErr: true},
		{name: "wrong-length base64 rejected", envKey: tooShortB64, wantErr: true},
		{name: "wrong-length hex rejected", envKey: tooShortHex, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setRequired(t, "")
			if tc.envKey != "" {
				t.Setenv("OAUTH_ENCRYPTION_KEY", tc.envKey)
			}
			if tc.fileKey != "" {
				t.Setenv("OAUTH_ENCRYPTION_KEY_FILE", writeSecretFile(t, tc.fileKey))
			}
			enc, err := oauthconfig.NewEncryptorFromEnv()
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "ENCRYPTION_KEY") {
					t.Fatalf("expected ENCRYPTION_KEY error, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewEncryptorFromEnv: %v", err)
			}
			if tc.wantEnc && enc == nil {
				t.Fatal("expected non-nil Encryptor")
			}
		})
	}
}

func TestFromEnv_EmptyTrustedAudiencesOmitted(t *testing.T) {
	setRequired(t, "https://auth.example")
	t.Setenv("OAUTH_TRUSTED_AUDIENCES", "  , , ")

	cfg, err := oauthconfig.FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if len(cfg.TrustedAudiences) != 0 {
		t.Errorf("TrustedAudiences = %v, want empty (whitespace-only entries dropped)", cfg.TrustedAudiences)
	}
}

// TestFromEnv_TrustedAudiencesCharset locks down the dex.ValidateAudiences
// gate added to FromEnv: client-id-shaped entries pass; entries with spaces,
// scheme separators, or path slashes (i.e. URL-shaped audiences) are
// rejected at startup so operators don't get a silent SSO break later.
func TestFromEnv_TrustedAudiencesCharset(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{name: "single client-id", raw: "muster-client"},
		{name: "multiple client-ids", raw: "muster-client, second-aud,a_b-c"},
		{name: "trailing comma", raw: "muster-client,"},
		{name: "url-shaped audience rejected", raw: "https://api.example.com", wantErr: true},
		{name: "audience with space rejected", raw: "muster client", wantErr: true},
		{name: "audience with colon rejected", raw: "muster:client", wantErr: true},
		{name: "audience with slash rejected", raw: "muster/client", wantErr: true},
		{name: "mix of valid and invalid rejects whole list", raw: "muster-client,bad audience", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setRequired(t, "https://auth.example")
			t.Setenv("OAUTH_TRUSTED_AUDIENCES", tc.raw)
			_, err := oauthconfig.FromEnv()
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "TRUSTED_AUDIENCES") {
					t.Fatalf("expected TRUSTED_AUDIENCES error, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("FromEnv: %v", err)
			}
		})
	}
}

func TestFromEnv_BadAllowLocalhostRedirectURIs(t *testing.T) {
	setRequired(t, "https://auth.example")
	t.Setenv("OAUTH_ALLOW_LOCALHOST_REDIRECT_URIS", "maybe")
	_, err := oauthconfig.FromEnv()
	if err == nil || !strings.Contains(err.Error(), "ALLOW_LOCALHOST_REDIRECT_URIS") {
		t.Fatalf("expected bool parse error on ALLOW_LOCALHOST_REDIRECT_URIS, got %v", err)
	}
}

func TestFromEnv_EmptyTrustedRedirectSchemesOmitted(t *testing.T) {
	setRequired(t, "https://auth.example")
	t.Setenv("OAUTH_TRUSTED_REDIRECT_SCHEMES", "  , , ")

	cfg, err := oauthconfig.FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if len(cfg.TrustedPublicRegistrationSchemes) != 0 {
		t.Errorf("TrustedPublicRegistrationSchemes = %v, want empty (whitespace-only entries dropped)", cfg.TrustedPublicRegistrationSchemes)
	}
}
