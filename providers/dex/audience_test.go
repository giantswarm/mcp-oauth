package dex

import (
	"reflect"
	"strings"
	"testing"
)

func TestValidateAudience(t *testing.T) {
	tests := []struct {
		name      string
		audience  string
		wantError bool
		errSubstr string
	}{
		{
			name:      "valid simple client id",
			audience:  "dex-k8s-authenticator",
			wantError: false,
		},
		{
			name:      "valid with hyphens",
			audience:  "my-cool-service",
			wantError: false,
		},
		{
			name:      "valid with underscores",
			audience:  "api_gateway_v2",
			wantError: false,
		},
		{
			name:      "valid short",
			audience:  "k8s",
			wantError: false,
		},
		{
			name:      "valid alphanumeric",
			audience:  "Service123",
			wantError: false,
		},
		{
			name:      "empty string rejected",
			audience:  "",
			wantError: true,
			errSubstr: "cannot be empty",
		},
		{
			name:      "space injection attempt rejected",
			audience:  "evil-client openid",
			wantError: true,
			errSubstr: "invalid characters",
		},
		{
			name:      "space at start rejected",
			audience:  " k8s-auth",
			wantError: true,
			errSubstr: "invalid characters",
		},
		{
			name:      "space at end rejected",
			audience:  "k8s-auth ",
			wantError: true,
			errSubstr: "invalid characters",
		},
		{
			name:      "newline injection rejected",
			audience:  "evil\nclient",
			wantError: true,
			errSubstr: "invalid characters",
		},
		{
			name:      "tab injection rejected",
			audience:  "evil\tclient",
			wantError: true,
			errSubstr: "invalid characters",
		},
		{
			name:      "carriage return rejected",
			audience:  "evil\rclient",
			wantError: true,
			errSubstr: "invalid characters",
		},
		{
			name:      "colon rejected",
			audience:  "audience:server",
			wantError: true,
			errSubstr: "invalid characters",
		},
		{
			name:      "slash rejected",
			audience:  "path/to/resource",
			wantError: true,
			errSubstr: "invalid characters",
		},
		{
			name:      "special characters rejected",
			audience:  "client@domain.com",
			wantError: true,
			errSubstr: "invalid characters",
		},
		{
			name:      "unicode rejected",
			audience:  "client\u200b", // zero-width space
			wantError: true,
			errSubstr: "invalid characters",
		},
		{
			name:      "exceeds max length",
			audience:  strings.Repeat("a", MaxAudienceLength+1),
			wantError: true,
			errSubstr: "exceeds maximum length",
		},
		{
			name:      "at max length is valid",
			audience:  strings.Repeat("a", MaxAudienceLength),
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAudience(tt.audience)
			if tt.wantError {
				if err == nil {
					t.Errorf("ValidateAudience(%q) = nil, want error containing %q", tt.audience, tt.errSubstr)
				} else if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("ValidateAudience(%q) error = %q, want error containing %q", tt.audience, err.Error(), tt.errSubstr)
				}
			} else {
				if err != nil {
					t.Errorf("ValidateAudience(%q) = %v, want nil", tt.audience, err)
				}
			}
		})
	}
}

func TestValidateAudiences(t *testing.T) {
	tests := []struct {
		name      string
		audiences []string
		wantError bool
		errSubstr string
	}{
		{
			name:      "valid single audience",
			audiences: []string{"k8s-auth"},
			wantError: false,
		},
		{
			name:      "valid multiple audiences",
			audiences: []string{"k8s-auth", "api-gateway"},
			wantError: false,
		},
		{
			name:      "empty strings allowed (filtered out)",
			audiences: []string{"k8s-auth", "", "api-gateway"},
			wantError: false,
		},
		{
			name:      "all empty strings allowed",
			audiences: []string{"", "", ""},
			wantError: false,
		},
		{
			name:      "nil slice allowed",
			audiences: nil,
			wantError: false,
		},
		{
			name:      "empty slice allowed",
			audiences: []string{},
			wantError: false,
		},
		{
			name:      "invalid audience in list",
			audiences: []string{"valid-client", "invalid client"},
			wantError: true,
			errSubstr: "audience at index 1",
		},
		{
			name:      "exceeds max count",
			audiences: make([]string, MaxAudienceCount+1),
			wantError: true,
			errSubstr: "exceed maximum count",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Fill the max count test with valid values
			if tt.name == "exceeds max count" {
				for i := range tt.audiences {
					tt.audiences[i] = "valid-client"
				}
			}

			err := ValidateAudiences(tt.audiences)
			if tt.wantError {
				if err == nil {
					t.Errorf("ValidateAudiences(%v) = nil, want error containing %q", tt.audiences, tt.errSubstr)
				} else if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("ValidateAudiences(%v) error = %q, want error containing %q", tt.audiences, err.Error(), tt.errSubstr)
				}
			} else {
				if err != nil {
					t.Errorf("ValidateAudiences(%v) = %v, want nil", tt.audiences, err)
				}
			}
		})
	}
}

func TestFormatAudienceScope(t *testing.T) {
	tests := []struct {
		name      string
		audience  string
		want      string
		wantError bool
		errSubstr string
	}{
		{
			name:     "simple client id",
			audience: "dex-k8s-authenticator",
			want:     "audience:server:client_id:dex-k8s-authenticator",
		},
		{
			name:     "client id with hyphens",
			audience: "my-cool-service",
			want:     "audience:server:client_id:my-cool-service",
		},
		{
			name:     "client id with underscores",
			audience: "api_gateway_v2",
			want:     "audience:server:client_id:api_gateway_v2",
		},
		{
			name:     "short client id",
			audience: "k8s",
			want:     "audience:server:client_id:k8s",
		},
		{
			name:      "empty string rejected",
			audience:  "",
			wantError: true,
			errSubstr: "cannot be empty",
		},
		{
			name:      "scope injection attempt rejected",
			audience:  "evil-client openid groups",
			wantError: true,
			errSubstr: "invalid characters",
		},
		{
			name:      "special characters rejected",
			audience:  "client:id",
			wantError: true,
			errSubstr: "invalid characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FormatAudienceScope(tt.audience)
			if tt.wantError {
				if err == nil {
					t.Errorf("FormatAudienceScope(%q) = (%q, nil), want error containing %q", tt.audience, got, tt.errSubstr)
				} else if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("FormatAudienceScope(%q) error = %q, want error containing %q", tt.audience, err.Error(), tt.errSubstr)
				}
			} else {
				if err != nil {
					t.Errorf("FormatAudienceScope(%q) returned unexpected error: %v", tt.audience, err)
				}
				if got != tt.want {
					t.Errorf("FormatAudienceScope(%q) = %q, want %q", tt.audience, got, tt.want)
				}
			}
		})
	}
}

func TestFormatAudienceScopes(t *testing.T) {
	tests := []struct {
		name      string
		audiences []string
		want      []string
		wantError bool
		errSubstr string
	}{
		{
			name:      "single audience",
			audiences: []string{"k8s-auth"},
			want:      []string{"audience:server:client_id:k8s-auth"},
		},
		{
			name:      "multiple audiences",
			audiences: []string{"k8s-auth", "api-gateway"},
			want: []string{
				"audience:server:client_id:k8s-auth",
				"audience:server:client_id:api-gateway",
			},
		},
		{
			name:      "filters empty strings",
			audiences: []string{"k8s-auth", "", "api-gateway", ""},
			want: []string{
				"audience:server:client_id:k8s-auth",
				"audience:server:client_id:api-gateway",
			},
		},
		{
			name:      "empty slice",
			audiences: []string{},
			want:      nil,
		},
		{
			name:      "nil slice",
			audiences: nil,
			want:      nil,
		},
		{
			name:      "all empty strings",
			audiences: []string{"", "", ""},
			want:      nil,
		},
		{
			name:      "single empty string",
			audiences: []string{""},
			want:      nil,
		},
		{
			name:      "three audiences",
			audiences: []string{"svc-a", "svc-b", "svc-c"},
			want: []string{
				"audience:server:client_id:svc-a",
				"audience:server:client_id:svc-b",
				"audience:server:client_id:svc-c",
			},
		},
		{
			name:      "invalid audience rejected",
			audiences: []string{"valid-client", "invalid client"},
			wantError: true,
			errSubstr: "invalid characters",
		},
		{
			name:      "scope injection in list rejected",
			audiences: []string{"client1", "evil openid groups"},
			wantError: true,
			errSubstr: "invalid characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FormatAudienceScopes(tt.audiences)
			if tt.wantError {
				if err == nil {
					t.Errorf("FormatAudienceScopes(%v) = (%v, nil), want error containing %q", tt.audiences, got, tt.errSubstr)
				} else if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("FormatAudienceScopes(%v) error = %q, want error containing %q", tt.audiences, err.Error(), tt.errSubstr)
				}
			} else {
				if err != nil {
					t.Errorf("FormatAudienceScopes(%v) returned unexpected error: %v", tt.audiences, err)
				}
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("FormatAudienceScopes(%v) = %v, want %v", tt.audiences, got, tt.want)
				}
			}
		})
	}
}

func TestAppendAudienceScopes(t *testing.T) {
	tests := []struct {
		name      string
		scopes    string
		audiences []string
		want      string
		wantError bool
		errSubstr string
	}{
		{
			name:      "append to existing scopes",
			scopes:    "openid profile email",
			audiences: []string{"k8s-auth"},
			want:      "openid profile email audience:server:client_id:k8s-auth",
		},
		{
			name:      "append multiple audiences to existing scopes",
			scopes:    "openid profile",
			audiences: []string{"k8s-auth", "api-gateway"},
			want:      "openid profile audience:server:client_id:k8s-auth audience:server:client_id:api-gateway",
		},
		{
			name:      "empty scopes with audiences",
			scopes:    "",
			audiences: []string{"k8s-auth", "api-gateway"},
			want:      "audience:server:client_id:k8s-auth audience:server:client_id:api-gateway",
		},
		{
			name:      "existing scopes with empty audiences",
			scopes:    "openid profile email",
			audiences: []string{},
			want:      "openid profile email",
		},
		{
			name:      "existing scopes with nil audiences",
			scopes:    "openid profile email",
			audiences: nil,
			want:      "openid profile email",
		},
		{
			name:      "existing scopes with only empty string audiences",
			scopes:    "openid profile email",
			audiences: []string{"", ""},
			want:      "openid profile email",
		},
		{
			name:      "empty scopes with empty audiences",
			scopes:    "",
			audiences: []string{},
			want:      "",
		},
		{
			name:      "empty scopes with nil audiences",
			scopes:    "",
			audiences: nil,
			want:      "",
		},
		{
			name:      "single scope with single audience",
			scopes:    "openid",
			audiences: []string{"k8s-auth"},
			want:      "openid audience:server:client_id:k8s-auth",
		},
		{
			name:      "filters empty audience strings",
			scopes:    "openid profile",
			audiences: []string{"k8s-auth", "", "api-gateway"},
			want:      "openid profile audience:server:client_id:k8s-auth audience:server:client_id:api-gateway",
		},
		{
			name:      "complex real-world example",
			scopes:    "openid profile email groups offline_access",
			audiences: []string{"dex-k8s-authenticator"},
			want:      "openid profile email groups offline_access audience:server:client_id:dex-k8s-authenticator",
		},
		{
			name:      "scope injection attempt rejected",
			scopes:    "openid profile",
			audiences: []string{"evil-client openid admin"},
			wantError: true,
			errSubstr: "invalid characters",
		},
		{
			name:      "invalid audience in list rejected",
			scopes:    "openid",
			audiences: []string{"valid", "in:valid"},
			wantError: true,
			errSubstr: "invalid characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := AppendAudienceScopes(tt.scopes, tt.audiences)
			if tt.wantError {
				if err == nil {
					t.Errorf("AppendAudienceScopes(%q, %v) = (%q, nil), want error containing %q", tt.scopes, tt.audiences, got, tt.errSubstr)
				} else if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("AppendAudienceScopes(%q, %v) error = %q, want error containing %q", tt.scopes, tt.audiences, err.Error(), tt.errSubstr)
				}
			} else {
				if err != nil {
					t.Errorf("AppendAudienceScopes(%q, %v) returned unexpected error: %v", tt.scopes, tt.audiences, err)
				}
				if got != tt.want {
					t.Errorf("AppendAudienceScopes(%q, %v) = %q, want %q", tt.scopes, tt.audiences, got, tt.want)
				}
			}
		})
	}
}

// TestAudienceScopePrefix verifies the constant is correctly defined
func TestAudienceScopePrefix(t *testing.T) {
	expected := "audience:server:client_id:"
	if AudienceScopePrefix != expected {
		t.Errorf("AudienceScopePrefix = %q, want %q", AudienceScopePrefix, expected)
	}
}

// TestSecurityScopeInjectionPrevention specifically tests that scope injection attacks are prevented
func TestSecurityScopeInjectionPrevention(t *testing.T) {
	// These are attack payloads that could be used to inject additional OAuth scopes
	attackPayloads := []struct {
		name    string
		payload string
	}{
		{"space injection", "evil-client openid"},
		{"multiple scope injection", "evil-client openid groups offline_access admin"},
		{"leading space", " openid"},
		{"trailing space", "openid "},
		{"tab injection", "evil\topenid"},
		{"newline injection", "evil\nopenid"},
		{"carriage return injection", "evil\ropenid"},
		{"null byte injection", "evil\x00openid"},
		{"url encoded space", "evil%20openid"},
	}

	for _, tt := range attackPayloads {
		t.Run(tt.name, func(t *testing.T) {
			// All attack payloads should be rejected
			err := ValidateAudience(tt.payload)
			if err == nil {
				t.Errorf("ValidateAudience(%q) should reject attack payload but returned nil", tt.payload)
			}

			_, err = FormatAudienceScope(tt.payload)
			if err == nil {
				t.Errorf("FormatAudienceScope(%q) should reject attack payload but returned nil", tt.payload)
			}

			_, err = FormatAudienceScopes([]string{tt.payload})
			if err == nil {
				t.Errorf("FormatAudienceScopes with %q should reject attack payload but returned nil", tt.payload)
			}

			_, err = AppendAudienceScopes("openid profile", []string{tt.payload})
			if err == nil {
				t.Errorf("AppendAudienceScopes with %q should reject attack payload but returned nil", tt.payload)
			}
		})
	}
}

// TestMaxAudienceLengthConstant verifies the constant is set appropriately
func TestMaxAudienceLengthConstant(t *testing.T) {
	if MaxAudienceLength < 64 {
		t.Errorf("MaxAudienceLength = %d, should be at least 64 to allow reasonable client IDs", MaxAudienceLength)
	}
	if MaxAudienceLength > 1024 {
		t.Errorf("MaxAudienceLength = %d, should not exceed 1024 to prevent DoS", MaxAudienceLength)
	}
}

// TestMaxAudienceCountConstant verifies the constant is set appropriately
func TestMaxAudienceCountConstant(t *testing.T) {
	if MaxAudienceCount < 10 {
		t.Errorf("MaxAudienceCount = %d, should be at least 10 for multi-service SSO", MaxAudienceCount)
	}
	if MaxAudienceCount > 100 {
		t.Errorf("MaxAudienceCount = %d, should not exceed 100 to prevent DoS", MaxAudienceCount)
	}
}
