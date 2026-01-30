package dex

import (
	"reflect"
	"testing"
)

func TestFormatAudienceScope(t *testing.T) {
	tests := []struct {
		name     string
		audience string
		want     string
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
			name:     "empty string",
			audience: "",
			want:     "audience:server:client_id:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatAudienceScope(tt.audience)
			if got != tt.want {
				t.Errorf("FormatAudienceScope(%q) = %q, want %q", tt.audience, got, tt.want)
			}
		})
	}
}

func TestFormatAudienceScopes(t *testing.T) {
	tests := []struct {
		name      string
		audiences []string
		want      []string
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatAudienceScopes(tt.audiences)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FormatAudienceScopes(%v) = %v, want %v", tt.audiences, got, tt.want)
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AppendAudienceScopes(tt.scopes, tt.audiences)
			if got != tt.want {
				t.Errorf("AppendAudienceScopes(%q, %v) = %q, want %q", tt.scopes, tt.audiences, got, tt.want)
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
