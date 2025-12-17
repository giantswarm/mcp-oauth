package server

import (
	"encoding/base64"
	"testing"
)

func TestParseKubernetesServiceAccount_RawFormat(t *testing.T) {
	tests := []struct {
		name          string
		sub           string
		wantNamespace string
		wantName      string
		wantOK        bool
	}{
		{
			name:          "valid service account",
			sub:           "system:serviceaccount:default:my-service",
			wantNamespace: "default",
			wantName:      "my-service",
			wantOK:        true,
		},
		{
			name:          "valid with complex namespace",
			sub:           "system:serviceaccount:org-giantswarm:grizzly-shoot",
			wantNamespace: "org-giantswarm",
			wantName:      "grizzly-shoot",
			wantOK:        true,
		},
		{
			name:          "valid with dots in names",
			sub:           "system:serviceaccount:my.namespace:my.service.name",
			wantNamespace: "my.namespace",
			wantName:      "my.service.name",
			wantOK:        true,
		},
		{
			name:   "not a service account - regular user",
			sub:    "user@example.com",
			wantOK: false,
		},
		{
			name:   "not a service account - wrong prefix",
			sub:    "system:node:my-node",
			wantOK: false,
		},
		{
			name:   "incomplete service account - missing name",
			sub:    "system:serviceaccount:default",
			wantOK: false,
		},
		{
			name:   "incomplete service account - missing namespace and name",
			sub:    "system:serviceaccount:",
			wantOK: false,
		},
		{
			name:   "empty string",
			sub:    "",
			wantOK: false,
		},
		{
			name:   "invalid namespace - starts with dash",
			sub:    "system:serviceaccount:-invalid:myservice",
			wantOK: false,
		},
		{
			name:   "invalid name - ends with dash",
			sub:    "system:serviceaccount:default:myservice-",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			namespace, name, ok := ParseKubernetesServiceAccount(tt.sub)
			if ok != tt.wantOK {
				t.Errorf("ParseKubernetesServiceAccount() ok = %v, want %v", ok, tt.wantOK)
				return
			}
			if ok {
				if namespace != tt.wantNamespace {
					t.Errorf("ParseKubernetesServiceAccount() namespace = %v, want %v", namespace, tt.wantNamespace)
				}
				if name != tt.wantName {
					t.Errorf("ParseKubernetesServiceAccount() name = %v, want %v", name, tt.wantName)
				}
			}
		})
	}
}

func TestParseKubernetesServiceAccount_DexEncodedFormat(t *testing.T) {
	// Helper to create Dex-style encoded subjects
	// Dex encodes as protobuf: field 1 = subject, field 2 = connector_id
	encodeDexSubject := func(subject, connectorID string) string {
		// Build protobuf manually:
		// Field 1 (tag 0x0a): subject
		// Field 2 (tag 0x12): connector_id
		var buf []byte

		// Field 1
		buf = append(buf, 0x0a)                    // tag
		buf = append(buf, byte(len(subject)))     // length (assuming < 128)
		buf = append(buf, []byte(subject)...)     // data

		// Field 2
		buf = append(buf, 0x12)                       // tag
		buf = append(buf, byte(len(connectorID)))    // length (assuming < 128)
		buf = append(buf, []byte(connectorID)...)    // data

		return base64.StdEncoding.EncodeToString(buf)
	}

	tests := []struct {
		name          string
		sub           string
		wantNamespace string
		wantName      string
		wantOK        bool
	}{
		{
			name:          "dex encoded - simple service account",
			sub:           encodeDexSubject("system:serviceaccount:default:my-service", "kubernetes"),
			wantNamespace: "default",
			wantName:      "my-service",
			wantOK:        true,
		},
		{
			name:          "dex encoded - complex namespace",
			sub:           encodeDexSubject("system:serviceaccount:org-giantswarm:grizzly-shoot", "kubernetes"),
			wantNamespace: "org-giantswarm",
			wantName:      "grizzly-shoot",
			wantOK:        true,
		},
		{
			name: "real dex subject from production",
			// This is the actual encoded subject from the user's issue
			sub:           "CjJzeXN0ZW06c2VydmljZWFjY291bnQ6b3JnLWdpYW50c3dhcm06Z3JpenpseS1zaG9vdBIKa3ViZXJuZXRlcw",
			wantNamespace: "org-giantswarm",
			wantName:      "grizzly-shoot",
			wantOK:        true,
		},
		{
			name:   "dex encoded - not a service account",
			sub:    encodeDexSubject("user@example.com", "oidc"),
			wantOK: false,
		},
		{
			name:   "invalid base64",
			sub:    "not-valid-base64!!!",
			wantOK: false,
		},
		{
			name:   "valid base64 but not protobuf",
			sub:    base64.StdEncoding.EncodeToString([]byte("just a string")),
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			namespace, name, ok := ParseKubernetesServiceAccount(tt.sub)
			if ok != tt.wantOK {
				t.Errorf("ParseKubernetesServiceAccount() ok = %v, want %v", ok, tt.wantOK)
				return
			}
			if ok {
				if namespace != tt.wantNamespace {
					t.Errorf("ParseKubernetesServiceAccount() namespace = %v, want %v", namespace, tt.wantNamespace)
				}
				if name != tt.wantName {
					t.Errorf("ParseKubernetesServiceAccount() name = %v, want %v", name, tt.wantName)
				}
			}
		})
	}
}

func TestGenerateSyntheticEmail(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		saName    string
		domain    string
		want      string
	}{
		{
			name:      "default domain",
			namespace: "default",
			saName:    "my-service",
			domain:    "",
			want:      "my-service@default.serviceaccount.local",
		},
		{
			name:      "custom domain",
			namespace: "org-giantswarm",
			saName:    "grizzly-shoot",
			domain:    "k8s.example.com",
			want:      "grizzly-shoot@org-giantswarm.k8s.example.com",
		},
		{
			name:      "explicit default domain",
			namespace: "kube-system",
			saName:    "coredns",
			domain:    DefaultMachineIdentityEmailDomain,
			want:      "coredns@kube-system.serviceaccount.local",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GenerateSyntheticEmail(tt.namespace, tt.saName, tt.domain)
			if got != tt.want {
				t.Errorf("GenerateSyntheticEmail() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDeriveKubernetesGroups(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		want      []string
	}{
		{
			name:      "default namespace",
			namespace: "default",
			want: []string{
				"system:serviceaccounts",
				"system:serviceaccounts:default",
				"system:authenticated",
			},
		},
		{
			name:      "custom namespace",
			namespace: "org-giantswarm",
			want: []string{
				"system:serviceaccounts",
				"system:serviceaccounts:org-giantswarm",
				"system:authenticated",
			},
		},
		{
			name:      "kube-system namespace",
			namespace: "kube-system",
			want: []string{
				"system:serviceaccounts",
				"system:serviceaccounts:kube-system",
				"system:authenticated",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DeriveKubernetesGroups(tt.namespace)
			if len(got) != len(tt.want) {
				t.Errorf("DeriveKubernetesGroups() returned %d groups, want %d", len(got), len(tt.want))
				return
			}
			for i, group := range got {
				if group != tt.want[i] {
					t.Errorf("DeriveKubernetesGroups()[%d] = %v, want %v", i, group, tt.want[i])
				}
			}
		})
	}
}

func TestIsKubernetesServiceAccount(t *testing.T) {
	tests := []struct {
		name string
		sub  string
		want bool
	}{
		{
			name: "valid raw service account",
			sub:  "system:serviceaccount:default:my-service",
			want: true,
		},
		{
			name: "valid dex encoded",
			sub:  "CjJzeXN0ZW06c2VydmljZWFjY291bnQ6b3JnLWdpYW50c3dhcm06Z3JpenpseS1zaG9vdBIKa3ViZXJuZXRlcw",
			want: true,
		},
		{
			name: "regular user email",
			sub:  "user@example.com",
			want: false,
		},
		{
			name: "empty string",
			sub:  "",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsKubernetesServiceAccount(tt.sub); got != tt.want {
				t.Errorf("IsKubernetesServiceAccount() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSanitizeForEmail(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "simple string",
			input: "myservice",
			want:  "myservice",
		},
		{
			name:  "with colons",
			input: "system:node:my-node",
			want:  "system-node-my-node",
		},
		{
			name:  "with slashes",
			input: "path/to/resource",
			want:  "path-to-resource",
		},
		{
			name:  "with spaces",
			input: "my service name",
			want:  "my-service-name",
		},
		{
			name:  "with special characters",
			input: "my@service#name!",
			want:  "myservicename",
		},
		{
			name:  "leading/trailing special chars",
			input: "-my-service-",
			want:  "my-service",
		},
		{
			name:  "empty after sanitization",
			input: "@#$%",
			want:  "machine",
		},
		{
			name:  "very long string",
			input: "this-is-a-very-long-string-that-exceeds-the-maximum-length-allowed-for-email-local-parts-and-should-be-truncated",
			want:  "this-is-a-very-long-string-that-exceeds-the-maximum-length-allow",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeForEmail(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeForEmail() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGenerateFallbackEmail(t *testing.T) {
	tests := []struct {
		name string
		sub  string
		want string
	}{
		{
			name: "simple identifier",
			sub:  "my-machine",
			want: "my-machine@machine.local",
		},
		{
			name: "complex identifier",
			sub:  "system:node:worker-1",
			want: "system-node-worker-1@machine.local",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GenerateFallbackEmail(tt.sub)
			if got != tt.want {
				t.Errorf("GenerateFallbackEmail() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractProtobufField1(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    string
		wantErr bool
	}{
		{
			name:    "valid protobuf field 1",
			data:    append([]byte{0x0a, 0x05}, []byte("hello")...),
			want:    "hello",
			wantErr: false,
		},
		{
			name:    "empty data",
			data:    []byte{},
			wantErr: true,
		},
		{
			name:    "wrong tag",
			data:    []byte{0x12, 0x05, 'h', 'e', 'l', 'l', 'o'},
			wantErr: true,
		},
		{
			name:    "length exceeds data",
			data:    []byte{0x0a, 0x10, 'h', 'e', 'l', 'l', 'o'}, // claims 16 bytes but only 5
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractProtobufField1(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractProtobufField1() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("extractProtobufField1() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestReadVarint(t *testing.T) {
	tests := []struct {
		name          string
		data          []byte
		wantValue     uint64
		wantBytesRead int
	}{
		{
			name:          "single byte",
			data:          []byte{0x05},
			wantValue:     5,
			wantBytesRead: 1,
		},
		{
			name:          "two bytes",
			data:          []byte{0x80, 0x01},
			wantValue:     128,
			wantBytesRead: 2,
		},
		{
			name:          "300 in varint",
			data:          []byte{0xac, 0x02},
			wantValue:     300,
			wantBytesRead: 2,
		},
		{
			name:          "empty",
			data:          []byte{},
			wantValue:     0,
			wantBytesRead: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, bytesRead := readVarint(tt.data)
			if value != tt.wantValue {
				t.Errorf("readVarint() value = %v, want %v", value, tt.wantValue)
			}
			if bytesRead != tt.wantBytesRead {
				t.Errorf("readVarint() bytesRead = %v, want %v", bytesRead, tt.wantBytesRead)
			}
		})
	}
}

// TestRealWorldDexSubject tests with the actual subject from the user's issue
func TestRealWorldDexSubject(t *testing.T) {
	// This is the exact subject from the user's Dex token
	sub := "CjJzeXN0ZW06c2VydmljZWFjY291bnQ6b3JnLWdpYW50c3dhcm06Z3JpenpseS1zaG9vdBIKa3ViZXJuZXRlcw"

	namespace, name, ok := ParseKubernetesServiceAccount(sub)
	if !ok {
		t.Fatal("Failed to parse real-world Dex subject")
	}

	if namespace != "org-giantswarm" {
		t.Errorf("namespace = %q, want %q", namespace, "org-giantswarm")
	}
	if name != "grizzly-shoot" {
		t.Errorf("name = %q, want %q", name, "grizzly-shoot")
	}

	// Test full enrichment flow
	email := GenerateSyntheticEmail(namespace, name, "")
	expectedEmail := "grizzly-shoot@org-giantswarm.serviceaccount.local"
	if email != expectedEmail {
		t.Errorf("email = %q, want %q", email, expectedEmail)
	}

	groups := DeriveKubernetesGroups(namespace)
	expectedGroups := []string{
		"system:serviceaccounts",
		"system:serviceaccounts:org-giantswarm",
		"system:authenticated",
	}
	if len(groups) != len(expectedGroups) {
		t.Errorf("groups count = %d, want %d", len(groups), len(expectedGroups))
	}
	for i, g := range groups {
		if g != expectedGroups[i] {
			t.Errorf("groups[%d] = %q, want %q", i, g, expectedGroups[i])
		}
	}
}

