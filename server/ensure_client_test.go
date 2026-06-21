package server

import (
	"context"
	"testing"
)

func TestEnsureConfidentialClient(t *testing.T) {
	setup := newTestServerSetup(false)
	srv, err := setup.createServer(&Config{
		Issuer:            "https://oauth.example.com",
		AllowInsecureHTTP: false,
	})
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}

	ctx := context.Background()
	const (
		id     = "broker-client-id"
		secret = "broker-client-secret"
	)
	scopes := []string{"openid"}

	// First call seeds the client.
	seeded, err := srv.EnsureConfidentialClient(ctx, id, secret, scopes)
	if err != nil {
		t.Fatalf("first EnsureConfidentialClient: %v", err)
	}
	if !seeded {
		t.Fatal("expected first call to seed the client")
	}

	c, err := srv.GetClient(ctx, id)
	if err != nil {
		t.Fatalf("GetClient after seed: %v", err)
	}
	if !c.IsConfidential() {
		t.Errorf("client type = %q, want confidential", c.ClientType)
	}
	if err := srv.ValidateClientCredentials(ctx, id, secret); err != nil {
		t.Errorf("ValidateClientCredentials with correct secret: %v", err)
	}

	// Second call with the same credentials is a no-op.
	seeded, err = srv.EnsureConfidentialClient(ctx, id, secret, scopes)
	if err != nil {
		t.Fatalf("idempotent EnsureConfidentialClient: %v", err)
	}
	if seeded {
		t.Error("expected idempotent call to be a no-op")
	}

	// Changing the secret rewrites the record.
	const newSecret = "rotated-secret"
	seeded, err = srv.EnsureConfidentialClient(ctx, id, newSecret, scopes)
	if err != nil {
		t.Fatalf("rotating EnsureConfidentialClient: %v", err)
	}
	if !seeded {
		t.Error("expected secret change to rewrite the record")
	}
	if err := srv.ValidateClientCredentials(ctx, id, newSecret); err != nil {
		t.Errorf("ValidateClientCredentials with rotated secret: %v", err)
	}

	// Empty inputs are rejected.
	if _, err := srv.EnsureConfidentialClient(ctx, "", secret, scopes); err == nil {
		t.Error("expected error for empty client id")
	}
	if _, err := srv.EnsureConfidentialClient(ctx, id, "", scopes); err == nil {
		t.Error("expected error for empty client secret")
	}
}
