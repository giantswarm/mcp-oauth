package oidc

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScopeClaim_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    ScopeClaim
		wantErr bool
	}{
		{name: "space-delimited string", payload: `{"scope":"tools:read  tools:write"}`, want: ScopeClaim{"tools:read", "tools:write"}},
		{name: "empty string", payload: `{"scope":""}`, want: ScopeClaim{}},
		{name: "absent", payload: `{}`},
		{name: "number refused", payload: `{"scope":42}`, wantErr: true},
		{name: "array of strings refused", payload: `{"scope":["tools:read","tools:write"]}`, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var claims IDTokenClaims
			err := json.Unmarshal([]byte(tc.payload), &claims)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, claims.Scope)
		})
	}
}

func TestScopeClaim_MarshalJSON(t *testing.T) {
	encoded, err := json.Marshal(IDTokenClaims{Scope: ScopeClaim{"tools:read", "tools:write"}})
	require.NoError(t, err)
	require.JSONEq(t, `{"scope":"tools:read tools:write"}`, string(encoded))

	encoded, err = json.Marshal(IDTokenClaims{})
	require.NoError(t, err)
	require.JSONEq(t, `{}`, string(encoded))
}
