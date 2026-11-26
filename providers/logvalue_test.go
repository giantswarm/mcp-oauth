package providers

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUserInfo_LogValue(t *testing.T) {
	const issuer, subject = "https://idp.example.test", "user-1"
	const actorIssuer, actorSubject = "https://sts.example.test", "agent-1"
	profile := UserInfo{Email: "person@example.test", Name: "Person", Groups: []string{"admins"}, Username: "person", ClientID: "client"}
	withProfile := func(user UserInfo) *UserInfo {
		user.Email, user.Name, user.Groups, user.Username, user.ClientID = profile.Email, profile.Name, profile.Groups, profile.Username, profile.ClientID
		return &user
	}
	tests := []struct {
		name string
		user *UserInfo
		want map[string]any
	}{
		{
			name: "user",
			user: withProfile(UserInfo{Issuer: issuer, ID: subject}),
			want: map[string]any{"issuer": issuer, "subject": subject},
		},
		{
			name: "delegated call",
			user: withProfile(UserInfo{Issuer: issuer, ID: subject, ActorIssuer: actorIssuer, ActorSubject: actorSubject}),
			want: map[string]any{"issuer": issuer, "subject": subject, "actor": map[string]any{"issuer": actorIssuer, "subject": actorSubject}},
		},
		{name: "nil"},
		{name: "no issuer", user: withProfile(UserInfo{ID: subject})},
		{name: "no subject", user: withProfile(UserInfo{Issuer: issuer})},
		{name: "actor without issuer", user: withProfile(UserInfo{Issuer: issuer, ID: subject, ActorSubject: actorSubject})},
		{name: "actor without subject", user: withProfile(UserInfo{Issuer: issuer, ID: subject, ActorIssuer: actorIssuer})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			slog.New(slog.NewJSONHandler(&output, nil)).Info("operation", slog.Any("user", test.user))
			var record map[string]any
			require.NoError(t, json.Unmarshal(output.Bytes(), &record))
			if test.want == nil {
				require.NotContains(t, record, "user")
			} else {
				require.Equal(t, test.want, record["user"])
			}
			for _, private := range []string{profile.Email, profile.Name, profile.Groups[0], profile.Username, profile.ClientID} {
				require.NotContains(t, output.String(), private)
			}
		})
	}
}
