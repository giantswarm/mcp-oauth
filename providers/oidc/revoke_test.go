package oidc

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRevokeAtEndpoint_PostsTokenAndBasicAuth(t *testing.T) {
	var (
		gotToken  string
		gotUser   string
		gotPass   string
		gotMethod string
		gotCT     string
		hasAuth   bool
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotCT = r.Header.Get("Content-Type")
		gotUser, gotPass, hasAuth = r.BasicAuth()
		require.NoError(t, r.ParseForm())
		gotToken = r.Form.Get("token")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	require.NoError(t, RevokeAtEndpoint(t.Context(), server.Client(), server.URL, "tok-abc", "client-1", "secret"))
	require.Equal(t, http.MethodPost, gotMethod)
	require.Equal(t, "application/x-www-form-urlencoded", gotCT)
	require.Equal(t, "tok-abc", gotToken)
	require.True(t, hasAuth, "Basic auth must be sent when clientID is non-empty")
	require.Equal(t, "client-1", gotUser)
	require.Equal(t, "secret", gotPass)
}

func TestRevokeAtEndpoint_FormEncodedBasicAuth(t *testing.T) {
	tests := []struct {
		name         string
		clientID     string
		clientSecret string
	}{
		{name: "plain credentials", clientID: "client-1", clientSecret: "secret"},
		{name: "base64 secret", clientID: "client-1", clientSecret: "abc+def/ghi="},
		{name: "percent in secret", clientID: "client-1", clientSecret: "secret%2B%"},
		{name: "reserved characters in client ID", clientID: "client+name:/=%", clientSecret: "secret"},
		{name: "spaces in credentials", clientID: "client name", clientSecret: "secret value"},
		{name: "empty secret", clientID: "client+name", clientSecret: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				encodedID, encodedSecret, hasAuth := request.BasicAuth()
				clientID, idError := url.QueryUnescape(encodedID)
				clientSecret, secretError := url.QueryUnescape(encodedSecret)
				if !hasAuth || idError != nil || secretError != nil || clientID != test.clientID || clientSecret != test.clientSecret {
					response.WriteHeader(http.StatusUnauthorized)
					return
				}
				response.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			require.NoError(t, RevokeAtEndpoint(t.Context(), server.Client(), server.URL, "test-token", test.clientID, test.clientSecret))
		})
	}
}

func TestRevokeAtEndpoint_SkipsBasicAuthForPublicEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _, hasAuth := r.BasicAuth()
		require.False(t, hasAuth, "Basic auth must be omitted when clientID is empty")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	require.NoError(t, RevokeAtEndpoint(t.Context(), server.Client(), server.URL, "tok", "", ""))
}

func TestRevokeAtEndpoint_ErrorsOnNon200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	err := RevokeAtEndpoint(t.Context(), server.Client(), server.URL, "tok", "", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "status 500")
}

func TestRevokeAtEndpoint_RejectsEmptyEndpoint(t *testing.T) {
	require.Error(t, RevokeAtEndpoint(t.Context(), nil, "", "tok", "", ""))
}
