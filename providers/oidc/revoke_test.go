package oidc

import (
	"context"
	"net/http"
	"net/http/httptest"
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

	require.NoError(t, RevokeAtEndpoint(context.Background(), server.Client(), server.URL, "tok-abc", "client-1", "secret"))
	require.Equal(t, http.MethodPost, gotMethod)
	require.Equal(t, "application/x-www-form-urlencoded", gotCT)
	require.Equal(t, "tok-abc", gotToken)
	require.True(t, hasAuth, "Basic auth must be sent when clientID is non-empty")
	require.Equal(t, "client-1", gotUser)
	require.Equal(t, "secret", gotPass)
}

func TestRevokeAtEndpoint_SkipsBasicAuthForPublicEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _, hasAuth := r.BasicAuth()
		require.False(t, hasAuth, "Basic auth must be omitted when clientID is empty")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	require.NoError(t, RevokeAtEndpoint(context.Background(), server.Client(), server.URL, "tok", "", ""))
}

func TestRevokeAtEndpoint_ErrorsOnNon200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	err := RevokeAtEndpoint(context.Background(), server.Client(), server.URL, "tok", "", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "status 500")
}

func TestRevokeAtEndpoint_RejectsEmptyEndpoint(t *testing.T) {
	require.Error(t, RevokeAtEndpoint(context.Background(), nil, "", "tok", "", ""))
}
