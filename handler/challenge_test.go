package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSetUnauthorizedChallengeLeavesStatusAndBodyToTheCaller(t *testing.T) {
	handler, _ := setupTestHandler(t)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/jobs", nil)
	recorder := httptest.NewRecorder()

	handler.SetUnauthorizedChallenge(recorder, request, "invalid_token", "downstream credential rejected")

	challenge := recorder.Header().Get("WWW-Authenticate")
	require.Contains(t, challenge, `Bearer resource_metadata="`+handler.server.Config.ProtectedResourceMetadataEndpoint()+`"`)
	require.Contains(t, challenge, `error="invalid_token"`)
	require.Contains(t, challenge, `error_description="downstream credential rejected"`)
	require.False(t, recorder.Flushed)
	require.Empty(t, recorder.Body.Bytes())
	recorder.WriteHeader(http.StatusUnauthorized)
	require.Equal(t, challenge, recorder.Result().Header.Get("WWW-Authenticate"))
}
