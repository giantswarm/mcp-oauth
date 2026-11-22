package handler

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/server"
)

func TestBrokeredExchangeAuthenticationMatrix(t *testing.T) {
	for _, method := range []string{"client_secret_basic", "client_secret_post", "private_key_jwt"} {
		for _, shape := range []string{"valid", "missing", "mixed", "duplicate identifier", "duplicate credential", "other owner", "deleted"} {
			t.Run(method+"/"+shape, func(t *testing.T) {
				exchanger := &stubExchanger{result: happyDownstreamResult()}
				environment := setupBrokeredExchangeHandler(t, exchanger, nil, "confidential")
				client := newMatrixClient(t, environment.handler, method)
				environment.srv.Config.TokenExchangeClientAudiences = map[string][]string{client.client.ClientID: {"gaggle"}}
				presented := method
				expectedStatus := http.StatusOK
				expectedError := ""
				switch shape {
				case "missing":
					presented, expectedStatus, expectedError = "none", http.StatusUnauthorized, "invalid_client"
				case "mixed", "duplicate identifier", "duplicate credential":
					expectedStatus, expectedError = http.StatusBadRequest, "invalid_request"
				case "other owner":
					client = newMatrixClient(t, environment.handler, method)
					expectedStatus, expectedError = http.StatusBadRequest, "invalid_target"
				case "deleted":
					require.NoError(t, environment.srv.DeleteClient(t.Context(), client.client.ClientID))
					expectedStatus, expectedError = http.StatusUnauthorized, "invalid_client"
				}
				response := matrixTokenRequest(t, environment.handler, client, presented, brokeredExchangeForm(), func(request *http.Request) {
					require.NoError(t, request.ParseForm())
					switch shape {
					case "mixed":
						request.SetBasicAuth(client.client.ClientID, "mixed-secret")
						request.PostForm.Set("client_secret", "mixed-secret")
						request.Form.Set("client_secret", "mixed-secret")
					case "duplicate identifier":
						request.PostForm.Add("client_id", client.client.ClientID)
						request.Form.Add("client_id", client.client.ClientID)
					case "duplicate credential":
						switch method {
						case "client_secret_basic":
							request.Header.Add("Authorization", request.Header.Get("Authorization"))
						case "client_secret_post":
							request.PostForm.Add("client_secret", client.secret)
							request.Form.Add("client_secret", client.secret)
						case "private_key_jwt":
							request.PostForm.Add("client_assertion", request.PostForm.Get("client_assertion"))
							request.Form.Add("client_assertion", request.Form.Get("client_assertion"))
						}
					}
				})
				require.Equal(t, expectedStatus, response.Code, response.Body.String())
				if expectedError != "" {
					require.Equal(t, expectedError, decodeErrorResponse(t, response).Error)
					require.Nil(t, exchanger.gotReq)
					return
				}
				require.NotNil(t, exchanger.gotReq)
				require.Equal(t, client.client.ClientID, exchanger.gotReq.ClientID)
			})
		}
	}
}

type recoverableAssertionReplayStore struct {
	unavailable bool
	store       server.ClientAssertionReplayStore
}

func (s *recoverableAssertionReplayStore) Seen(ctx context.Context, identifier string, lifetime time.Duration) (bool, error) {
	if s.unavailable {
		return false, errors.New("replay storage unavailable")
	}
	return s.store.Seen(ctx, identifier, lifetime)
}

func TestPrivateKeyBrokeredExchangeReplayAndRetry(t *testing.T) {
	exchanger := &stubExchanger{result: happyDownstreamResult()}
	environment := setupBrokeredExchangeHandler(t, exchanger, nil, "confidential")
	client := newMatrixClient(t, environment.handler, "private_key_jwt")
	environment.srv.Config.TokenExchangeClientAudiences = map[string][]string{client.client.ClientID: {"gaggle"}}
	replay := &recoverableAssertionReplayStore{unavailable: true, store: server.NewMemoryClientAssertionReplayStore()}
	server.WithClientAssertionReplayStore(replay)(environment.srv)
	var assertion string
	response := matrixTokenRequest(t, environment.handler, client, "private_key_jwt", brokeredExchangeForm(), func(request *http.Request) {
		require.NoError(t, request.ParseForm())
		assertion = request.PostForm.Get("client_assertion")
	})
	require.Equal(t, http.StatusServiceUnavailable, response.Code, response.Body.String())
	require.NotEmpty(t, response.Header().Get("Retry-After"))
	require.Empty(t, response.Header().Get("WWW-Authenticate"))
	require.Nil(t, exchanger.gotReq)
	replay.unavailable = false
	for _, expected := range []int{http.StatusOK, http.StatusUnauthorized} {
		response = matrixTokenRequest(t, environment.handler, client, "private_key_jwt", brokeredExchangeForm(), func(request *http.Request) {
			require.NoError(t, request.ParseForm())
			request.PostForm.Set("client_assertion", assertion)
			request.Form.Set("client_assertion", assertion)
		})
		require.Equal(t, expected, response.Code, response.Body.String())
	}
}
