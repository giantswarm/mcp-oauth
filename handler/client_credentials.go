package handler

import (
	"net/http"

	oauth "github.com/giantswarm/mcp-oauth"
)

func validateClientCredentialShape(request *http.Request) error {
	if len(request.Form["client_id"]) > 1 {
		return oauth.ErrInvalidRequest("Multiple client identifiers")
	}
	if request.Form.Has("client_secret") && (len(request.PostForm["client_secret"]) != 1 || len(request.Form["client_secret"]) != 1 || request.Header.Get("Authorization") != "") {
		return oauth.ErrInvalidRequest("Client credentials must use one authentication method and appear only once in the request body")
	}
	return nil
}
