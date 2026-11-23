package handler

import (
	"net/http"

	"github.com/felixge/httpsnoop"
)

func (h *Handler) protectedResponseWriter(writer http.ResponseWriter, request *http.Request) http.ResponseWriter {
	return httpsnoop.Wrap(writer, httpsnoop.Hooks{WriteHeader: func(writeHeader httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
		return func(status int) {
			if status == http.StatusUnauthorized && writer.Header().Get("WWW-Authenticate") == "" {
				h.SetUnauthorizedChallenge(writer, request, "", "")
			}
			writeHeader(status)
		}
	}})
}
