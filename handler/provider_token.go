package handler

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/giantswarm/mcp-oauth/internal/constants"
	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/storage"
)

// ErrProviderIDTokenUnavailable means authentication yielded no provider ID token.
var ErrProviderIDTokenUnavailable = errors.New("no provider ID token is available")

type providerTokenKey struct{}

type providerIDTokenKey struct{}

type validatedProviderToken struct {
	bearer string
	source providers.TokenSource
	store  storage.TokenStore
}

// ProviderIDTokenFromContext resolves the provider ID token of a validated
// request. It never substitutes an access token or application credential.
func ProviderIDTokenFromContext(ctx context.Context) (string, error) {
	if token, ok := ctx.Value(providerIDTokenKey{}).(string); ok && token != "" {
		return token, nil
	}
	validated, ok := ctx.Value(providerTokenKey{}).(validatedProviderToken)
	if !ok || validated.bearer == "" {
		return "", ErrProviderIDTokenUnavailable
	}
	if validated.source == providers.TokenSourceSSO {
		return validated.bearer, nil
	}
	if validated.source != providers.TokenSourceOAuth {
		return "", ErrProviderIDTokenUnavailable
	}
	providerToken, err := validated.store.GetToken(ctx, validated.bearer)
	if err != nil {
		return "", err
	}
	if providerToken != nil {
		if token, ok := providerToken.Extra("id_token").(string); ok && token != "" {
			return token, nil
		}
	}
	return "", ErrProviderIDTokenUnavailable
}

// RequireProviderIDToken refuses validated requests without a provider ID token.
// It runs inside ValidateToken and keeps resolved credentials request-scoped.
func (h *Handler) RequireProviderIDToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		token, err := ProviderIDTokenFromContext(request.Context())
		if err != nil {
			if errors.Is(err, ErrProviderIDTokenUnavailable) || errors.Is(err, storage.ErrTokenNotFound) {
				h.writeUnauthorizedError(w, request, constants.ErrorCodeInvalidToken, "Provider ID token is unavailable")
			} else {
				h.writeStorageUnavailable(w, request, endpointValidateToken, request.Method, nil, time.Now(), err)
			}
			return
		}
		ctx := context.WithValue(request.Context(), providerIDTokenKey{}, token)
		next.ServeHTTP(w, request.WithContext(ctx))
	})
}
