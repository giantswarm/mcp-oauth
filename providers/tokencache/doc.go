// Package tokencache provides a generic LRU-bounded token cache for short-lived
// access tokens. It is provider-neutral: any credential provider that mints tokens
// with an expiry (OIDC exchange, GitHub App installation tokens, etc.) can use it
// directly with an arbitrary string key.
package tokencache
