module github.com/giantswarm/mcp-oauth/examples/custom-scopes

go 1.25.4

replace github.com/giantswarm/mcp-oauth => ../..

require github.com/giantswarm/mcp-oauth v0.0.0-00010101000000-000000000000

require (
	golang.org/x/crypto v0.45.0 // indirect
	golang.org/x/oauth2 v0.33.0 // indirect
	golang.org/x/time v0.14.0 // indirect
)
