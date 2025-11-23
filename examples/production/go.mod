module github.com/giantswarm/mcp-oauth/examples/production

go 1.24.0

replace github.com/giantswarm/mcp-oauth => ../..

require github.com/giantswarm/mcp-oauth v0.1.2

require (
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	golang.org/x/crypto v0.45.0 // indirect
	golang.org/x/oauth2 v0.33.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
	golang.org/x/time v0.14.0 // indirect
)
