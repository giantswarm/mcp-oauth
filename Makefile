.PHONY: help test test-coverage test-race lint fmt vet clean build examples install-tools

# Default target
.DEFAULT_GOAL := help

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

test: ## Run tests
	go test -v ./...

test-coverage: ## Run tests with coverage
	go test -v -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

test-race: ## Run tests with race detector
	go test -v -race ./...

test-all: test-race test-coverage ## Run all tests

lint: ## Run linters
	golangci-lint run

fmt: ## Format code
	gofmt -s -w .
	goimports -w -local github.com/giantswarm/mcp-oauth .

vet: ## Run go vet
	go vet ./...

clean: ## Clean build artifacts
	rm -f coverage.out coverage.html
	rm -rf dist/ build/
	find examples -type f -name '*.exe' -delete
	find examples -type f ! -name '*.go' ! -name '*.mod' ! -name '*.sum' ! -name 'README.md' -delete 2>/dev/null || true

build-examples: ## Build all examples
	@echo "Building examples..."
	cd examples/basic && go build -v
	cd examples/production && go build -v
	cd examples/custom-scopes && go build -v

run-example-basic: ## Run basic example
	cd examples/basic && go run main.go

run-example-production: ## Run production example
	cd examples/production && go run main.go

run-example-custom-scopes: ## Run custom-scopes example
	cd examples/custom-scopes && go run main.go

install-tools: ## Install development tools
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/tools/cmd/goimports@latest

deps: ## Download dependencies
	go mod download
	go mod verify

tidy: ## Tidy go.mod
	go mod tidy

verify: fmt vet lint test-race ## Run all verification steps

ci: verify test-coverage ## Run CI checks

update-deps: ## Update dependencies
	go get -u ./...
	go mod tidy

check-security: ## Check for security vulnerabilities
	go list -json -m all | docker run --rm -i sonatypecommunity/nancy:latest sleuth

godoc: ## Run local godoc server
	@echo "Starting godoc server at http://localhost:6060/pkg/github.com/giantswarm/mcp-oauth/"
	godoc -http=:6060

release-check: ## Check if ready for release
	@echo "Checking release readiness..."
	@git diff-index --quiet HEAD -- || (echo "Error: uncommitted changes" && exit 1)
	@grep -q "## \[Unreleased\]" CHANGELOG.md || (echo "Error: CHANGELOG.md not updated" && exit 1)
	@echo "✓ Ready for release"

# Development helpers
watch-test: ## Watch and run tests on file changes (requires entr)
	find . -name '*.go' | entr -c make test

benchmark: ## Run benchmarks
	go test -bench=. -benchmem ./...

# Generate encryption key for testing
gen-key: ## Generate encryption key
	@go run -C . -exec echo 'package main; import "fmt"; import oauth "github.com/giantswarm/mcp-oauth"; func main() { k, _ := oauth.GenerateEncryptionKey(); fmt.Println(oauth.EncryptionKeyToBase64(k)) }'

