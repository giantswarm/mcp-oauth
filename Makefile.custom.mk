# Custom targets for mcp-oauth library

##@ Library Development

.PHONY: test test-coverage test-race test-all
test: ## Run tests
	@echo "====> $@"
	go test -v ./...

test-coverage: ## Run tests with coverage
	@echo "====> $@"
	go test -v -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

test-race: ## Run tests with race detector
	@echo "====> $@"
	go test -v -race ./...

test-all: test-race test-coverage ## Run all tests
	@echo "====> $@"

##@ Code Quality

.PHONY: lint fmt vet clean
lint: ## Run linters
	@echo "====> $@"
	golangci-lint run

fmt: ## Format code
	@echo "====> $@"
	gofmt -s -w .
	goimports -w -local github.com/giantswarm/mcp-oauth .

vet: ## Run go vet
	@echo "====> $@"
	go vet ./...

clean: ## Clean build artifacts
	@echo "====> $@"
	rm -f coverage.out coverage.html
	rm -rf dist/ build/
	find examples -type f -name '*.exe' -delete
	find examples -type f ! -name '*.go' ! -name '*.mod' ! -name '*.sum' ! -name 'README.md' -type f -executable -delete 2>/dev/null || true

##@ Examples

.PHONY: build-examples run-example-basic run-example-production run-example-custom-scopes
build-examples: ## Build all examples
	@echo "====> $@"
	@echo "Building examples..."
	cd examples/basic && go build -v
	cd examples/production && go build -v
	cd examples/custom-scopes && go build -v

run-example-basic: ## Run basic example
	@echo "====> $@"
	cd examples/basic && go run main.go

run-example-production: ## Run production example
	@echo "====> $@"
	cd examples/production && go run main.go

run-example-custom-scopes: ## Run custom-scopes example
	@echo "====> $@"
	cd examples/custom-scopes && go run main.go

##@ Dependencies

.PHONY: install-tools deps tidy update-deps
install-tools: ## Install development tools
	@echo "====> $@"
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/tools/cmd/goimports@latest

deps: ## Download dependencies
	@echo "====> $@"
	go mod download
	go mod verify

tidy: ## Tidy go.mod
	@echo "====> $@"
	go mod tidy

update-deps: ## Update dependencies
	@echo "====> $@"
	go get -u ./...
	go mod tidy

##@ Verification

.PHONY: verify ci check-security
verify: fmt vet lint test-race ## Run all verification steps
	@echo "====> $@"

ci: verify test-coverage ## Run CI checks
	@echo "====> $@"

check-security: ## Check for security vulnerabilities
	@echo "====> $@"
	go list -json -m all | docker run --rm -i sonatypecommunity/nancy:latest sleuth

##@ Documentation

.PHONY: godoc
godoc: ## Run local godoc server
	@echo "====> $@"
	@echo "Starting godoc server at http://localhost:6060/pkg/github.com/giantswarm/mcp-oauth/"
	godoc -http=:6060

##@ Release

.PHONY: release-check
release-check: ## Check if ready for release
	@echo "====> $@"
	@echo "Checking release readiness..."
	@git diff-index --quiet HEAD -- || (echo "Error: uncommitted changes" && exit 1)
	@grep -q "## \[Unreleased\]" CHANGELOG.md || (echo "Error: CHANGELOG.md not updated" && exit 1)
	@echo "✓ Ready for release"

##@ Development Helpers

.PHONY: watch-test benchmark
watch-test: ## Watch and run tests on file changes (requires entr)
	@echo "====> $@"
	find . -name '*.go' | entr -c make test

benchmark: ## Run benchmarks
	@echo "====> $@"
	go test -bench=. -benchmem ./...

