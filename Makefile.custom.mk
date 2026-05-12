# Custom targets for mcp-oauth library
# This file extends the devctl-generated Makefile.gen.go.mk with additional analysis tools

# Examples have no go.mod (generated at build time), so exclude them from analysis.
GO_PACKAGES := $(shell go list ./... 2>/dev/null | grep -v /examples/)

##@ Library Development

.PHONY: test-fast test-coverage test-race
test-fast: ## Run tests (fast, no race detector) - RECOMMENDED for local dev
	@echo "====> $@"
	go test -v ./...

test-coverage: ## Run tests with coverage and race detector
	@echo "====> $@"
	go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

test-race: ## Run tests with race detector (no coverage report)
	@echo "====> $@"
	go test -v -race ./...

##@ Code Formatting

.PHONY: fmt-all fmt-check gofumpt
fmt-all: fmt imports gofumpt ## Apply all formatting (gofmt, goimports, gofumpt)
	@echo "====> $@"

fmt-check: ## Check formatting without applying changes
	@echo "====> $@"
	@echo "Checking gofmt..."
	@gofmt -s -d . | (! grep .) || (echo "gofmt check failed" && exit 1)
	@echo "Checking goimports..."
	@goimports -d -local $(MODULE) . | (! grep .) || (echo "goimports check failed" && exit 1)
	@echo "Checking gofumpt..."
	@command -v gofumpt >/dev/null 2>&1 || (echo "ERROR: gofumpt not installed. Run: go install mvdan.cc/gofumpt@latest" && exit 1)
	@gofumpt -d . | (! grep .) || (echo "gofumpt check failed" && exit 1)
	@echo "All format checks passed"

gofumpt: ## Apply gofumpt (stricter gofmt)
	@echo "====> $@"
	@command -v gofumpt >/dev/null 2>&1 || (echo "ERROR: gofumpt not installed. Run: go install mvdan.cc/gofumpt@latest" && exit 1)
	gofumpt -w .

##@ Security Analysis

.PHONY: gosec govulncheck security-check trivy
gosec: ## Run gosec - security-focused linter
	@echo "====> $@"
	@command -v gosec >/dev/null 2>&1 || (echo "ERROR: gosec not installed. Run: go install github.com/securego/gosec/v2/cmd/gosec@latest" && exit 1)
	gosec -quiet -exclude=G101,G104,G117,G118,G203,G704 -exclude-dir=examples ./...

govulncheck: ## Run govulncheck - official Go vulnerability checker
	@echo "====> $@"
	@command -v govulncheck >/dev/null 2>&1 || (echo "ERROR: govulncheck not installed. Run: go install golang.org/x/vuln/cmd/govulncheck@latest" && exit 1)
	govulncheck $(GO_PACKAGES)

trivy: ## Run trivy filesystem scan
	@echo "====> $@"
	@command -v trivy >/dev/null 2>&1 || (echo "ERROR: trivy not installed. See: https://aquasecurity.github.io/trivy/latest/getting-started/installation/" && exit 1)
	trivy fs --scanners vuln,secret --severity HIGH,CRITICAL .

security-check: gosec govulncheck ## Run all security checks
	@echo "====> $@"

##@ Code Quality

.PHONY: gocyclo gocognit dupl quality-check
gocyclo: ## Run gocyclo - cyclomatic complexity (threshold 15, excludes tests)
	@echo "====> $@"
	@command -v gocyclo >/dev/null 2>&1 || (echo "ERROR: gocyclo not installed. Run: go install github.com/fzipp/gocyclo/cmd/gocyclo@latest" && exit 1)
	find . -name '*.go' -not -name '*_test.go' -not -path './vendor/*' -not -path './examples/*' | xargs gocyclo -over 15

gocognit: ## Run gocognit - cognitive complexity (threshold 15, excludes tests)
	@echo "====> $@"
	@command -v gocognit >/dev/null 2>&1 || (echo "ERROR: gocognit not installed. Run: go install github.com/uudashr/gocognit/cmd/gocognit@latest" && exit 1)
	find . -name '*.go' -not -name '*_test.go' -not -path './vendor/*' -not -path './examples/*' | xargs gocognit -over 15

dupl: ## Run dupl - code duplication detection (threshold 100, excludes tests)
	@echo "====> $@"
	@command -v dupl >/dev/null 2>&1 || (echo "ERROR: dupl not installed. Run: go install github.com/mibk/dupl@latest" && exit 1)
	find . -name '*.go' -not -name '*_test.go' -not -path './vendor/*' -not -path './examples/*' | xargs dupl -threshold 100

quality-check: gocyclo gocognit dupl ## Run all code quality checks
	@echo "====> $@"

##@ Dependency Analysis

.PHONY: mod-verify mod-tidy-check mod-outdated deps-check
mod-verify: ## Verify go.mod dependencies
	@echo "====> $@"
	go mod verify

mod-tidy-check: clean-examples ## Check if go mod tidy would make changes
	@echo "====> $@"
	@cp go.mod go.mod.backup
	@cp go.sum go.sum.backup
	@go mod tidy
	@if ! diff -q go.mod go.mod.backup >/dev/null 2>&1 || ! diff -q go.sum go.sum.backup >/dev/null 2>&1; then \
		echo "go.mod or go.sum would be modified by 'go mod tidy'"; \
		diff go.mod go.mod.backup || true; \
		mv go.mod.backup go.mod; \
		mv go.sum.backup go.sum; \
		exit 1; \
	fi
	@rm -f go.mod.backup go.sum.backup
	@echo "go.mod is tidy"

mod-outdated: ## Check for outdated dependencies (informational)
	@echo "====> $@"
	@outdated=$$(go list -m -u -json all 2>/dev/null | jq -r 'select(.Update) | "\(.Path): \(.Version) -> \(.Update.Version)"'); \
	if [ -n "$$outdated" ]; then \
		echo "WARNING: Outdated dependencies found:"; \
		echo "$$outdated"; \
		echo ""; \
		echo "Please update dependencies by running: go get -u ./... && go mod tidy"; \
	else \
		echo "All dependencies are up to date"; \
	fi

deps-check: mod-verify mod-tidy-check ## Run all dependency checks
	@echo "====> $@"

##@ Documentation Checks

.PHONY: doc-check
doc-check: ## Check for missing doc.go files in packages
	@echo "====> $@"
	@missing=""; \
	for dir in $$(find . -type d -not -path './vendor/*' -not -path './.git/*' -not -path './examples/*'); do \
		if ls "$$dir"/*.go >/dev/null 2>&1 && [ ! -f "$$dir/doc.go" ]; then \
			missing="$$missing\n  $$dir"; \
		fi; \
	done; \
	if [ -n "$$missing" ]; then \
		echo "Packages missing doc.go:$$missing"; \
	else \
		echo "All packages have doc.go files"; \
	fi

##@ Examples

EXAMPLES := $(shell find examples -mindepth 1 -maxdepth 1 -type d | sort)
GO_VERSION := $(shell grep '^go ' go.mod | awk '{print $$2}')

.PHONY: init-examples
init-examples: ## Generate go.mod stubs for all examples (no build)
	@for dir in $(EXAMPLES); do \
		name=$$(basename $$dir); \
		printf 'module %s/examples/%s\n\ngo %s\n\nreplace %s => ../..\n' \
			"$(MODULE)" "$$name" "$(GO_VERSION)" "$(MODULE)" > "$$dir/go.mod"; \
	done

.PHONY: build-examples
build-examples: init-examples ## Build all examples (generates go.mod from root module)
	@echo "====> $@"
	@for dir in $(EXAMPLES); do \
		name=$$(basename $$dir); \
		echo "Building example: $$name ..."; \
		(cd "$$dir" && go mod tidy -v && go build -v ./...) || exit 1; \
	done
	@echo "All examples built successfully"

.PHONY: clean-examples
clean-examples: ## Remove generated go.mod/go.sum and binaries from examples
	@echo "====> $@"
	@for dir in $(EXAMPLES); do \
		rm -f "$$dir/go.mod" "$$dir/go.sum"; \
	done
	find examples -type f -name '*.exe' -delete 2>/dev/null || true
	find examples -type f ! -name '*.go' ! -name 'README.md' ! -name '*.json' -type f -executable -delete 2>/dev/null || true

##@ Dependencies

.PHONY: install-tools install-analyze-tools deps tidy update-deps
install-tools: ## Install essential development tools
	@echo "====> $@"
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/tools/cmd/goimports@latest

install-analyze-tools: install-tools ## Install all analysis tools
	@echo "====> $@"
	@echo "Installing formatting tools..."
	go install mvdan.cc/gofumpt@latest
	@echo "Installing security tools..."
	go install github.com/securego/gosec/v2/cmd/gosec@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest
	@echo "Installing code quality tools..."
	go install github.com/fzipp/gocyclo/cmd/gocyclo@latest
	go install github.com/uudashr/gocognit/cmd/gocognit@latest
	go install github.com/mibk/dupl@latest
	@echo "All analysis tools installed"

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

##@ Aggregate Analysis Targets

.PHONY: analyze-all
analyze-all: fmt-check vet lint gosec quality-check deps-check doc-check ## Run ALL analysis (golangci-lint includes most linters)
	@echo "====> $@"
	@echo ""
	@echo "=========================================="
	@echo "  All analysis checks completed"
	@echo "=========================================="

##@ Verification

.PHONY: verify ci check-security
verify: init-examples analyze-all test-coverage ## Run all verification steps (read-only; use `fmt-all` first locally to apply formatters)
	@echo "====> $@"

ci: verify ## Run CI checks (alias for verify)
	@echo "====> $@"

check-security: security-check ## Alias for security-check
	@echo "====> $@"

##@ Documentation

.PHONY: godoc
godoc: ## Run local godoc server
	@echo "====> $@"
	@echo "Starting godoc server at http://localhost:6060/pkg/$(MODULE)/"
	godoc -http=:6060

##@ Release

.PHONY: release-check
release-check: ## Check if ready for release
	@echo "====> $@"
	@echo "Checking release readiness..."
	@git diff-index --quiet HEAD -- || (echo "Error: uncommitted changes" && exit 1)
	@grep -q "## \[Unreleased\]" CHANGELOG.md || (echo "Error: CHANGELOG.md not updated" && exit 1)
	@echo "Ready for release"

##@ Development Helpers

.PHONY: watch-test benchmark
watch-test: ## Watch and run tests on file changes (requires entr)
	@echo "====> $@"
	find . -name '*.go' | entr -c make test

benchmark: ## Run benchmarks
	@echo "====> $@"
	go test -bench=. -benchmem ./...
