# Custom targets for mcp-oauth library
# This file extends the devctl-generated Makefile.gen.go.mk with additional analysis tools

##@ Library Development

# NOTE: 'make test' is defined in Makefile.gen.go.mk and runs with -race (slow but thorough)
# For faster local iteration, use 'make test-fast' instead

.PHONY: test-fast test-coverage test-race test-all
test-fast: ## Run tests (fast, no race detector) - RECOMMENDED for local dev
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

##@ Code Formatting

.PHONY: fmt-all fmt-check gofumpt gci
fmt-all: fmt imports gofumpt gci-write ## Apply all formatting (gofmt, goimports, gofumpt, gci)
	@echo "====> $@"

fmt-check: ## Check formatting without applying changes
	@echo "====> $@"
	@echo "Checking gofmt..."
	@gofmt -s -d . | (! grep .) || (echo "gofmt check failed" && exit 1)
	@echo "Checking goimports..."
	@goimports -d -local $(MODULE) . | (! grep .) || (echo "goimports check failed" && exit 1)
	@if command -v gofumpt >/dev/null 2>&1; then \
		echo "Checking gofumpt..."; \
		gofumpt -d . | (! grep .) || (echo "gofumpt check failed" && exit 1); \
	fi
	@echo "All format checks passed"

gofumpt: ## Apply gofumpt (stricter gofmt)
	@echo "====> $@"
	@if command -v gofumpt >/dev/null 2>&1; then \
		gofumpt -w .; \
	else \
		echo "gofumpt not installed. Run: go install mvdan.cc/gofumpt@latest"; \
	fi

gci-write: ## Apply gci import ordering
	@echo "====> $@"
	@if command -v gci >/dev/null 2>&1; then \
		gci write -s standard -s default -s 'prefix($(MODULE))' --skip-generated .; \
	else \
		echo "gci not installed. Run: go install github.com/daixiang0/gci@latest"; \
	fi

gci-check: ## Check gci import ordering
	@echo "====> $@"
	@if command -v gci >/dev/null 2>&1; then \
		gci diff -s standard -s default -s 'prefix($(MODULE))' --skip-generated . | (! grep .) || (echo "gci check failed" && exit 1); \
	else \
		echo "gci not installed. Run: go install github.com/daixiang0/gci@latest"; \
	fi

##@ Static Analysis

.PHONY: staticcheck errcheck ineffassign unconvert misspell gocritic revive
staticcheck: ## Run staticcheck
	@echo "====> $@"
	@if command -v staticcheck >/dev/null 2>&1; then \
		staticcheck ./...; \
	else \
		echo "staticcheck not installed. Run: go install honnef.co/go/tools/cmd/staticcheck@latest"; \
	fi

errcheck: ## Run errcheck - find unchecked errors
	@echo "====> $@"
	@if command -v errcheck >/dev/null 2>&1; then \
		errcheck -ignoretests ./...; \
	else \
		echo "errcheck not installed. Run: go install github.com/kisielk/errcheck@latest"; \
	fi

ineffassign: ## Run ineffassign - detect ineffectual assignments
	@echo "====> $@"
	@if command -v ineffassign >/dev/null 2>&1; then \
		ineffassign ./...; \
	else \
		echo "ineffassign not installed. Run: go install github.com/gordonklaus/ineffassign@latest"; \
	fi

unconvert: ## Run unconvert - remove unnecessary type conversions
	@echo "====> $@"
	@if command -v unconvert >/dev/null 2>&1; then \
		unconvert ./...; \
	else \
		echo "unconvert not installed. Run: go install github.com/mdempsky/unconvert@latest"; \
	fi

misspell: ## Run misspell - find commonly misspelled words
	@echo "====> $@"
	@if command -v misspell >/dev/null 2>&1; then \
		find . -name '*.go' -not -path './vendor/*' -not -path './examples/*/vendor/*' | xargs misspell; \
	else \
		echo "misspell not installed. Run: go install github.com/client9/misspell/cmd/misspell@latest"; \
	fi

gocritic: ## Run gocritic - opinionated linter
	@echo "====> $@"
	@if command -v gocritic >/dev/null 2>&1; then \
		gocritic check ./...; \
	else \
		echo "gocritic not installed. Run: go install github.com/go-critic/go-critic/cmd/gocritic@latest"; \
	fi

revive: ## Run revive - fast, configurable linter
	@echo "====> $@"
	@if command -v revive >/dev/null 2>&1; then \
		revive ./...; \
	else \
		echo "revive not installed. Run: go install github.com/mgechev/revive@latest"; \
	fi

##@ Security Analysis

.PHONY: gosec govulncheck security-check trivy
gosec: ## Run gosec - security-focused linter
	@echo "====> $@"
	@if command -v gosec >/dev/null 2>&1; then \
		gosec -quiet -exclude=G101,G104,G203 -exclude-dir=examples ./...; \
	else \
		echo "gosec not installed. Run: go install github.com/securego/gosec/v2/cmd/gosec@latest"; \
	fi

govulncheck: ## Run govulncheck - official Go vulnerability checker
	@echo "====> $@"
	@if command -v govulncheck >/dev/null 2>&1; then \
		govulncheck ./...; \
	else \
		echo "govulncheck not installed. Run: go install golang.org/x/vuln/cmd/govulncheck@latest"; \
	fi

trivy: ## Run trivy filesystem scan (if installed)
	@echo "====> $@"
	@if command -v trivy >/dev/null 2>&1; then \
		trivy fs --scanners vuln,secret --severity HIGH,CRITICAL .; \
	else \
		echo "trivy not installed. See: https://aquasecurity.github.io/trivy/latest/getting-started/installation/"; \
	fi

security-check: gosec govulncheck ## Run all security checks
	@echo "====> $@"

##@ Code Quality

.PHONY: gocyclo gocognit goconst dupl quality-check
gocyclo: ## Run gocyclo - cyclomatic complexity (threshold 15, excludes tests)
	@echo "====> $@"
	@if command -v gocyclo >/dev/null 2>&1; then \
		find . -name '*.go' -not -name '*_test.go' -not -path './vendor/*' -not -path './examples/*' | xargs gocyclo -over 15; \
	else \
		echo "gocyclo not installed. Run: go install github.com/fzipp/gocyclo/cmd/gocyclo@latest"; \
	fi

gocognit: ## Run gocognit - cognitive complexity (threshold 15, excludes tests)
	@echo "====> $@"
	@if command -v gocognit >/dev/null 2>&1; then \
		find . -name '*.go' -not -name '*_test.go' -not -path './vendor/*' -not -path './examples/*' | xargs gocognit -over 15; \
	else \
		echo "gocognit not installed. Run: go install github.com/uudashr/gocognit/cmd/gocognit@latest"; \
	fi

goconst: ## Run goconst - find repeated strings (excludes tests and examples)
	@echo "====> $@"
	@if command -v goconst >/dev/null 2>&1; then \
		goconst -ignore "test" ./...; \
	else \
		echo "goconst not installed. Run: go install github.com/jgautheron/goconst/cmd/goconst@latest"; \
	fi

dupl: ## Run dupl - code duplication detection (threshold 100, excludes tests)
	@echo "====> $@"
	@if command -v dupl >/dev/null 2>&1; then \
		find . -name '*.go' -not -name '*_test.go' -not -path './vendor/*' -not -path './examples/*' | xargs dupl -threshold 100; \
	else \
		echo "dupl not installed. Run: go install github.com/mibk/dupl@latest"; \
	fi

quality-check: gocyclo gocognit goconst dupl ## Run all code quality checks
	@echo "====> $@"

##@ Dependency Analysis

.PHONY: mod-verify mod-tidy-check mod-outdated deps-check
mod-verify: ## Verify go.mod dependencies
	@echo "====> $@"
	go mod verify

mod-tidy-check: ## Check if go mod tidy would make changes
	@echo "====> $@"
	@cp go.mod go.mod.backup
	@cp go.sum go.sum.backup
	@go mod tidy
	@if ! diff -q go.mod go.mod.backup >/dev/null 2>&1 || ! diff -q go.sum go.sum.backup >/dev/null 2>&1; then \
		echo "go.mod or go.sum would be modified by 'go mod tidy'"; \
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

.PHONY: install-tools install-analyze-tools deps tidy update-deps
install-tools: ## Install essential development tools
	@echo "====> $@"
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/tools/cmd/goimports@latest

install-analyze-tools: install-tools ## Install all analysis tools
	@echo "====> $@"
	@echo "Installing formatting tools..."
	go install mvdan.cc/gofumpt@latest
	go install github.com/daixiang0/gci@latest
	@echo "Installing static analysis tools..."
	go install honnef.co/go/tools/cmd/staticcheck@latest
	go install github.com/kisielk/errcheck@latest
	go install github.com/gordonklaus/ineffassign@latest
	go install github.com/mdempsky/unconvert@latest
	go install github.com/client9/misspell/cmd/misspell@latest
	go install github.com/go-critic/go-critic/cmd/gocritic@latest
	go install github.com/mgechev/revive@latest
	@echo "Installing security tools..."
	go install github.com/securego/gosec/v2/cmd/gosec@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest
	@echo "Installing code quality tools..."
	go install github.com/fzipp/gocyclo/cmd/gocyclo@latest
	go install github.com/uudashr/gocognit/cmd/gocognit@latest
	go install github.com/jgautheron/goconst/cmd/goconst@latest
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

.PHONY: analyze-format analyze-lint analyze-security analyze-quality analyze-deps analyze-all
analyze-format: fmt-check gci-check ## Run all formatting checks
	@echo "====> $@"

analyze-lint: vet lint staticcheck errcheck ineffassign unconvert misspell gocritic revive ## Run all linting tools
	@echo "====> $@"

analyze-security: security-check ## Run all security tools
	@echo "====> $@"

analyze-quality: quality-check ## Run all code quality tools
	@echo "====> $@"

analyze-deps: deps-check mod-outdated ## Run all dependency analysis
	@echo "====> $@"

analyze-all: analyze-format analyze-lint analyze-security analyze-quality analyze-deps doc-check ## Run ALL analysis tools
	@echo "====> $@"
	@echo ""
	@echo "=========================================="
	@echo "  All analysis checks completed"
	@echo "=========================================="

##@ Verification

.PHONY: verify verify-all ci check-security
verify: fmt vet lint test-race ## Run standard verification steps
	@echo "====> $@"

verify-all: fmt-all analyze-all test-all ## Run all verification steps (comprehensive)
	@echo "====> $@"

ci: verify test-coverage ## Run CI checks
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
