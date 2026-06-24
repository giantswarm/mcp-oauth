# Custom targets for the mcp-oauth library.
# Extends the devctl-generated Makefile.gen.go.mk.
#
# The extra quality linters that used to run as bespoke targets here
# (gofumpt, gocyclo, gocognit, dupl) now live in .golangci.yml and run via the
# platform-standard pre-commit golangci-lint hook. gofmt/goimports/go-vet/
# go-mod-tidy/gosec are likewise covered by pre-commit and the architect orb.

MODULE ?= $(shell go list -m)

##@ Examples

# Examples are standalone modules whose go.mod is generated at build time via a
# `replace` directive (see init-examples). They are excluded from analysis and
# from the root module, but building them catches library API breakage.
EXAMPLES := $(shell find examples -mindepth 1 -maxdepth 1 -type d | sort)
GO_VERSION := $(shell grep '^go ' go.mod | awk '{print $$2}')

# The architect go-build job runs `make test` (test_target: test). Building the
# examples used to be a separate ci.yml job; wire it into `make test` so CI and
# local runs share one command. This only adds a prerequisite -- the generated
# `go test` recipe in Makefile.gen.go.mk is not overridden.
test: build-examples

.PHONY: init-examples
init-examples: ## Generate go.mod stubs for all examples (no build).
	@for dir in $(EXAMPLES); do \
		name=$$(basename $$dir); \
		printf 'module %s/examples/%s\n\ngo %s\n\nreplace %s => ../..\n' \
			"$(MODULE)" "$$name" "$(GO_VERSION)" "$(MODULE)" > "$$dir/go.mod"; \
	done

.PHONY: build-examples
build-examples: init-examples ## Build all examples (generates go.mod from the root module).
	@echo "====> $@"
	@for dir in $(EXAMPLES); do \
		name=$$(basename $$dir); \
		echo "Building example: $$name ..."; \
		(cd "$$dir" && go mod tidy -v && go build -v ./...) || exit 1; \
	done
	@echo "All examples built successfully"

.PHONY: clean-examples
clean-examples: ## Remove generated go.mod/go.sum and binaries from examples.
	@echo "====> $@"
	@for dir in $(EXAMPLES); do \
		rm -f "$$dir/go.mod" "$$dir/go.sum"; \
	done
	find examples -type f -name '*.exe' -delete 2>/dev/null || true
	find examples -type f ! -name '*.go' ! -name 'README.md' ! -name '*.json' -type f -executable -delete 2>/dev/null || true

##@ Development Helpers

.PHONY: test-fast benchmark godoc
test-fast: ## Run tests fast (no race detector) -- RECOMMENDED for local dev.
	@echo "====> $@"
	go test -v ./...

benchmark: ## Run benchmarks.
	@echo "====> $@"
	go test -bench=. -benchmem ./...

godoc: ## Run a local godoc server.
	@echo "====> $@"
	@echo "Starting godoc server at http://localhost:6060/pkg/$(MODULE)/"
	godoc -http=:6060
