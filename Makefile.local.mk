# Local development overrides
# This file loads last (alphabetically) to override targets from generated Makefiles

##@ Local Development

# Override the generated test target for faster local development
# The generated target in Makefile.gen.go.mk runs with -race which is very slow
.PHONY: test
test: ## Run tests (fast version for local dev, use test-race for full CI checks)
	@echo "====> $@"
	go test -v ./...

# Override the generated clean target with a more comprehensive version for library development
.PHONY: clean
clean: ## Clean build artifacts and coverage files
	@echo "====> $@"
	rm -f $(APPLICATION)* 2>/dev/null || true
	rm -f coverage.out coverage.html coverage_security.out
	rm -rf dist/ build/
	find examples -type f -name '*.exe' -delete 2>/dev/null || true
	find examples -type f ! -name '*.go' ! -name '*.mod' ! -name '*.sum' ! -name 'README.md' ! -name '*.json' -type f -executable -delete 2>/dev/null || true
	go clean

