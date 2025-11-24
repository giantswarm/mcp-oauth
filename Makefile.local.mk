# Local development overrides
# This file loads after Makefile.gen.go.mk to override the slow test target

##@ Local Development

# Override the generated test target for faster local development
# The generated target in Makefile.gen.go.mk runs with -race which is very slow
.PHONY: test
test: ## Run tests (fast version for local dev, use test-race for full CI checks)
	@echo "====> $@"
	go test -v ./...

