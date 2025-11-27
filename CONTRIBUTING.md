# Contributing to mcp-oauth

Thank you for your interest in contributing to mcp-oauth! This document provides guidelines and instructions for contributing.

## Code of Conduct

This project adheres to a code of conduct that all contributors are expected to follow. Please be respectful and constructive in all interactions.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, include:

- **Clear title and description**
- **Steps to reproduce** the problem
- **Expected behavior** vs actual behavior
- **Version information** (Go version, library version, OS)
- **Code samples** or test cases if applicable
- **Logs or error messages** (sanitized to remove sensitive data)

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion:

- Use a **clear and descriptive title**
- Provide a **detailed description** of the proposed functionality
- Explain **why this enhancement would be useful**
- List any **alternative solutions** you've considered

### Security Vulnerabilities

**Do not report security vulnerabilities through public GitHub issues.**

Please follow our [Security Policy](SECURITY.md) to report vulnerabilities responsibly.

## Development Process

### Setting Up Development Environment

1. **Fork and clone** the repository:
   ```bash
   git clone https://github.com/YOUR_USERNAME/mcp-oauth.git
   cd mcp-oauth
   ```

2. **Install Go** (version 1.21 or later):
   ```bash
   go version  # Should be 1.21+
   ```

3. **Install development dependencies**:
   ```bash
   go mod download
   ```

4. **Run tests** to verify setup:
   ```bash
   go test ./...
   ```

### Making Changes

1. **Create a branch** for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/your-bug-fix
   ```

2. **Make your changes** following our coding standards (see below)

3. **Write tests** for your changes:
   - Add unit tests for new functionality
   - Update existing tests if behavior changes
   - Aim for high test coverage

4. **Run tests and linters**:
   ```bash
   # Run all tests
   go test ./...
   
   # Run with coverage
   go test -cover ./...
   
   # Run with race detector
   go test -race ./...
   
   # Run linters (if golangci-lint is installed)
   golangci-lint run
   
   # Format code
   go fmt ./...
   ```

5. **Update documentation**:
   - Update godoc comments for any changed public APIs
   - Update README.md if adding features
   - Add examples for new functionality

6. **Commit your changes**:
   ```bash
   git add .
   git commit -m "feat: add new feature X"
   ```
   
   Follow [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat:` new features
   - `fix:` bug fixes
   - `docs:` documentation changes
   - `test:` test additions or changes
   - `refactor:` code refactoring
   - `perf:` performance improvements
   - `chore:` maintenance tasks

### Pull Request Process

1. **Push your branch**:
   ```bash
   git push origin feature/your-feature-name
   ```

2. **Create a Pull Request** on GitHub with:
   - Clear title describing the change
   - Detailed description of what changed and why
   - Link to any related issues
   - Screenshots or examples if applicable

3. **Address review feedback**:
   - Respond to reviewer comments
   - Make requested changes
   - Push updates to your branch

4. **Merge requirements**:
   - All tests must pass
   - Code coverage should not decrease
   - At least one approving review
   - No merge conflicts
   - Follows coding standards

## Coding Standards

### Go Style Guide

Follow the [Effective Go](https://golang.org/doc/effective_go.html) guidelines and these additional standards:

1. **Code Formatting**:
   - Use `go fmt` on all code
   - Use `gofmt -s` for simplifications
   - Maximum line length: ~100 characters

2. **Naming Conventions**:
   - Use `MixedCaps` or `mixedCaps` (not underscores)
   - Short, concise names for local variables
   - Descriptive names for exported functions/types
   - Package names: lowercase, single word

3. **Documentation**:
   - All exported types, functions, constants have godoc comments
   - Comments start with the name of the thing being described
   - Package comment in `doc.go` file
   - Example code in `_test.go` files

4. **Error Handling**:
   - Always check errors
   - Provide context when wrapping errors
   - Use custom error types when appropriate
   - Don't panic in library code

5. **Testing**:
   - Table-driven tests preferred
   - Test file names: `*_test.go`
   - Test function names: `TestXxx`
   - Use subtests for variations: `t.Run("case name", ...)`

6. **Security**:
   - Never log sensitive data (tokens, passwords, PII)
   - Use crypto/rand for random generation
   - Validate all user input
   - Follow OWASP guidelines

### Project Structure

```
mcp-oauth/
├── *.go              # Library source files
├── *_test.go         # Test files (same directory as source)
├── examples/         # Example code
│   ├── basic/
│   ├── production/
│   └── custom-scopes/
├── .github/          # GitHub workflows and templates
│   ├── workflows/
│   └── ISSUE_TEMPLATE/
├── README.md         # Project documentation
├── CONTRIBUTING.md   # This file
├── SECURITY.md       # Security policy
├── LICENSE           # Apache 2.0 license
├── CHANGELOG.md      # Version history
└── go.mod            # Go module definition
```

### Testing Guidelines

1. **Unit Tests**:
   - Test all public APIs
   - Test error conditions
   - Test edge cases
   - Use table-driven tests

2. **Example Tests**:
   ```go
   func ExampleNewHandler() {
       // Create a handler with a server
       handler := oauth.NewHandler(server, logger)
       _ = handler
       // Output:
   }
   ```

3. **Benchmark Tests**:
   ```go
   func BenchmarkTokenValidation(b *testing.B) {
       // Setup...
       b.ResetTimer()
       for i := 0; i < b.N; i++ {
           // Test code
       }
   }
   ```

4. **Coverage**:
   - Aim for >80% code coverage
   - Focus on critical paths
   - Don't game coverage metrics

## Documentation

### Godoc Comments

```go
// NewHandler creates a new OAuth handler with the provided configuration.
// It validates the configuration and initializes all required components.
//
// The handler implements both OAuth 2.1 Authorization Server (proxying to Google)
// and Resource Server (validating tokens) functionality.
//
// Returns an error if the configuration is invalid or initialization fails.
func NewHandler(config *Config) (*Handler, error) {
    // ...
}
```

### README Updates

When adding features, update README.md:
- Add to feature list if significant
- Add configuration options
- Add examples
- Update API reference

### Examples

Provide working examples in `examples/` directory:
```go
// examples/basic/main.go
package main

import (
    oauth "github.com/giantswarm/mcp-oauth"
)

func main() {
    // Complete working example
}
```

## Release Process

(For maintainers)

1. Update `CHANGELOG.md` with all changes
2. Update version in documentation
3. Create and push a git tag: `git tag -a v1.2.3 -m "Release v1.2.3"`
4. GitHub Actions will automatically build and release

## Questions?

- **General questions**: Use [GitHub Discussions](https://github.com/giantswarm/mcp-oauth/discussions)
- **Bug reports**: [GitHub Issues](https://github.com/giantswarm/mcp-oauth/issues)
- **Security**: See [SECURITY.md](SECURITY.md)

## Recognition

Contributors will be recognized in:
- Git commit history
- GitHub contributors page
- Release notes (for significant contributions)

Thank you for contributing to mcp-oauth!

