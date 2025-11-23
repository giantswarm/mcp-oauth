# Cursor AI Rules

This directory contains rules and guidelines for AI-assisted development with Cursor AI.

## Structure

- **`rules/architecture.mdc`** - Architecture principles, testing standards, Go development style, and library design guidelines
- **`rules/dev_workflow.mdc`** - Complete development workflow including git branching, commit messages, and quality checks

## Purpose

These rules ensure that AI-assisted development:
- Follows consistent coding standards
- Maintains high test coverage (80%+)
- Adheres to proper Git workflows
- Preserves library design principles (provider abstraction, storage abstraction, separation of concerns)
- Produces well-documented, production-ready code

## Key Principles

1. **Never commit directly to `main`** - Always use feature branches
2. **Test coverage ≥ 80%** - All new code must be well-tested
3. **Format before commit** - Run `goimports` and `go fmt`
4. **Provider-agnostic design** - Core library must work with any OAuth provider
5. **Security by default** - Secure configurations out of the box

## Usage

Cursor AI will automatically apply these rules when working in this repository. The rules are declared with `alwaysApply: true` and apply to all files (`globs: **/*`).

To modify or add rules, edit the `.mdc` files in the `rules/` directory.

