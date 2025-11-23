#!/bin/bash

# Script to update package declarations and add imports for internal packages

echo "Updating clientstore package..."
sed -i 's/^package oauth$/package clientstore/' internal/clientstore/*.go
sed -i '1a\\nimport oauth "github.com/giantswarm/mcp-oauth"' internal/clientstore/store_test.go

echo "Updating tokenstore package..."
sed -i 's/^package oauth$/package tokenstore/' internal/tokenstore/*.go

echo "Updating flowstore package..."
sed -i 's/^package oauth$/package flowstore/' internal/flowstore/*.go

echo "Updating security package..."
sed -i 's/^package oauth$/package security/' internal/security/*.go

echo "Updating ratelimit package..."
sed -i 's/^package oauth$/package ratelimit/' internal/ratelimit/*.go

echo "Done with package declarations!"


