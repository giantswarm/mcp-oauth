package server

import (
	"testing"

	"github.com/giantswarm/mcp-oauth/instrumentation"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/stretchr/testify/require"
)

func testInstrumentation(t testing.TB) *instrumentation.Instrumentation {
	t.Helper()
	inst, err := instrumentation.New(instrumentation.Config{})
	require.NoError(t, err)
	return inst
}

func testAuditor() *security.Auditor {
	return security.NewAuditor(nil, false)
}
