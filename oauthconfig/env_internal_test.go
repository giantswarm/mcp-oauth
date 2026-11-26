package oauthconfig

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOptionalSecret_TightPermissionsNoWarn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	require.NoError(t, os.WriteFile(path, []byte("s3cret"), 0o600))

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	t.Setenv("OAUTH_TEST_SECRET_FILE", path)
	got, err := optionalSecret("OAUTH_TEST_SECRET")
	require.NoError(t, err)
	require.Equal(t, "s3cret", got)
	require.Empty(t, buf.String())
}

func TestOptionalSecret_WorldReadableWarns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	require.NoError(t, os.WriteFile(path, []byte("leak-risk"), 0o644)) //nolint:gosec // G306 intentional: world-readable mode exercises the permission-warning path under test

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	t.Setenv("OAUTH_TEST_SECRET_FILE", path)
	got, err := optionalSecret("OAUTH_TEST_SECRET")
	require.NoError(t, err, "WARN-only path must not fail the read")
	require.Equal(t, "leak-risk", got)
	require.Contains(t, buf.String(), "unsafe permissions")
	require.Contains(t, buf.String(), "OAUTH_TEST_SECRET_FILE")
	require.Contains(t, buf.String(), "CWE-732")
}

func TestOptionalSecret_OwnGroupReadableFileWarns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	require.NoError(t, os.WriteFile(path, []byte("leak-risk"), 0o640)) //nolint:gosec // G306 intentional: a group-readable file this process owns could be 0600

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	t.Setenv("OAUTH_TEST_SECRET_FILE", path)
	_, err := optionalSecret("OAUTH_TEST_SECRET")
	require.NoError(t, err)
	require.Contains(t, buf.String(), "unsafe permissions")
}

func TestOptionalSecret_HardFailWhenStrictModeOn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	require.NoError(t, os.WriteFile(path, []byte("leak-risk"), 0o644)) //nolint:gosec // G306 intentional: world-readable mode exercises the strict-mode hard-fail path under test

	t.Setenv("OAUTH_REQUIRE_TIGHT_SECRET_PERMISSIONS", "true")
	t.Setenv("OAUTH_TEST_SECRET_FILE", path)

	_, err := optionalSecret("OAUTH_TEST_SECRET")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsafe permissions")
}

func TestOptionalSecret_PlainEnvVarSkipsPermCheck(t *testing.T) {
	t.Setenv("OAUTH_REQUIRE_TIGHT_SECRET_PERMISSIONS", "true")
	t.Setenv("OAUTH_TEST_SECRET", "from-env-var")

	got, err := optionalSecret("OAUTH_TEST_SECRET")
	require.NoError(t, err)
	require.Equal(t, "from-env-var", got)
	require.NotContains(t, got, "file")
}
