package oauthconfig

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOptionalSecret_TightPermissionsNoWarn(t *testing.T) {
	if runtime.GOOS == goosWindows {
		t.Skip("Unix mode bits not meaningful on Windows")
	}
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
	require.NotContains(t, buf.String(), "group/world readable")
}

func TestOptionalSecret_WorldReadableWarns(t *testing.T) {
	if runtime.GOOS == goosWindows {
		t.Skip("Unix mode bits not meaningful on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	require.NoError(t, os.WriteFile(path, []byte("leak-risk"), 0o644))

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	t.Setenv("OAUTH_TEST_SECRET_FILE", path)
	got, err := optionalSecret("OAUTH_TEST_SECRET")
	require.NoError(t, err, "WARN-only path must not fail the read")
	require.Equal(t, "leak-risk", got)
	require.Contains(t, buf.String(), "group/world readable")
	require.Contains(t, buf.String(), "OAUTH_TEST_SECRET_FILE")
	require.Contains(t, buf.String(), "CWE-732")
}

func TestOptionalSecret_HardFailWhenStrictModeOn(t *testing.T) {
	if runtime.GOOS == goosWindows {
		t.Skip("Unix mode bits not meaningful on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	require.NoError(t, os.WriteFile(path, []byte("leak-risk"), 0o644))

	t.Setenv("OAUTH_REQUIRE_TIGHT_SECRET_PERMISSIONS", "true")
	t.Setenv("OAUTH_TEST_SECRET_FILE", path)

	_, err := optionalSecret("OAUTH_TEST_SECRET")
	require.Error(t, err)
	require.Contains(t, err.Error(), "group/world readable")
}

func TestOptionalSecret_PlainEnvVarSkipsPermCheck(t *testing.T) {
	t.Setenv("OAUTH_REQUIRE_TIGHT_SECRET_PERMISSIONS", "true")
	t.Setenv("OAUTH_TEST_SECRET", "from-env-var")

	got, err := optionalSecret("OAUTH_TEST_SECRET")
	require.NoError(t, err)
	require.Equal(t, "from-env-var", got)
	require.False(t, strings.Contains(got, "file"))
}
