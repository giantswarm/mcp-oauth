//go:build unix

package oauthconfig

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOptionalSecret_GroupAccess(t *testing.T) {
	if directory := os.Getenv("OAUTH_TEST_GROUP_SECRET_DIRECTORY"); directory != "" {
		testGroupSecretFiles(t, directory)
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root to create cross-UID fixtures and start an unprivileged subprocess")
	}

	directory := t.TempDir()
	// The unprivileged subprocess needs search access through both temporary directories.
	require.NoError(t, os.Chmod(filepath.Dir(directory), 0o755)) //nolint:gosec // G302: search access for the test subprocess
	require.NoError(t, os.Chmod(directory, 0o755))               //nolint:gosec // G302: search access for the test subprocess

	executable, err := os.Executable()
	require.NoError(t, err)
	binary, err := os.ReadFile(executable) // #nosec G304 G703 -- the running test executable
	require.NoError(t, err)
	binaryPath := filepath.Join(directory, "oauthconfig.test")
	require.NoError(t, os.WriteFile(binaryPath, binary, 0o700)) //nolint:gosec // G306: executable test fixture
	require.NoError(t, os.Chmod(binaryPath, 0o555))             //nolint:gosec // G302: the unprivileged subprocess must execute the test binary

	for _, fixture := range groupSecretFixtures() {
		path := filepath.Join(directory, fixture.name)
		require.NoError(t, os.WriteFile(path, []byte("mounted-secret\n"), 0o600))
		require.NoError(t, os.Chmod(path, fixture.mode)) //nolint:gosec // G302: permission-policy fixtures include unsafe modes
		require.NoError(t, os.Chown(path, fixture.uid, fixture.gid))
	}

	command := exec.CommandContext(t.Context(), binaryPath, "-test.run=^TestOptionalSecret_GroupAccess$", "-test.v") // #nosec G204 -- the running test executable copied into a private test directory
	command.Dir = directory
	command.Env = []string{"OAUTH_TEST_GROUP_SECRET_DIRECTORY=" + directory}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1000, Gid: 1000, Groups: []uint32{2000}}}
	output, err := command.CombinedOutput()
	require.NoError(t, err, "%s", output)
}

type groupSecretFixture struct {
	name     string
	mode     os.FileMode
	uid, gid int
	unsafe   bool
}

func groupSecretFixtures() []groupSecretFixture {
	return []groupSecretFixture{
		{name: "primary-group", mode: 0o440, gid: 1000},
		{name: "supplementary-group", mode: 0o440, gid: 2000},
		{name: "owner-writable", mode: 0o640, gid: 2000},
		{name: "world-readable", mode: 0o444, gid: 2000, unsafe: true},
		{name: "group-writable", mode: 0o460, gid: 2000, unsafe: true},
		{name: "world-writable", mode: 0o442, gid: 2000, unsafe: true},
		{name: "owned-group-readable", mode: 0o640, uid: 1000, gid: 1000, unsafe: true},
		{name: "owned-group-writable", mode: 0o620, uid: 1000, gid: 1000, unsafe: true},
		{name: "owned-world-writable", mode: 0o602, uid: 1000, gid: 1000, unsafe: true},
	}
}

func testGroupSecretFiles(t *testing.T, directory string) {
	t.Helper()
	require.Equal(t, 1000, os.Geteuid())
	require.Equal(t, 1000, os.Getegid())
	groups, err := os.Getgroups()
	require.NoError(t, err)
	require.Contains(t, groups, 2000)

	for _, fixture := range groupSecretFixtures() {
		for _, strict := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/strict=%t", fixture.name, strict), func(t *testing.T) {
				var logs bytes.Buffer
				previous := slog.Default()
				slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
				t.Cleanup(func() { slog.SetDefault(previous) })
				t.Setenv("OAUTH_REQUIRE_TIGHT_SECRET_PERMISSIONS", fmt.Sprint(strict))
				path := filepath.Join(directory, fixture.name)
				t.Setenv("OAUTH_TEST_SECRET_FILE", path)

				secret, err := optionalSecret("OAUTH_TEST_SECRET")
				if fixture.unsafe && strict {
					require.ErrorContains(t, err, "unsafe permissions")
					require.NotContains(t, err.Error(), "mounted-secret")
					require.Empty(t, secret)
					require.Empty(t, logs.String())
					return
				}
				require.NoError(t, err)
				require.Equal(t, "mounted-secret", secret)
				if fixture.unsafe {
					require.Contains(t, logs.String(), `"cwe":"CWE-732"`)
					require.Contains(t, logs.String(), `"env_var":"OAUTH_TEST_SECRET_FILE"`)
					require.Contains(t, logs.String(), fmt.Sprintf(`"path":%q`, path))
					require.Contains(t, logs.String(), fmt.Sprintf(`"mode":"%#o"`, fixture.mode))
					require.NotContains(t, logs.String(), "mounted-secret")
				} else {
					require.Empty(t, logs.String())
				}
			})
		}
	}
}
