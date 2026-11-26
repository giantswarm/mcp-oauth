package oauthconfig

import (
	"io/fs"
	"os"
	"slices"
)

// fileOwner is the owning user and group of a file, when the platform reports
// them.
type fileOwner struct {
	uid, gid int64
	known    bool
}

// credentials are the effective user and the groups of this process.
type credentials struct {
	uid    int64
	groups []int64
}

func processCredentials() credentials {
	process := credentials{uid: int64(os.Geteuid()), groups: []int64{int64(os.Getegid())}}
	groups, err := os.Getgroups()
	if err != nil {
		return process
	}
	for _, gid := range groups {
		process.groups = append(process.groups, int64(gid))
	}
	return process
}

// secretFileTooOpen checks mode bits against the secret-file policy. Group or
// other write access and other read access are refused. Group read access is
// allowed only when another user owns the file and its group is one of this
// process's effective or supplementary groups. All members of that group must
// be trusted. ACLs and capabilities are not evaluated. When ownership is unknown,
// group read access is refused.
func secretFileTooOpen(perm fs.FileMode, owner fileOwner, process credentials) bool {
	if perm&0o026 != 0 {
		return true
	}
	if perm&0o040 == 0 {
		return false
	}
	if !owner.known || owner.uid == process.uid {
		return true
	}
	return !slices.Contains(process.groups, owner.gid)
}
