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

// secretFileTooOpen reports whether a secret file with mode perm is readable
// by other local accounts although a tighter mode would still let this process
// read it. A world-readable file always is. A group-readable file is not when
// another user owns it and its group is one of this process's groups: the
// group bit is then the only way the process reads it, as for a Kubernetes
// Secret volume, which the kubelet mounts root-owned with mode 0440 and the
// pod's fsGroup. When the owner is unknown, any group or world bit counts.
func secretFileTooOpen(perm fs.FileMode, owner fileOwner, process credentials) bool {
	if perm&0o004 != 0 {
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
