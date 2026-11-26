//go:build unix

package oauthconfig

import (
	"io/fs"
	"syscall"
)

func fileOwnerOf(info fs.FileInfo) fileOwner {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileOwner{}
	}
	return fileOwner{uid: int64(stat.Uid), gid: int64(stat.Gid), known: true}
}
