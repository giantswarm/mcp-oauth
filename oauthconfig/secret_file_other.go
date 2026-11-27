//go:build !unix

package oauthconfig

import "io/fs"

func fileOwnerOf(fs.FileInfo) fileOwner {
	return fileOwner{}
}
