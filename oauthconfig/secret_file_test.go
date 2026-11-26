package oauthconfig

import (
	"io/fs"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSecretFileTooOpen(t *testing.T) {
	process := credentials{uid: 1000, groups: []int64{1000, 2000}}
	tests := []struct {
		name  string
		perm  fs.FileMode
		owner fileOwner
		want  bool
	}{
		{name: "owner only", perm: 0o600, owner: fileOwner{uid: 1000, gid: 1000, known: true}},
		{name: "owner read only", perm: 0o400, owner: fileOwner{uid: 1000, gid: 1000, known: true}},
		{name: "Kubernetes Secret volume with fsGroup", perm: 0o440, owner: fileOwner{uid: 0, gid: 2000, known: true}},
		{name: "own file shared with own group", perm: 0o640, owner: fileOwner{uid: 1000, gid: 1000, known: true}, want: true},
		{name: "another user's file in a foreign group", perm: 0o440, owner: fileOwner{uid: 0, gid: 3000, known: true}, want: true},
		{name: "world readable in own group", perm: 0o444, owner: fileOwner{uid: 0, gid: 2000, known: true}, want: true},
		{name: "world readable own file", perm: 0o604, owner: fileOwner{uid: 1000, gid: 1000, known: true}, want: true},
		{name: "unknown owner, group readable", perm: 0o440, want: true},
		{name: "unknown owner, owner only", perm: 0o400},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, secretFileTooOpen(tt.perm, tt.owner, process))
		})
	}
}
