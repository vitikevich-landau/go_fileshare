package server

import (
	"strings"
	"testing"

	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

// TestListDirFrameSizeGuard covers CR-10: a listing that would exceed the frame
// limit is refused (so the server never emits an oversize frame the client
// would reject), while a normal listing encodes fine.
func TestListDirFrameSizeGuard(t *testing.T) {
	small := []proto.DirEntry{{Name: "a.txt", Size: 1}, {Name: "dir", Kind: proto.KindDir}}
	if _, ok := listDirFrame("/", small); !ok {
		t.Fatal("a small listing should fit in one frame")
	}

	// ~16k max-length names comfortably exceed the 4 MiB payload ceiling.
	name := strings.Repeat("x", proto.MaxNameLen)
	big := make([]proto.DirEntry, 16000)
	for i := range big {
		big[i] = proto.DirEntry{Name: name, Size: 1, Mtime: 1}
	}
	if _, ok := listDirFrame("/", big); ok {
		t.Fatal("an oversize listing must be refused, not framed")
	}
}
