package bootstrap

import (
	"context"
	"os"
	"syscall"
	"testing"
)

func TestInitialBootstrapScratchCreatesPrivateOwnedChild(t *testing.T) {
	_, parent := bootstrapProjectionFilesFixture(t)
	if err := parent.Chmod(".", 0777); err != nil {
		t.Fatal(err)
	}
	// This is the actual fresh fsGroup mount condition: the former direct-root
	// composition must still reject it. The correction creates a distinct child.
	if old, err := openBootstrapProjectionFiles(parent); err == nil {
		old.Close()
		t.Fatal("group-writable root became private")
	}
	child, err := openBootstrapScratchChild(context.Background(), parent)
	if err != nil {
		t.Fatal("nonroot fsGroup scratch cannot create private projection", err)
	}
	defer child.Close()
	files, err := openBootstrapProjectionFiles(child)
	if err != nil {
		t.Fatal(err)
	}
	files.Close()
	st, err := child.Stat(".")
	if err != nil || st.Mode().Perm() != 0700 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		t.Fatal("child ownership/mode not exact")
	}
	again, err := openBootstrapScratchChild(context.Background(), parent)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	other, _ := again.Stat(".")
	if !os.SameFile(st, other) {
		t.Fatal("same-Pod replay replaced original directory")
	}
}

func TestInitialBootstrapScratchRejectsAliasAndForeignMetadata(t *testing.T) {
	for _, kind := range []string{"symlink", "shared", "file"} {
		t.Run(kind, func(t *testing.T) {
			_, parent := bootstrapProjectionFilesFixture(t)
			switch kind {
			case "symlink":
				if err := parent.Mkdir("other", 0700); err != nil {
					t.Fatal(err)
				}
				if err := parent.Symlink("other", "projection"); err != nil {
					t.Fatal(err)
				}
			case "shared":
				if err := parent.Mkdir("projection", 0750); err != nil {
					t.Fatal(err)
				}
			case "file":
				if err := parent.WriteFile("projection", []byte("occupied"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := parent.Lstat("projection")
			if child, err := openBootstrapScratchChild(context.Background(), parent); err == nil {
				child.Close()
				t.Fatal("foreign/shared path adopted")
			}
			after, _ := parent.Lstat("projection")
			if !os.SameFile(before, after) || before.Mode() != after.Mode() {
				t.Fatal("rejected path mutated")
			}
		})
	}
	_, parent := bootstrapProjectionFilesFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if child, err := openBootstrapScratchChild(ctx, parent); err == nil {
		child.Close()
		t.Fatal("canceled phase created projection")
	}
	if _, err := parent.Stat("projection"); !os.IsNotExist(err) {
		t.Fatal("canceled phase mutated parent")
	}
	st, err := parent.Stat(".")
	if err != nil {
		t.Fatal(err)
	}
	original := *st.Sys().(*syscall.Stat_t)
	foreign := original
	foreign.Uid = uint32(os.Geteuid() + 1)
	if bootstrapScratchMetadata(bootstrapScratchTestInfo{FileInfo: st, sys: &foreign}, true) {
		t.Fatal("foreign private owner accepted")
	}
	foreign = original
	foreign.Gid = uint32(os.Getegid() + 1)
	if bootstrapScratchMetadata(bootstrapScratchTestInfo{FileInfo: st, sys: &foreign}, false) {
		t.Fatal("unexpected scratch group accepted")
	}
}

type bootstrapScratchTestInfo struct {
	os.FileInfo
	sys *syscall.Stat_t
}

func (s bootstrapScratchTestInfo) Sys() any { return s.sys }
