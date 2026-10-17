package bootstrap

import (
	"context"
	"errors"
	"os"
	"syscall"

	"asservat.local/asservat/internal/adapters/mounts"
	"golang.org/x/sys/unix"
)

// The fixed dedicated scratch mount may retain native emptyDir permissions. Private
// projections live only in this process-owned child; existing foreign/shared
// paths are never chmod-ed or adopted. Each later phase mounts just its subPath.
func openInitialBootstrapProjectionRoot(ctx context.Context) (*os.Root, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, mounts.ErrUnavailable
	}
	before, err := os.Lstat(InitialBootstrapScratchRoot)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, mounts.ErrUnavailable
	}
	parent, err := os.OpenRoot(InitialBootstrapScratchRoot)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	defer parent.Close()
	after, err := parent.Stat(".")
	if err != nil || !os.SameFile(before, after) {
		return nil, mounts.ErrUnavailable
	}
	return openBootstrapScratchChild(ctx, parent)
}

func bootstrapScratchMetadata(st os.FileInfo, private bool) bool {
	if st == nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return false
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	if private {
		return sys.Uid == uint32(os.Geteuid()) && st.Mode().Perm() == 0700
	}
	return (sys.Uid == 0 || sys.Uid == uint32(os.Geteuid())) && sys.Gid == uint32(os.Getegid())
}

func openBootstrapScratchChild(ctx context.Context, parent *os.Root) (*os.Root, error) {
	if ctx == nil || ctx.Err() != nil || parent == nil {
		return nil, mounts.ErrUnavailable
	}
	f, err := parent.Open(".")
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	defer f.Close()
	st, err := f.Stat()
	var fs unix.Statfs_t
	if err != nil || !bootstrapScratchMetadata(st, false) || unix.Fstatfs(int(f.Fd()), &fs) != nil || fs.Type != unix.TMPFS_MAGIC {
		return nil, mounts.ErrUnavailable
	}
	if err = parent.Mkdir("projection", 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, mounts.ErrUnavailable
	}
	before, err := parent.Lstat("projection")
	if err != nil || !bootstrapScratchMetadata(before, true) {
		return nil, mounts.ErrUnavailable
	}
	child, err := parent.OpenRoot("projection")
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	after, err := child.Stat(".")
	if err != nil || !bootstrapScratchMetadata(after, true) || !os.SameFile(before, after) || ctx.Err() != nil {
		child.Close()
		return nil, mounts.ErrUnavailable
	}
	opened, err := child.Open(".")
	if err != nil {
		child.Close()
		return nil, mounts.ErrUnavailable
	}
	var childFS unix.Statfs_t
	fsErr := unix.Fstatfs(int(opened.Fd()), &childFS)
	closeErr := opened.Close()
	if fsErr != nil || closeErr != nil || childFS.Type != unix.TMPFS_MAGIC || ctx.Err() != nil {
		child.Close()
		return nil, mounts.ErrUnavailable
	}
	return child, nil
}
