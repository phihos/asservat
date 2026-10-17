// Package mounts reads bounded installation-owned projected files. It neither
// selects a credential path from public input nor supplies fallback credentials.
package mounts

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
)

var ErrUnavailable = errors.New("protected mounted file unavailable")

// Read opens each projection afresh, follows only symlinks confined to root,
// then reads one nonblocking-opened regular-file descriptor. This supports
// Kubernetes AtomicWriter rotation but rejects FIFOs before waiting for a peer.
// Qualified local projection storage is required; this cannot interrupt a
// kernel stuck reading a broken remote filesystem. The process owns containment.
func Read(ctx context.Context, root *os.Root, name string, limit int64) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || root == nil || !filepath.IsLocal(name) || len(name) > 512 || limit < 1 || limit > 16<<20 {
		return nil, ErrUnavailable
	}
	f, err := open(root, name)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > limit || info.Mode().Perm()&0022 != 0 || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || len(b) < 1 || int64(len(b)) > limit || ctx.Err() != nil {
		clear(b)
		return nil, ErrUnavailable
	}
	return b, nil
}
