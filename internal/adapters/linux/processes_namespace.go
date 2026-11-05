//go:build linux

package linux

import (
	"context"
	"os"
	"runtime"

	execution "asservat.local/asservat/internal/application/execution"
	"asservat.local/asservat/internal/domain/artifact"
	"golang.org/x/sys/unix"
)

// Capture uses the same joined, restored cgroup-namespace pattern as the
// qualified argument reader. It changes the reading thread's view only, never
// process cgroup membership, mounts, another namespace or application state.
func (s *ProcessSnapshots) Capture(ctx context.Context, r execution.ProcessSnapshotRequest) (artifact.ProcessInventory, error) {
	return s.captureInNodeNamespace(ctx, r, os.Open, unix.Setns)
}

func (s *ProcessSnapshots) captureInNodeNamespace(ctx context.Context, r execution.ProcessSnapshotRequest, open func(string) (*os.File, error), setns func(int, int) error) (artifact.ProcessInventory, error) {
	if s == nil || s.now == nil || ctx == nil || ctx.Err() != nil || !r.Valid() || !s.now().Before(r.Deadline) || s.now().Before(r.NotBefore) {
		return artifact.ProcessInventory{}, ErrProcessUnavailable
	}
	type result struct {
		value artifact.ProcessInventory
		err   error
	}
	done := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		restored := true
		defer func() {
			if restored {
				runtime.UnlockOSThread()
			}
		}()
		out := func() result {
			original, e := open("/proc/thread-self/ns/cgroup")
			if e != nil {
				return result{err: ErrProcessUnavailable}
			}
			defer original.Close()
			node, e := open("/proc/1/ns/cgroup")
			if e != nil {
				return result{err: ErrProcessUnavailable}
			}
			defer node.Close()
			if ctx.Err() != nil {
				return result{err: ctx.Err()}
			}
			if e = setns(int(node.Fd()), unix.CLONE_NEWCGROUP); e != nil {
				return result{err: ErrProcessUnavailable}
			}
			restored = false
			value, e := s.capture(ctx, r)
			restore := setns(int(original.Fd()), unix.CLONE_NEWCGROUP)
			restored = restore == nil
			if restore != nil {
				return result{err: ErrProcessUnavailable}
			}
			if ctx.Err() != nil {
				return result{err: ctx.Err()}
			}
			return result{value: value, err: e}
		}()
		done <- out
	}()
	// Join even when canceled: no namespace handle or output escapes while
	// runtime reads or restoration still own the thread. Runtime RPCs use ctx.
	out := <-done
	if out.err != nil {
		return artifact.ProcessInventory{}, out.err
	}
	return out.value, nil
}
