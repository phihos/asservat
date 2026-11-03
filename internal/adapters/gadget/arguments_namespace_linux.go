//go:build gadget && linux

package gadget

import (
	"context"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

type argumentNamespaceOps struct {
	open  func(string) (*os.File, error)
	setns func(int, int) error
	scan  func(context.Context, string, string, string) (map[argumentMembership]argumentPins, error)
}

func argumentMembers(ctx context.Context, pod string) (map[argumentMembership]argumentPins, error) {
	return argumentMembersInNodeNamespace(ctx, pod, argumentNamespaceOps{
		open: os.Open, setns: unix.Setns,
		scan: func(ctx context.Context, proc, groups, pod string) (map[argumentMembership]argumentPins, error) {
			return scanArgumentMembers(ctx, proc, groups, pod, argumentCgroupID)
		},
	})
}

// Containerd gives nonprivileged cgroup-v2 containers a private cgroup namespace
// even with hostPID. Read Pod paths in the node's namespace and resolve them in
// that same node's cgroup tree. PID 1 selects the Kind node too, not its outer VM.
// This changes no cgroup membership, mounts, acquisition bounds or privileges.
func argumentMembersInNodeNamespace(ctx context.Context, pod string, ops argumentNamespaceOps) (map[argumentMembership]argumentPins, error) {
	if ctx == nil {
		return nil, ErrEngineUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	type answer struct {
		members map[argumentMembership]argumentPins
		err     error
	}
	result := make(chan answer, 1)
	go func() {
		runtime.LockOSThread()
		restored := true
		defer func() {
			// As in DialProfile, a failed restoration retires this locked thread;
			// it must never return to the scheduler in the node's namespace.
			if restored {
				runtime.UnlockOSThread()
			}
		}()
		out := func() answer {
			original, err := ops.open("/proc/thread-self/ns/cgroup")
			if err != nil {
				return answer{err: ErrEngineUnavailable}
			}
			defer original.Close()
			node, err := ops.open("/proc/1/ns/cgroup")
			if err != nil {
				return answer{err: ErrEngineUnavailable}
			}
			defer node.Close()
			if err := ctx.Err(); err != nil {
				return answer{err: err}
			}
			if err := ops.setns(int(node.Fd()), unix.CLONE_NEWCGROUP); err != nil {
				return answer{err: ErrEngineUnavailable}
			}
			restored = false
			members, scanErr := ops.scan(ctx, "/proc", "/proc/1/root/sys/fs/cgroup", pod)
			restoreErr := ops.setns(int(original.Fd()), unix.CLONE_NEWCGROUP)
			restored = restoreErr == nil
			if restoreErr != nil {
				scanErr = ErrEngineUnavailable
			} else if ctx.Err() != nil {
				scanErr = ctx.Err()
			}
			if scanErr != nil {
				for _, pins := range members {
					pins.close()
				}
				return answer{err: scanErr}
			}
			return answer{members: members}
		}()
		result <- out
	}()
	// Join even on cancellation: namespace handles and member pins cannot escape
	// while the scan or restoration still uses them. The existing scan checks ctx.
	out := <-result
	if err := ctx.Err(); err != nil {
		for _, pins := range out.members {
			pins.close()
		}
		return nil, err
	}
	return out.members, out.err
}
