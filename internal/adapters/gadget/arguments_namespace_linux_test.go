//go:build gadget && linux

package gadget

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

// Only namespace syscalls and the scan are injected. These tests never enter
// another namespace or create/load kernel maps on the developer workstation.
func TestArgumentNodeNamespaceScanRestoresAndClosesOnFailures(t *testing.T) {
	for _, mode := range []string{"success", "open-original", "open-node", "enter", "scan", "restore", "cancelled-scan"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			root := t.TempDir()
			opened := []*os.File{}
			order := []string{}
			var pins argumentPins
			opens, sets, tid := 0, 0, 0
			ops := argumentNamespaceOps{
				open: func(path string) (*os.File, error) {
					opens++
					order = append(order, path)
					if opens == 1 && path != "/proc/thread-self/ns/cgroup" || opens == 2 && path != "/proc/1/ns/cgroup" {
						t.Error("wrong namespace", path)
					}
					if mode == "open-original" && opens == 1 || mode == "open-node" && opens == 2 {
						return nil, os.ErrPermission
					}
					f, err := os.CreateTemp(root, "namespace-")
					if err == nil {
						opened = append(opened, f)
					}
					return f, err
				},
				setns: func(fd, kind int) error {
					sets++
					order = append(order, "setns")
					if sets == 1 {
						tid = unix.Gettid()
					}
					if unix.Gettid() != tid || kind != unix.CLONE_NEWCGROUP {
						t.Error("namespace switch left locked thread")
					}
					want := opened[1]
					if sets == 2 {
						want = opened[0]
					}
					if fd != int(want.Fd()) {
						t.Error("wrong namespace descriptor")
					}
					if mode == "enter" && sets == 1 || mode == "restore" && sets == 2 {
						return os.ErrPermission
					}
					return nil
				},
				scan: func(actual context.Context, proc, groups, pod string) (map[argumentMembership]argumentPins, error) {
					order = append(order, "scan")
					if actual != ctx || proc != "/proc" || groups != "/proc/1/root/sys/fs/cgroup" || pod != "approved-pod" || unix.Gettid() != tid {
						t.Error("scan lost original scope or node view")
					}
					g, err := os.Create(filepath.Join(root, "group"))
					if err != nil {
						return nil, err
					}
					ns, err := os.Create(filepath.Join(root, "mount-namespace"))
					if err != nil {
						g.Close()
						return nil, err
					}
					pins = argumentPins{g, ns}
					out := map[argumentMembership]argumentPins{{group: 1, namespace: 2}: pins}
					if mode == "cancelled-scan" {
						cancel()
					}
					if mode == "scan" {
						return out, ErrTargetNotFound
					}
					return out, nil
				},
			}
			members, err := argumentMembersInNodeNamespace(ctx, "approved-pod", ops)
			if (err == nil) != (mode == "success") {
				t.Fatal("unexpected result", mode, err)
			}
			for _, f := range opened {
				if _, e := f.Stat(); e == nil {
					t.Fatal("namespace descriptor leaked")
				}
			}
			if mode == "success" {
				if len(members) != 1 || sets != 2 || !reflect.DeepEqual(order, []string{"/proc/thread-self/ns/cgroup", "/proc/1/ns/cgroup", "setns", "scan", "setns"}) {
					t.Fatal("scan/restore ordering", order)
				}
				if _, err := pins.group.Stat(); err != nil {
					t.Fatal("successful pin closed", err)
				}
				pins.close()
			} else {
				if members != nil {
					t.Fatal("failed scan returned pins")
				}
				if pins.group != nil {
					for _, f := range []*os.File{pins.group, pins.namespace} {
						if _, e := f.Stat(); e == nil {
							t.Fatal("failed scan leaked pin")
						}
					}
				}
			}
			if mode == "cancelled-scan" && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation lost", err)
			}
		})
	}
}

func TestArgumentNodeNamespaceCallerCancellationJoinsScanAndRestore(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	entered, leave, restoring, restore := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	root := t.TempDir()
	sets := 0
	ops := argumentNamespaceOps{
		open: func(string) (*os.File, error) { return os.CreateTemp(root, "namespace-") },
		setns: func(int, int) error {
			sets++
			if sets == 2 {
				close(restoring)
				<-restore
			}
			return nil
		},
		scan: func(actual context.Context, _, _, _ string) (map[argumentMembership]argumentPins, error) {
			close(entered)
			<-actual.Done()
			<-leave
			return nil, actual.Err()
		},
	}
	done := make(chan error, 1)
	go func() { _, err := argumentMembersInNodeNamespace(ctx, "pod", ops); done <- err }()
	<-entered
	cancel()
	select {
	case <-done:
		t.Fatal("caller abandoned active scan")
	default:
	}
	close(leave)
	<-restoring
	select {
	case <-done:
		t.Fatal("caller abandoned namespace restoration")
	default:
	}
	close(restore)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	// Already cancelled calls do not open namespace handles or start a scan.
	ops.open = func(string) (*os.File, error) {
		t.Error("cancelled call opened namespace")
		return nil, os.ErrPermission
	}
	if _, err := argumentMembersInNodeNamespace(ctx, "pod", ops); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
