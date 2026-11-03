//go:build gadget && linux

package gadget

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestArgumentCgroupMembershipIsExactUnifiedPod(t *testing.T) {
	pod := "11111111-1111-4111-8111-111111111111"
	for _, path := range []string{"/kubepods/pod" + pod + "/container", "/kubepods.slice/kubepods-burstable-pod11111111_1111_4111_8111_111111111111.slice/container.scope"} {
		if got, ok := argumentCgroupPath("0::"+path+"\n", pod); !ok || got != path {
			t.Fatal(got, ok)
		}
	}
	for _, raw := range []string{"0::/kubepods/pod" + pod + "-replacement/c\n", "0::/kubepods/pod" + pod + "/../other\n", "1:cpu:/kubepods/pod" + pod + "/c\n", "0::/outside\n"} {
		if _, ok := argumentCgroupPath(raw, pod); ok {
			t.Fatal(raw)
		}
	}
}
func TestArgumentMembershipPinsOnlyCurrentPod(t *testing.T) {
	root := t.TempDir()
	proc := filepath.Join(root, "proc")
	groups := filepath.Join(root, "cgroup")
	pod := "11111111-1111-4111-8111-111111111111"
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	must(os.MkdirAll(filepath.Join(proc, "1/ns"), 0700))
	must(os.Symlink("mnt:[123]", filepath.Join(proc, "1/ns/mnt")))
	path := "/kubepods/pod" + pod + "/container"
	must(os.MkdirAll(filepath.Join(groups, path), 0700))
	for _, pid := range []string{"2", "3"} {
		must(os.MkdirAll(filepath.Join(proc, pid, "ns"), 0700))
		must(os.WriteFile(filepath.Join(proc, pid, "ns/mnt"), []byte("synthetic namespace inode"), 0600))
		selected := path
		if pid == "3" {
			selected = "/outside"
		}
		must(os.WriteFile(filepath.Join(proc, pid, "cgroup"), []byte("0::"+selected+"\n"), 0600))
		stat := fmt.Sprintf("%s (synthetic process) S", pid)
		for i := 0; i < 18; i++ {
			stat += " 0"
		}
		stat += " 100\n"
		must(os.WriteFile(filepath.Join(proc, pid, "stat"), []byte(stat), 0600))
	}
	members, err := scanArgumentMembers(t.Context(), proc, groups, pod, argumentInode)
	if err != nil || len(members) != 1 {
		t.Fatal(members, err)
	}
	for key, pins := range members {
		if key.group == 0 || key.namespace == 0 {
			t.Fatal(key)
		}
		pins.close()
		if _, e := pins.group.Stat(); e == nil {
			t.Fatal("group pin retained after close")
		}
	}
}

func TestArgumentMembershipCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := scanArgumentMembers(ctx, t.TempDir(), t.TempDir(), "pod", argumentInode)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled scan did not preserve cancellation", err)
	}
}

func TestArgumentMembershipVanishedGroupDoesNotHideLiveMembers(t *testing.T) {
	for _, inaccessible := range []bool{false, true} {
		t.Run(fmt.Sprintf("invalid_parent_%t", inaccessible), func(t *testing.T) {
			root := t.TempDir()
			proc, groups := filepath.Join(root, "proc"), filepath.Join(root, "groups")
			pod := "11111111-1111-4111-8111-111111111111"
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			must(os.MkdirAll(filepath.Join(proc, "1/ns"), 0700))
			must(os.Symlink("mnt:[123]", filepath.Join(proc, "1/ns/mnt")))
			base := filepath.Join(groups, "kubepods/pod"+pod)
			must(os.MkdirAll(filepath.Join(base, "live"), 0700))
			if inaccessible {
				must(os.WriteFile(filepath.Join(base, "gone"), []byte("not a cgroup directory"), 0600))
			}
			for _, pid := range []string{"2", "3"} {
				must(os.MkdirAll(filepath.Join(proc, pid, "ns"), 0700))
				must(os.WriteFile(filepath.Join(proc, pid, "ns/mnt"), []byte("namespace"), 0600))
				name := "live"
				if pid == "2" {
					name = "gone/member"
				}
				must(os.WriteFile(filepath.Join(proc, pid, "cgroup"), []byte("0::/kubepods/pod"+pod+"/"+name+"\n"), 0600))
				stat := pid + " (process) S"
				for i := 0; i < 18; i++ {
					stat += " 0"
				}
				must(os.WriteFile(filepath.Join(proc, pid, "stat"), []byte(stat+" 100\n"), 0600))
			}
			members, err := scanArgumentMembers(t.Context(), proc, groups, pod, argumentInode)
			defer func() {
				for _, pins := range members {
					pins.close()
				}
			}()
			if inaccessible {
				if !errors.Is(err, syscall.ENOTDIR) {
					t.Fatalf("real cgroup access error hidden: %v", err)
				}
			} else if err != nil || len(members) != 1 {
				t.Fatalf("vanished member discarded live member: count=%d err=%v", len(members), err)
			}
		})
	}
}
