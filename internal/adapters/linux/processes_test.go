//go:build linux

package linux

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	execution "asservat.local/asservat/internal/application/execution"
	"asservat.local/asservat/internal/domain/artifact"
)

type runtimeProcesses struct {
	members []execution.ProcessRuntimeMember
	change  bool
	post    func()
}

func (f *runtimeProcesses) PodProcesses(context.Context, artifact.PinnedPod) ([]execution.ProcessRuntimeMember, error) {
	return append([]execution.ProcessRuntimeMember(nil), f.members...), nil
}
func (f *runtimeProcesses) CurrentProcessMember(_ context.Context, m execution.ProcessRuntimeMember) (execution.ProcessRuntimeMember, error) {
	if f.post != nil {
		f.post()
	}
	if f.change {
		m.MainPID++
	}
	return m, nil
}

func syntheticProcesses(t *testing.T) (*ProcessSnapshots, execution.ProcessSnapshotRequest, *runtimeProcesses) {
	t.Helper()
	dir := t.TempDir()
	proc := filepath.Join(dir, "proc")
	cgroups := filepath.Join(dir, "cgroups")
	boot := "10000000-0000-4000-8000-000000000001"
	id := strings.Repeat("a", 64)
	cg := "/kubepods/pod/origin/" + id
	write := func(name, data string) {
		t.Helper()
		p := filepath.Join(proc, name)
		if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(p, []byte(data), 0600); e != nil {
			t.Fatal(e)
		}
	}
	write("sys/kernel/random/boot_id", boot+"\n")
	for _, pid := range []uint32{110, 111} {
		f := make([]string, 22)
		for n := range f {
			f[n] = "0"
		}
		f[0], f[1], f[17], f[19], f[21] = "S", "9", "2", "12345", "4"
		write(fmt.Sprintf("%d/stat", pid), fmt.Sprintf("%d (space ) and ( parens) %s\n", pid, strings.Join(f, " ")))
		write(fmt.Sprintf("%d/status", pid), fmt.Sprintf("Name:\tapp\nUid:\t1000\t1000\t1000\t1000\nNSpid:\t%d\t4\n", pid))
		write(fmt.Sprintf("%d/cgroup", pid), "0::"+cg+"\n")
		if e := os.Symlink("/app/server", filepath.Join(proc, fmt.Sprintf("%d/exe", pid))); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.MkdirAll(filepath.Join(cgroups, cg), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(cgroups, cg, "cgroup.procs"), []byte("110\n111\n"), 0600); e != nil {
		t.Fatal(e)
	}
	runtime := &runtimeProcesses{members: []execution.ProcessRuntimeMember{{ID: "containerd://" + id, SandboxID: "sandbox", PodUID: "pod", RestartCount: 2, MainPID: 111, Running: true}}}
	n := time.Now()
	return &ProcessSnapshots{runtime: runtime, proc: proc, cgroups: cgroups, now: time.Now}, execution.ProcessSnapshotRequest{Pin: artifact.PinnedPod{Namespace: "ns", NamespaceUID: "namespace", Name: "app", UID: "pod", NodeName: "node"}, NodeUID: "node", NodeBootID: boot, Mode: artifact.ProcessMain, NativeLimit: artifact.ProcessNativeLimit, NotBefore: n, Deadline: n.Add(5 * time.Second)}, runtime
}

func TestProcessSnapshotMainComesFromRuntimeNotLowestPID(t *testing.T) {
	s, r, _ := syntheticProcesses(t)
	p, e := s.capture(context.Background(), r)
	if e != nil || len(p.Processes) != 1 || p.Processes[0].Identity.HostPID != 111 {
		t.Fatal(p, e)
	}
	r.Mode = artifact.ProcessAll
	p, e = s.capture(context.Background(), r)
	if e != nil || len(p.Processes) != 2 || p.Processes[0].Main || !p.Processes[1].Main {
		t.Fatal(p, e)
	}
}
func TestProcessSnapshotChangedRuntimeReturnsNoInventory(t *testing.T) {
	s, r, f := syntheticProcesses(t)
	f.change = true
	p, e := s.capture(context.Background(), r)
	if !errors.Is(e, ErrProcessChanged) || p.Format != "" {
		t.Fatal(p, e)
	}
}
func TestProcessSnapshotReusedMainPIDReturnsNoInventory(t *testing.T) {
	s, r, f := syntheticProcesses(t)
	f.post = func() {
		p := filepath.Join(s.proc, "111/stat")
		b, e := os.ReadFile(p)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(p, []byte(strings.Replace(string(b), "12345", "98765", 1)), 0600); e != nil {
			t.Fatal(e)
		}
	}
	p, e := s.capture(context.Background(), r)
	if !errors.Is(e, ErrProcessChanged) || p.Format != "" {
		t.Fatal(p, e)
	}
}
func TestProcessSnapshotWrongCgroupAndExpiredRefuse(t *testing.T) {
	s, r, _ := syntheticProcesses(t)
	if e := os.WriteFile(filepath.Join(s.proc, "111/cgroup"), []byte("0::/unrelated/node\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := s.capture(context.Background(), r); !errors.Is(e, ErrProcessChanged) {
		t.Fatal(e)
	}
	r.Deadline = r.NotBefore.Add(time.Nanosecond)
	if _, e := s.capture(context.Background(), r); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal(e)
	}
}
