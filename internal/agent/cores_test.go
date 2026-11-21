package agent

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCoreHandlerKeepsOnlyWatchedPods(t *testing.T) {
	spool, proc := CoreSpool(t.TempDir()), t.TempDir()
	pattern := filepath.Join(t.TempDir(), "core_pattern")
	os.WriteFile(pattern, []byte("|/usr/lib/systemd/systemd-coredump %P %u\n"), 0o644)
	pipeLimit := filepath.Join(filepath.Dir(pattern), "core_pipe_limit")
	os.WriteFile(pipeLimit, []byte("0\n"), 0o644)
	restore, err := spool.Install(pattern)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(pattern); string(b) != "|"+string(spool)+"/asservat core-handler %P %t" {
		t.Fatalf("core pattern %q", b)
	}
	if b, _ := os.ReadFile(pipeLimit); string(b) != "16" {
		t.Fatalf("core pipe limit %q", b)
	}
	if info, err := os.Stat(spool.handler()); err != nil || info.Mode()&0o100 == 0 {
		t.Fatal("the handler is not installed", err)
	}

	const uid, container = "0b7f2a56-6b6e-4bd4-9f3e-0c7d4c2a1e11", "5f3a9c1e7b2d4f6a8c0e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f3a"
	process := func(pid, cgroup string) {
		os.MkdirAll(filepath.Join(proc, pid), 0o755)
		os.WriteFile(filepath.Join(proc, pid, "cgroup"), []byte(cgroup), 0o644)
	}
	// systemd cgroup driver, cgroupfs driver, and a process of the node.
	process("100", "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod"+strings.ReplaceAll(uid, "-", "_")+".slice/cri-containerd-"+container+".scope\n")
	process("101", "0::/kubepods/besteffort/pod"+uid+"/"+container+"\n")
	process("200", "0::/system.slice/sshd.service\n")
	cores := func() []string {
		names, _ := filepath.Glob(filepath.Join(spool.cores(uid), "*"))
		for i := range names {
			names[i] = filepath.Base(names[i])
		}
		return names
	}
	handle := func(pid, content string) {
		t.Helper()
		if err := spool.Handle(proc, pid, "1700000000", strings.NewReader(content)); err != nil {
			t.Fatal(err)
		}
	}
	handle("100", "core of an unwatched pod")
	handle("200", "core of a node process")
	if got := cores(); len(got) != 0 {
		t.Fatal("kept a core that nobody watches for:", got)
	}
	if err := os.WriteFile(spool.marker(uid, "watch-1"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	handle("200", "core of a node process")
	handle("100", "first core")
	// A later core of the same container replaces the earlier one.
	handle("101", "second core")
	got := cores()
	if len(got) != 1 || got[0] != container+".101.1700000000.core" {
		t.Fatal("cores", got)
	}
	if b, _ := os.ReadFile(filepath.Join(spool.cores(uid), got[0])); !bytes.Equal(b, []byte("second core")) {
		t.Fatalf("core content %q", b)
	}

	// An agent that ended without restoring finds its own pattern and still
	// restores the one before it.
	again, err := spool.Install(pattern)
	if err != nil {
		t.Fatal(err)
	}
	if len(cores()) != 0 {
		t.Fatal("a new agent kept the cores of the previous one")
	}
	again()
	if b, _ := os.ReadFile(pattern); string(b) != "|/usr/lib/systemd/systemd-coredump %P %u" {
		t.Fatalf("restored core pattern %q", b)
	}
	restore()
	if b, _ := os.ReadFile(pipeLimit); string(b) != "0" {
		t.Fatalf("restored core pipe limit %q", b)
	}
}
