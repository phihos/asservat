package agent

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
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
		if _, err := spool.Handle(proc, pid, "1700000000", strings.NewReader(content)); err != nil {
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

	// A crash report takes the pod's cores; ending the last watch of the
	// pod removes what is left.
	spool.take(uid, "trigger-1")
	if taken, _ := filepath.Glob(filepath.Join(spool.taken("trigger-1"), "*.core")); len(taken) != 1 || len(cores()) != 0 {
		t.Fatal("taken cores", taken, cores())
	}
	handle("100", "a core that no crash report takes")
	os.WriteFile(spool.marker(uid, "watch-2"), nil, 0o600)
	spool.unmark(uid, "watch-1")
	if len(cores()) != 1 {
		t.Fatal("ending one watch removed the cores that another one keeps")
	}
	spool.unmark(uid, "watch-2")
	handle("100", "a core after the last watch ended")
	if len(cores()) != 0 {
		t.Fatal("cores after the last watch ended:", cores())
	}
	// A core that was finished while the pod's last watch ended is taken,
	// and nothing of the pod stays in the spool.
	os.MkdirAll(spool.cores(uid), 0o700)
	os.WriteFile(filepath.Join(spool.cores(uid), container+".100.1700000001.core"), []byte("the last core"), 0o600)
	spool.take(uid, "trigger-2")
	if taken, _ := filepath.Glob(filepath.Join(spool.taken("trigger-2"), "*.core")); len(taken) != 1 {
		t.Fatal("the last core was not taken", taken)
	}
	if _, err := os.Stat(spool.cores(uid)); !os.IsNotExist(err) {
		t.Fatal("the directory of a pod without watches stays:", err)
	}
	os.WriteFile(spool.marker(uid, "watch-3"), nil, 0o600)
	handle("100", "a core of the previous agent")

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

// A crash report takes the core when the handler has finished it, without
// looking for it at an interval: the kernel tells of the finished file.
func TestTakeWaitsForTheHandlersCore(t *testing.T) {
	spool := CoreSpool(t.TempDir())
	const uid = "0b7f2a56-6b6e-4bd4-9f3e-0c7d4c2a1e11"
	os.MkdirAll(filepath.Join(string(spool), "watched"), 0o700)
	os.WriteFile(spool.marker(uid, "watch-1"), nil, 0o600)
	taken := make(chan time.Time)
	go func() {
		spool.take(uid, "trigger-1")
		taken <- time.Now()
	}()
	// The handler begins its core after the report has begun to wait, as
	// with a container that the kubelet reports before the core is written.
	time.Sleep(20 * time.Millisecond)
	part := filepath.Join(spool.cores(uid), "c1.100.1700000000.part")
	if err := os.MkdirAll(spool.cores(uid), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(part, []byte("core"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	finished := time.Now()
	if err := os.Rename(part, strings.TrimSuffix(part, ".part")+".core"); err != nil {
		t.Fatal(err)
	}
	waited := (<-taken).Sub(finished)
	t.Log("taken", waited, "after the core was finished")
	if waited > 100*time.Millisecond {
		t.Fatal("the report waited for a finished core for", waited)
	}
	if cores, _ := filepath.Glob(filepath.Join(spool.taken("trigger-1"), "*.core")); len(cores) != 1 {
		t.Fatal("taken cores", cores)
	}
}

// Installing the handler copies the agent's own program, some 90 MiB, to
// the node. It must not pass through the agent's memory, where it would
// stay as heap for as long as the agent runs.
func TestInstallCopiesTheProgramWithoutHoldingIt(t *testing.T) {
	spool, pattern := CoreSpool(t.TempDir()), filepath.Join(t.TempDir(), "core_pattern")
	if err := os.WriteFile(pattern, []byte("core\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(filepath.Dir(pattern), "core_pipe_limit"), []byte("0\n"), 0o600)
	self, _ := os.Executable()
	program, err := os.Stat(self)
	if err != nil {
		t.Fatal(err)
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	restore, err := spool.Install(pattern)
	if err != nil {
		t.Fatal(err)
	}
	defer restore()
	runtime.ReadMemStats(&after)
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 1<<20 {
		t.Fatalf("installing a program of %d bytes allocated %d", program.Size(), allocated)
	}
	if copied, err := os.Stat(spool.handler()); err != nil || copied.Size() != program.Size() || copied.Mode().Perm() != 0o700 {
		t.Fatal("the copy:", copied, err)
	}
}
