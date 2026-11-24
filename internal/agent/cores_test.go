package agent

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// spoolDir makes a spool with a short path, as on a node: the kernel takes
// a core pattern, which names the spool, of 127 characters at most.
func spoolDir(t *testing.T) CoreSpool {
	dir, err := os.MkdirTemp("/tmp", "spool")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return CoreSpool(dir)
}

func TestCoreHandlerKeepsOnlyWatchedPods(t *testing.T) {
	spool, proc := spoolDir(t), t.TempDir()
	pattern := filepath.Join(t.TempDir(), "core_pattern")
	os.WriteFile(pattern, []byte("|/usr/lib/no-such-handler %P %u\n"), 0o644)
	pipeLimit := filepath.Join(filepath.Dir(pattern), "core_pipe_limit")
	os.WriteFile(pipeLimit, []byte("0\n"), 0o644)
	restore, err := spool.Install(pattern)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(pattern); string(b) != "|"+string(spool)+"/asservat core-handler %P %t %P %u" {
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
	if b, _ := os.ReadFile(pattern); string(b) != "|/usr/lib/no-such-handler %P %u" {
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

// coreNaming is a core as the kernel writes it, as far as it names the
// files that the process mapped (its NT_FILE note): here one file.
func coreNaming(file string) []byte {
	le := binary.LittleEndian
	files := le.AppendUint64(le.AppendUint64(nil, 1), 0x1000)
	for _, n := range []uint64{0x400000, 0x401000, 0} {
		files = le.AppendUint64(files, n)
	}
	files = append(append(files, file...), 0)
	note := le.AppendUint32(le.AppendUint32(le.AppendUint32(nil, 5), uint32(len(files))), 0x46494c45)
	note = append(append(note, "CORE\x00\x00\x00\x00"...), files...)
	var core bytes.Buffer
	header := elf.Header64{Type: uint16(elf.ET_CORE), Machine: uint16(elf.EM_X86_64), Version: 1, Phoff: 64, Ehsize: 64, Phentsize: 56, Phnum: 1}
	copy(header.Ident[:], "\x7fELF\x02\x01\x01")
	binary.Write(&core, le, header)
	binary.Write(&core, le, elf.Prog64{Type: uint32(elf.PT_NOTE), Off: 64 + 56, Filesz: uint64(len(note))})
	core.Write(note)
	return core.Bytes()
}

// The handler keeps the crashed program's files with its core, while the
// process and its container's files are still there: the agent describes
// the core with them when both are gone.
func TestHandlerKeepsTheProgramsFiles(t *testing.T) {
	spool, proc := CoreSpool(t.TempDir()), t.TempDir()
	const uid, container = "0b7f2a56-6b6e-4bd4-9f3e-0c7d4c2a1e11", "5f3a9c1e7b2d4f6a8c0e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f3a"
	os.MkdirAll(filepath.Join(proc, "100/root/app"), 0o755)
	os.WriteFile(filepath.Join(proc, "100/cgroup"), []byte("0::/kubepods/besteffort/pod"+uid+"/"+container+"\n"), 0o644)
	os.WriteFile(filepath.Join(proc, "100/root/app/server"), []byte("\x7fELF the program"), 0o755)
	os.MkdirAll(filepath.Dir(spool.marker(uid, "watch-1")), 0o700)
	os.WriteFile(spool.marker(uid, "watch-1"), nil, 0o600)
	if outcome, err := spool.Handle(proc, "100", "1700000000", bytes.NewReader(coreNaming("/app/server"))); err != nil || outcome != "kept for pod "+uid {
		t.Fatal(outcome, err)
	}
	spool.take(uid, "trigger-1")
	taken, _ := filepath.Glob(filepath.Join(spool.taken("trigger-1"), "*"))
	if len(taken) != 2 || !strings.HasSuffix(taken[0], ".core") || !strings.HasSuffix(taken[1], programFiles) {
		t.Fatal("taken with the core:", taken)
	}
	// The process is gone; its files are unpacked for the description.
	os.RemoveAll(filepath.Join(proc, "100"))
	a := &Agent{Scratch: t.TempDir()}
	root, err := a.keptProgramFiles(taken[1])
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "app/server")); string(b) != "\x7fELF the program" {
		t.Fatalf("the program as kept: %q", b)
	}
	// A core that names no file of the container is kept without, and the
	// files of the earlier core do not stay for it.
	os.MkdirAll(filepath.Join(proc, "101/root"), 0o755)
	os.WriteFile(filepath.Join(proc, "101/cgroup"), []byte("0::/kubepods/besteffort/pod"+uid+"/"+container+"\n"), 0o644)
	stale := filepath.Join(spool.cores(uid), container+".100.1700000000"+programFiles)
	os.MkdirAll(spool.cores(uid), 0o700)
	os.WriteFile(stale, []byte("of a core that was never finished"), 0o600)
	outcome, err := spool.Handle(proc, "101", "1700000001", bytes.NewReader(coreNaming("/app/gone")))
	if err != nil || !strings.HasPrefix(outcome, "kept for pod "+uid+", without the program's files") {
		t.Fatal(outcome, err)
	}
	left, _ := filepath.Glob(filepath.Join(spool.cores(uid), "*"))
	if len(left) != 1 || filepath.Base(left[0]) != container+".101.1700000001.core" {
		t.Fatal("in the spool:", left)
	}
}

// The cores that the agent's handler does not keep go to the handler that
// the node had before, as the kernel would have run it: with the values
// that its pattern asks the kernel for, and the core on standard input.
// The core of a watched pod is Asservat's alone.
func TestHandlerPassesOtherCoresOnToTheNodesHandler(t *testing.T) {
	spool, proc := spoolDir(t), t.TempDir()
	dir := string(spoolDir(t))
	// Stands in for the node's handler, as apport or systemd-coredump.
	node := filepath.Join(dir, "node-handler")
	script := "#!/bin/sh\nfor a in \"$@\"; do printf '[%s]' \"$a\"; done >" + dir + "/arguments\ncat >" + dir + "/core\n"
	if err := os.WriteFile(node, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	pattern := filepath.Join(t.TempDir(), "core_pattern")
	os.WriteFile(pattern, []byte("|"+node+" -p%p -F%F 100%% -- %E\n"), 0o644)
	os.WriteFile(filepath.Join(filepath.Dir(pattern), "core_pipe_limit"), []byte("16\n"), 0o644)
	restore, err := spool.Install(pattern)
	if err != nil {
		t.Fatal(err)
	}
	defer restore()
	// The agent's pattern asks the kernel for what the node's handler takes.
	installed := "|" + string(spool) + "/asservat core-handler %P %t %p %F %E"
	if b, _ := os.ReadFile(pattern); string(b) != installed {
		t.Fatalf("core pattern %q", b)
	}
	const uid, container = "0b7f2a56-6b6e-4bd4-9f3e-0c7d4c2a1e11", "5f3a9c1e7b2d4f6a8c0e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f3a"
	for pid, cgroup := range map[string]string{"100": "0::/kubepods/besteffort/pod" + uid + "/" + container + "\n", "200": "0::/system.slice/sshd.service\n"} {
		os.MkdirAll(filepath.Join(proc, pid), 0o755)
		os.WriteFile(filepath.Join(proc, pid, "cgroup"), []byte(cgroup), 0o644)
	}
	passed := func() (arguments, core string) {
		a, _ := os.ReadFile(filepath.Join(dir, "arguments"))
		c, _ := os.ReadFile(filepath.Join(dir, "core"))
		os.Remove(filepath.Join(dir, "arguments"))
		os.Remove(filepath.Join(dir, "core"))
		return string(a), string(c)
	}
	// What the kernel puts for %p, %F (nothing, where it does not know it) and %E.
	for pid, content := range map[string]string{"200": "core of a node process", "100": "core of an unwatched pod"} {
		outcome, err := spool.Handle(proc, pid, "1700000000", strings.NewReader(content), "7", "", "!usr!bin!my shop")
		if arguments, core := passed(); err != nil || !strings.Contains(outcome, "passed on") || arguments != "[-p7][-F][100%][--][!usr!bin!my shop]" || core != content {
			t.Fatalf("process %s: %q, %v; the node's handler got %s and %q", pid, outcome, err, arguments, core)
		}
	}
	os.WriteFile(spool.marker(uid, "watch-1"), nil, 0o600)
	if outcome, err := spool.Handle(proc, "100", "1700000000", strings.NewReader("core of a watched pod"), "7", "", "!usr!bin!shop"); err != nil || !strings.Contains(outcome, "kept") {
		t.Fatal(outcome, err)
	}
	if arguments, core := passed(); arguments != "" || core != "" {
		t.Fatalf("the core of a watched pod went to the node's handler: %s %q", arguments, core)
	}
	// A handler of an agent before this one was asked for fewer values
	// than the node's handler takes: the core is dropped as before.
	if outcome, err := spool.Handle(proc, "200", "1700000000", strings.NewReader("core"), "7"); err != nil || !strings.HasPrefix(outcome, "dropped") {
		t.Fatal(outcome, err)
	}
	if arguments, _ := passed(); arguments != "" {
		t.Fatal("the node's handler ran with too few values:", arguments)
	}

	// A node that writes cores to files has no handler to pass on to, and
	// a pattern of more than the kernel's 127 characters is not written.
	for previous, want := range map[string]string{
		"core.%e.%p": "|" + string(spool) + "/asservat core-handler %P %t",
		"|/usr/lib/a-handler-with-a-long-name " + strings.Repeat("%p ", 30): "|" + string(spool) + "/asservat core-handler %P %t",
	} {
		restore()
		os.WriteFile(pattern, []byte(previous), 0o644)
		if restore, err = spool.Install(pattern); err != nil {
			t.Fatal(err)
		}
		if b, _ := os.ReadFile(pattern); string(b) != want {
			t.Fatalf("core pattern %q after %q", b, previous)
		}
		if outcome, err := spool.Handle(proc, "200", "1700000000", strings.NewReader("core")); err != nil || !strings.HasPrefix(outcome, "dropped") {
			t.Fatal(outcome, err)
		}
	}
}
