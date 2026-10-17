package bootstrap

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
)

func TestWorkerProcessDisablesOwnCoreDumping(t *testing.T) {
	if os.Getenv("ASSERVAT_SYNTHETIC_CORE_GUARD") == "child" {
		if err := disableWorkerCoreDumps(); err != nil {
			t.Fatal(err)
		}
		var limit syscall.Rlimit
		if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &limit); err != nil || limit.Cur != 0 || limit.Max != 0 {
			t.Fatal("core limit", err)
		}
		flag, _, err := syscall.RawSyscall6(syscall.SYS_PRCTL, syscall.PR_GET_DUMPABLE, 0, 0, 0, 0, 0)
		if err != 0 || flag != 0 {
			t.Fatal("process still dumpable", err)
		}
		return
	}
	var before, after syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &before); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestWorkerProcessDisablesOwnCoreDumping$", "-test.count=1")
	cmd.Env = append(os.Environ(), "ASSERVAT_SYNTHETIC_CORE_GUARD=child")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child guard: %v %s", err, out)
	}
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &after); err != nil || before != after {
		t.Fatal("changed parent core limits", err)
	}
}
