package coredesc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// A synthetic Go program whose goroutines block where the test finds them.
const blockedProgram = `package main

import (
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"
)

type order struct {
	ID       int
	Customer string
}

var started sync.WaitGroup

func waitForOrder(orders chan order, shelf string) {
	started.Done()
	o := <-orders
	fmt.Println(o, shelf)
}

func holdLedger(ledger *sync.Mutex, attempt int) {
	started.Done()
	ledger.Lock()
	fmt.Println(attempt)
}

func main() {
	// Yama lets only ancestors attach unless the process allows others; the
	// test's gcore is a sibling.
	syscall.RawSyscall(syscall.SYS_PRCTL, 0x59616d61 /* PR_SET_PTRACER */, ^uintptr(0), 0)
	var ledger sync.Mutex
	ledger.Lock()
	orders := make(chan order)
	started.Add(2)
	go waitForOrder(orders, "synthetic-shelf")
	go holdLedger(&ledger, 6)
	started.Wait()
	// Nothing tells when the goroutines have gone on to block.
	time.Sleep(200 * time.Millisecond)
	fmt.Println("ready")
	// Reading keeps main in a system call: the runtime sees no deadlock.
	os.Stdin.Read(make([]byte, 1))
}
`

// TestGoroutinesOfGoCore describes the core of a Go program as the agent
// does after recording it: gdb first, then Delve's goroutines. Most Go
// programs in containers are built without debug information: their
// goroutines are found all the same, with functions and lines from Go's
// line table, and without variables.
func TestGoroutinesOfGoCore(t *testing.T) {
	for _, tool := range []string{"go", "gcore", "gdb"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
	t.Run("with debug information", func(t *testing.T) { goroutinesOfGoCore(t, true) })
	t.Run("stripped", func(t *testing.T) { goroutinesOfGoCore(t, false, "-trimpath", "-ldflags=-s -w") })
}

func goroutinesOfGoCore(t *testing.T, variables bool, flags ...string) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(blockedProgram), 0o644); err != nil {
		t.Fatal(err)
	}
	program := filepath.Join(dir, "blocked")
	build := exec.Command("go", append(append([]string{"build"}, flags...), "-o", program, "main.go")...)
	build.Dir = dir
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v: %s", err, out)
	}
	cmd := exec.Command(program)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stdin.Close(); cmd.Process.Kill(); cmd.Wait() })
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("program said %q: %v", line, err)
	}
	pid := strconv.Itoa(cmd.Process.Pid)
	if out, err := exec.Command("gcore", "-o", filepath.Join(dir, "core"), pid).CombinedOutput(); err != nil {
		t.Skipf("gcore cannot attach here: %v: %s", err, tail(out))
	}

	data, err := Describer{Scratch: dir}.Describe(context.Background(), filepath.Join(dir, "core."+pid), "/proc/"+pid+"/root")
	if err != nil {
		t.Fatal(err)
	}
	// The program's files that the core maps are kept with it: unpacked
	// elsewhere, they describe the core as the files on the node did.
	if DescribedBy(data) != Version {
		t.Error("described by", DescribedBy(data))
	}
	files := Files(data, "/proc/"+pid+"/root")
	if len(files) == 0 || !slices.Contains(files, program) {
		t.Fatal("the program is not among the core's files:", files)
	}
	var archive bytes.Buffer
	if err := WriteFiles(&archive, "/proc/"+pid+"/root", files); err != nil {
		t.Fatal(err)
	}
	elsewhere := t.TempDir()
	if err := ExtractFiles(&archive, elsewhere); err != nil {
		t.Fatal(err)
	}
	stdin.Close()
	cmd.Process.Kill()
	cmd.Wait() // the process and its root are gone
	if data, err = (Describer{Scratch: dir}).Describe(context.Background(), filepath.Join(dir, "core."+pid), elsewhere); err != nil {
		t.Fatal(err)
	}
	var report struct {
		Runtime string
		Threads []struct {
			SystemID int
			Frames   []struct {
				goFrame
				Registers []json.RawMessage
			}
		}
		Goroutines       []goroutine
		WithoutDebugInfo bool
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(report.Runtime, "go1") {
		t.Errorf("runtime = %q", report.Runtime)
	}
	if len(report.Threads) == 0 {
		t.Error("gdb's threads are gone")
	}
	if report.WithoutDebugInfo == variables {
		t.Error("withoutDebugInfo =", report.WithoutDebugInfo)
	}
	described, _ := json.Marshal(report.Goroutines)
	t.Logf("%d goroutines in %d bytes, runtime %s", len(report.Goroutines), len(described), report.Runtime)
	value := func(vars []goVariable, name string) string {
		for _, v := range vars {
			if v.Name == name {
				return v.Value
			}
		}
		return "<absent>"
	}
	found := map[string]bool{}
	for _, g := range report.Goroutines {
		t.Logf("goroutine %d [%s] %s, %d frames, thread %d", g.ID, g.Status, g.Function, len(g.Frames), g.ThreadSystemID)
		for _, f := range g.Frames {
			if f.Function == "sync.(*Mutex).Lock" && filepath.Base(f.File) == "mutex.go" {
				found[f.Function] = true
			}
			if !strings.HasPrefix(f.Function, "main.") {
				continue
			}
			found[f.Function] = true
			if filepath.Base(f.File) != "main.go" || f.Line == 0 {
				t.Errorf("%s is at %s:%d", f.Function, f.File, f.Line)
			}
			t.Logf("  #%d %s %s:%d arguments %v locals %v", f.Level, f.Function, filepath.Base(f.File), f.Line, f.Arguments, f.Locals)
			switch f.Function {
			case "main.waitForOrder":
				if g.Status != "chan receive" {
					t.Errorf("waitForOrder is %q", g.Status)
				}
				if v := value(f.Arguments, "shelf"); variables && v != `"synthetic-shelf"` {
					t.Errorf("shelf = %s", v)
				}
			case "main.holdLedger":
				if g.Status != "sync.Mutex.Lock" {
					t.Errorf("holdLedger is %q", g.Status)
				}
				if v := value(f.Arguments, "attempt"); variables && v != "6" {
					t.Errorf("attempt = %s", v)
				}
			case "main.main":
				if g.ThreadSystemID == 0 {
					t.Error("main runs on no thread, though it is in a system call")
				}
				if v := value(f.Locals, "orders"); variables && !strings.HasPrefix(v, "chan main.order") {
					t.Errorf("orders = %s", v)
				}
			}
		}
	}
	// The thread in which main reads is described down to main, with the
	// registers of its innermost frame.
	reads := false
	for _, thread := range report.Threads {
		for _, f := range thread.Frames {
			if f.Function == "main.main" && filepath.Base(f.File) == "main.go" && len(thread.Frames[0].Registers) > 0 {
				reads = true
			}
		}
	}
	if !reads && !variables {
		t.Error("no thread's stack reaches main.main")
	}
	// The compiler put Lock into holdLedger: it is a frame all the same.
	for _, name := range []string{"main.main", "main.waitForOrder", "main.holdLedger", "sync.(*Mutex).Lock"} {
		if !found[name] {
			t.Errorf("no goroutine in %s", name)
		}
	}
}
