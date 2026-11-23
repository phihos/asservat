package coredesc

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

// A synthetic Python program whose threads wait where the test finds them.
const waitingPython = `import ctypes, threading, time
ctypes.CDLL(None).prctl(0x59616d61, ctypes.c_ulong(-1), 0, 0, 0)  # lets the test's gcore, a sibling, attach

def wait_for_order(shelf):
    lock.acquire()  # main holds it

def handle_request(order_id, customer):
    note = "synthetic-" + customer
    print("ready", flush=True)
    time.sleep(1000)

lock = threading.Lock()
lock.acquire()
threading.Thread(target=wait_for_order, args=("synthetic-shelf",), daemon=True).start()
handle_request(7, "alice")
`

// The core of a Python program is described with the interpreter's
// threads as Python sees them: functions, lines, arguments and locals.
func TestPythonStacksOfACore(t *testing.T) {
	pystack := PystackPython
	if set := os.Getenv("ASSERVAT_PYSTACK"); set != "" {
		pystack = set
	}
	if _, err := os.Stat(pystack); err != nil {
		t.Skipf("pystack is not installed at %s", pystack)
	}
	for _, tool := range []string{"python3", "gcore", "gdb"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "app.py"), []byte(waitingPython), 0o644)
	cmd := exec.Command("python3", filepath.Join(dir, "app.py"))
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("program said %q: %v", line, err)
	}
	pid := strconv.Itoa(cmd.Process.Pid)
	if out, err := exec.Command("gcore", "-o", filepath.Join(dir, "core"), pid).CombinedOutput(); err != nil {
		t.Skipf("gcore cannot attach here: %v: %s", err, tail(out))
	}
	data, err := Describer{Scratch: dir, PystackPython: pystack}.Describe(context.Background(), filepath.Join(dir, "core."+pid), "/proc/"+pid+"/root")
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Threads       []json.RawMessage
		RuntimeStacks []struct {
			Runtime, Title, Version string
			Threads                 []struct {
				ThreadSystemID int
				Frames         []struct {
					Function, File string
					Line           int
					Arguments      []goVariable
					Locals         []goVariable
				}
			}
		}
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Threads) == 0 || len(report.RuntimeStacks) != 1 || report.RuntimeStacks[0].Runtime != "python" || report.RuntimeStacks[0].Version == "" {
		t.Fatalf("%d threads of gdb, runtime stacks: %+v", len(report.Threads), report.RuntimeStacks)
	}
	found := map[string]bool{}
	for _, thread := range report.RuntimeStacks[0].Threads {
		for _, f := range thread.Frames {
			if filepath.Base(f.File) != "app.py" {
				continue
			}
			found[f.Function] = true
			switch f.Function {
			case "handle_request":
				if f.Line == 0 || len(f.Arguments) != 2 || len(f.Locals) != 1 || f.Locals[0].Name != "note" || f.Locals[0].Value != `"synthetic-alice"` || thread.ThreadSystemID != cmd.Process.Pid {
					t.Errorf("handle_request: line %d, arguments %v, locals %v, thread %d", f.Line, f.Arguments, f.Locals, thread.ThreadSystemID)
				}
			case "wait_for_order":
				if len(f.Arguments) != 1 || f.Arguments[0].Value != `"synthetic-shelf"` {
					t.Errorf("wait_for_order: arguments %v", f.Arguments)
				}
			}
		}
	}
	for _, name := range []string{"handle_request", "wait_for_order", "<module>"} {
		if !found[name] {
			t.Errorf("no thread in %s", name)
		}
	}
}
