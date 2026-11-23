package coredesc

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// A synthetic library as musl is built: without unwind tables and frame
// pointers, stripped. A thread that waits in it ends there for gdb.
const libraryWithoutTables = `#include <unistd.h>
#include <string.h>
static int deeper(int depth, volatile char *note) {
	volatile char local[96];
	memset((char *)local, depth, sizeof local);
	if (depth > 0) return deeper(depth - 1, note) + local[1];
	pause();
	return note[0] + local[0];
}
int block_in_library(int depth) {
	volatile char note[200];
	memset((char *)note, 1, sizeof note);
	return deeper(depth, note) + 1;
}
`

const programThatWaitsInIt = `#include <stdio.h>
#include <sys/prctl.h>
int block_in_library(int depth);
__attribute__((noinline)) int handle_order(int order) { return block_in_library(2) + order; }
int main(void) {
	prctl(0x59616d61, -1UL, 0, 0, 0); /* lets the test's gcore, a sibling, attach */
	puts("ready"); fflush(stdout);
	return handle_order(7);
}
`

// buildWaiting builds the program and its library into dir. The program
// asks for the library by a name that is a link to its file.
func buildWaiting(t *testing.T, dir, program string) {
	for _, tool := range []string{"gcc", "gcore", "gdb"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
	os.WriteFile(filepath.Join(dir, "block.c"), []byte(libraryWithoutTables), 0o644)
	os.WriteFile(filepath.Join(dir, "main.c"), []byte(program), 0o644)
	os.Symlink("libblock.so.1.0", filepath.Join(dir, "libblock.so.1"))
	os.Symlink("libblock.so.1", filepath.Join(dir, "libblock.so"))
	for _, args := range [][]string{
		{"-O1", "-fPIC", "-shared", "-fno-asynchronous-unwind-tables", "-fno-unwind-tables", "-fomit-frame-pointer", "-fno-optimize-sibling-calls", "-s", "-Wl,-soname,libblock.so.1", "-o", "libblock.so.1.0", "block.c"},
		{"-O1", "-g", "-fno-optimize-sibling-calls", "-o", "waiting", "main.c", "-L.", "-lblock", "-Wl,-rpath,$ORIGIN"},
	} {
		build := exec.Command("gcc", args...)
		build.Dir = dir
		if out, err := build.CombinedOutput(); err != nil {
			t.Skipf("gcc cannot build the test program here: %v: %s", err, out)
		}
	}
}

type waitingReport struct {
	Executable string
	Modules    []struct{ File string }
	Threads    []struct {
		Frames []struct {
			Function, File string
			Line           int
			Scanned        bool
		}
	}
}

// describeWaiting runs the program built into dir and describes its core,
// with the files under root, once it waits in the library. It returns the
// description and the functions of the stack.
func describeWaiting(t *testing.T, dir, root string) (waitingReport, string) {
	cmd := exec.Command(filepath.Join(dir, "waiting"))
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("program said %q: %v", line, err)
	}
	pid := strconv.Itoa(cmd.Process.Pid)
	stack := ""
	// The program says it is ready before it waits.
	for range 20 {
		if out, err := exec.Command("gcore", "-o", filepath.Join(dir, "core"), pid).CombinedOutput(); err != nil {
			t.Skipf("gcore cannot attach here: %v: %s", err, tail(out))
		}
		data, err := Describer{Scratch: t.TempDir()}.Describe(context.Background(), filepath.Join(dir, "core."+pid), root)
		if err != nil {
			t.Fatal(err)
		}
		var report waitingReport
		if err := json.Unmarshal(data, &report); err != nil || len(report.Threads) == 0 {
			t.Fatal(err, len(report.Threads))
		}
		var names []string
		for _, f := range report.Threads[0].Frames {
			names = append(names, f.Function)
		}
		stack = strings.Join(names, " < ")
		if strings.Contains(stack, "pause") {
			return report, stack
		}
	}
	t.Fatalf("the program never waited in pause: %s", stack)
	return waitingReport{}, ""
}

// The stack of a thread that waits in a library without unwind tables is
// followed through it by the return addresses on the stack, up to the
// program's own functions; the frames found so are marked.
func TestStackThroughALibraryWithoutUnwindTables(t *testing.T) {
	dir := t.TempDir()
	buildWaiting(t, dir, programThatWaitsInIt)
	report, stack := describeWaiting(t, dir, "")
	order, marked := false, false
	for _, f := range report.Threads[0].Frames {
		order = order || f.Function == "handle_order" && filepath.Base(f.File) == "main.c" && f.Line > 0
		marked = marked || f.Scanned
	}
	if !order || !marked || !strings.Contains(stack, "block_in_library < handle_order < main") {
		t.Fatalf("the stack: %s (handle_order with its line: %v, frames marked as scanned: %v)", stack, order, marked)
	}
}

// gdb reads the program's files where the container's links lead within
// the root. A container's /app that is a link to an absolute path does not
// make it read the file at that path outside of the root, here another
// program of the same name. A library that the program asks for by a link
// to its file is found.
func TestGdbFollowsLinksWithinTheRoot(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	app, outside, root := filepath.Join(dir, "app"), filepath.Join(dir, "outside"), filepath.Join(dir, "root")
	for _, d := range []string{app, outside, filepath.Join(root, dir), filepath.Join(root, outside)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	buildWaiting(t, app, programThatWaitsInIt)
	buildWaiting(t, outside, strings.ReplaceAll(programThatWaitsInIt, "handle_order", "decoy_order"))
	// In the root the program's directory is a link to an absolute path.
	// Its files are at that path in the root, the decoy at it outside.
	if err := os.Symlink(outside, filepath.Join(root, app)); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"waiting", "libblock.so.1.0"} {
		data, err := os.ReadFile(filepath.Join(app, name))
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(root, outside, name), data, 0o755)
	}
	os.Symlink("libblock.so.1.0", filepath.Join(root, outside, "libblock.so.1"))
	// The system's libraries are in the root by the names asked for.
	libraries, err := exec.Command("ldd", filepath.Join(app, "waiting")).Output()
	if err != nil {
		t.Skipf("ldd does not list the libraries here: %v", err)
	}
	for _, name := range strings.Fields(string(libraries)) {
		if data, err := os.ReadFile(name); err == nil && filepath.IsAbs(name) && !strings.HasPrefix(name, dir) {
			os.MkdirAll(filepath.Join(root, filepath.Dir(name)), 0o755)
			os.WriteFile(filepath.Join(root, name), data, 0o755)
		}
	}
	report, stack := describeWaiting(t, app, root)
	if !strings.Contains(stack, "block_in_library < handle_order < main") {
		t.Errorf("the stack: %s", stack)
	}
	asked := false
	for _, m := range report.Modules {
		asked = asked || m.File == filepath.Join(app, "libblock.so.1")
	}
	if report.Executable != filepath.Join(app, "waiting") || !asked {
		t.Errorf("the program %s with the libraries %v, not as the program saw them", report.Executable, report.Modules)
	}
}
