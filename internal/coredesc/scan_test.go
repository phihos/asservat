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

// The stack of a thread that waits in a library without unwind tables is
// followed through it by the return addresses on the stack, up to the
// program's own functions; the frames found so are marked.
func TestStackThroughALibraryWithoutUnwindTables(t *testing.T) {
	for _, tool := range []string{"gcc", "gcore", "gdb"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "block.c"), []byte(libraryWithoutTables), 0o644)
	os.WriteFile(filepath.Join(dir, "main.c"), []byte(programThatWaitsInIt), 0o644)
	for _, args := range [][]string{
		{"-O1", "-fPIC", "-shared", "-fno-asynchronous-unwind-tables", "-fno-unwind-tables", "-fomit-frame-pointer", "-fno-optimize-sibling-calls", "-s", "-o", "libblock.so", "block.c"},
		{"-O1", "-g", "-fno-optimize-sibling-calls", "-o", "waiting", "main.c", "-L.", "-lblock", "-Wl,-rpath,$ORIGIN"},
	} {
		build := exec.Command("gcc", args...)
		build.Dir = dir
		if out, err := build.CombinedOutput(); err != nil {
			t.Skipf("gcc cannot build the test program here: %v: %s", err, out)
		}
	}
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
	var out []byte
	var err error
	// The program says it is ready before it waits.
	for range 20 {
		if out, err = exec.Command("gcore", "-o", filepath.Join(dir, "core"), pid).CombinedOutput(); err != nil {
			t.Skipf("gcore cannot attach here: %v: %s", err, tail(out))
		}
		data, err := Describer{Scratch: dir}.Describe(context.Background(), filepath.Join(dir, "core."+pid), "")
		if err != nil {
			t.Fatal(err)
		}
		var report struct {
			Threads []struct {
				Frames []struct {
					Function, File string
					Line           int
					Scanned        bool
				}
			}
		}
		if err := json.Unmarshal(data, &report); err != nil || len(report.Threads) == 0 {
			t.Fatal(err, len(report.Threads))
		}
		var names []string
		order, marked := false, false
		for _, f := range report.Threads[0].Frames {
			names = append(names, f.Function)
			order = order || f.Function == "handle_order" && filepath.Base(f.File) == "main.c" && f.Line > 0
			marked = marked || f.Scanned
		}
		stack := strings.Join(names, " < ")
		if !strings.Contains(stack, "pause") {
			continue // not waiting yet
		}
		if !order || !marked || !strings.Contains(stack, "block_in_library < handle_order < main") {
			t.Fatalf("the stack: %s (handle_order with its line: %v, frames marked as scanned: %v)", stack, order, marked)
		}
		return
	}
	t.Fatal("the program never waited in pause")
}
