package coredesc

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// Where gdb runs as nobody in root's group, a program or library that its
// container keeps to its own user is one gdb cannot read: the description
// names it, so that frames without functions have their reason told.
func TestWhatNobodyMayRead(t *testing.T) {
	for _, c := range []struct {
		mode     fs.FileMode
		uid, gid uint32
		readable bool
	}{
		{0o644, 1000, 1000, true},   // everyone
		{0o755, 0, 0, true},         // everyone
		{0o600, 1000, 1000, false},  // its user alone
		{0o700, 1000, 1000, false},  // its user alone
		{0o640, 1000, 1000, false},  // a group that is not root's
		{0o640, 1000, 0, true},      // root's group
		{0o600, 0, 0, false},        // root alone
		{0o400, nobody, 1000, true}, // nobody's own
		{0o040, nobody, 1000, false},
	} {
		if got := readableAs(c.mode, c.uid, c.gid); got != c.readable {
			t.Errorf("%o of %d:%d: readable %v", c.mode, c.uid, c.gid, got)
		}
	}
}

// Only programs and libraries are named: a core maps data files too, and a
// data file that is kept private explains no frame.
func TestOnlyProgramsKeptToTheirUserAreTold(t *testing.T) {
	was := lowered
	lowered = func() bool { return true }
	defer func() { lowered = was }()
	dir := t.TempDir()
	told := func(name, content string, mode fs.FileMode) bool {
		path := filepath.Join(dir, name)
		os.WriteFile(path, []byte(content), 0o600)
		os.Chmod(path, mode)
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		return kept(f)
	}
	if !told("app", "\x7fELF a program", 0o700) || told("orders.db", "SQLite format 3", 0o600) || told("libc.so", "\x7fELF a library", 0o755) {
		t.Fatal("a private program is told, a private data file and a public library are not")
	}
	lowered = func() bool { return false }
	if told("app2", "\x7fELF a program", 0o700) {
		t.Fatal("where gdb runs as the describer itself, nothing is kept from it")
	}
}

// A Go program's stacks are read by the describer itself, not by gdb: a Go
// program that its container keeps private has its functions all the same
// and is not told as the reason for frames without them.
func TestAGoProgramReadAllTheSameIsNotTold(t *testing.T) {
	fields := map[string]json.RawMessage{"unreadable": json.RawMessage(`["/app/server","/app/libprivate.so"]`)}
	readAllTheSame(fields, "/app/server")
	if string(fields["unreadable"]) != `["/app/libprivate.so"]` {
		t.Fatal(string(fields["unreadable"]))
	}
	// The program's name as the kernel gives it once its file was replaced.
	readAllTheSame(fields, "/app/libprivate.so (deleted)")
	if _, still := fields["unreadable"]; still {
		t.Fatal("an empty list is still told")
	}
}
