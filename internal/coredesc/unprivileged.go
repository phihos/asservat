package coredesc

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// On a node the describer is root, and gdb reads there what a workload
// shaped: a core, programs, libraries and their debug information. gdb's
// makers do not count a fault in reading such files as one of security
// and tell to run it in a sandbox for files that are not trusted
// (gdb/SECURITY.txt). So the gdb that describes a core runs as the user
// "nobody", without any of the agent's capabilities: what it needs is
// handed to it open, and a fault in it then reaches what that user may
// read, not the node. The hub is no root and runs gdb as itself.
//
// The price: a program or library that the container lets only its own
// user read cannot be opened by gdb either, and its frames then show
// addresses instead of functions. gdb taking the core (gcore) stays root,
// which attaching to a process of another user needs.
const nobody = 65534

// lowered tells whether tools run as nobody: where the describer is root.
var lowered = func() bool { return os.Geteuid() == 0 }

// handed returns the name by which a tool that was started with files
// handed to it open finds the one at index i among them.
func handed(i int) string { return fmt.Sprintf("/proc/self/fd/%d", 3+i) }

// asNobody has the command run as nobody where the describer is root.
func asNobody(cmd *exec.Cmd) {
	if lowered() {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: nobody, Gid: nobody}}
	}
}

// given makes files that the describer made, or keeps, nobody's for the
// tool to open, where the describer is root, and returns what gives them
// back. A file that is handed over open is opened anew by the tool under
// the name of handed, which asks for the file's own permissions.
func given(files ...*os.File) (back func(), err error) {
	if !lowered() {
		return func() {}, nil
	}
	for _, f := range files {
		if err := f.Chown(nobody, -1); err != nil {
			return nil, err
		}
	}
	return func() {
		for _, f := range files {
			f.Chown(0, -1)
		}
	}, nil
}

// passable makes a directory tree that the describer made readable to a
// tool that runs as nobody: every directory from below scratch down, and
// the files in it. What lies there is no secret: links of a view, and
// debug information as public servers give it out.
func passable(scratch, dir string) {
	if !lowered() {
		return
	}
	// Through the scratch directory itself the tool may pass, not look:
	// what else lies there, as a core, is root's alone.
	if info, err := os.Stat(scratch); err == nil && info.Mode()&0o001 == 0 {
		os.Chmod(scratch, info.Mode().Perm()|0o011)
	}
	for parent := filepath.Dir(dir); len(parent) > len(scratch); parent = filepath.Dir(parent) {
		os.Chmod(parent, 0o755)
	}
	filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		if entry.IsDir() {
			os.Chmod(path, 0o755)
		} else {
			os.Chmod(path, 0o644)
		}
		return nil
	})
}
