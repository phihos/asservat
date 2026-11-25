package coredesc

import (
	"fmt"
	"io/fs"
	"log/slog"
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
// handed to it open, and a fault in it then reaches what that user and
// root's group may read, not the node. The hub is no root and runs gdb as itself.
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

// asNobody has the command run as nobody where the describer is root. Its
// group stays root's, which by itself may nothing but read what root's
// group may: by that the tool reads what it is given.
func asNobody(cmd *exec.Cmd) {
	if lowered() {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: nobody, Gid: 0, Groups: []uint32{}}}
	}
}

// given lets the tool open files that the describer made or keeps, where
// the describer is root: its group may read them, and write those that
// are written, for as long as the tool runs. It returns what takes that
// back. A file that is handed over open is opened anew by the tool under
// the name of handed, which asks for the file's own permissions. The
// permissions are changed, not the owner: an agent has no capability to
// give files away.
func given(files ...*os.File) (back func(), err error) {
	if !lowered() {
		return func() {}, nil
	}
	was, changed := make([]fs.FileMode, len(files)), make([]bool, len(files))
	back = func() {
		for i, f := range files {
			if !changed[i] {
				continue
			}
			if err := f.Chmod(was[i]); err != nil {
				slog.Warn("a file's permissions are not put back", "file", f.Name(), "error", err)
			}
		}
	}
	for i, f := range files {
		info, err := f.Stat()
		if err == nil {
			was[i], changed[i] = info.Mode().Perm(), true
			err = f.Chmod(info.Mode().Perm() | 0o060)
		}
		if err != nil {
			back()
			return nil, err
		}
	}
	return back, nil
}

// passable lets a tool that runs as nobody, in root's group, read a
// directory tree that the describer made: the group may pass through
// every directory from scratch down to it, and read what is in it. What
// lies there is no secret: links of a view, and debug information as
// public servers give it out.
func passable(scratch, dir string) {
	if !lowered() {
		return
	}
	also := func(path string, bits fs.FileMode) {
		if info, err := os.Stat(path); err == nil && info.Mode().Perm()&bits != bits {
			os.Chmod(path, info.Mode().Perm()|bits)
		}
	}
	// Pass through, not list.
	also(scratch, 0o010)
	for parent := filepath.Dir(dir); len(parent) > len(scratch); parent = filepath.Dir(parent) {
		also(parent, 0o010)
	}
	filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		if entry.IsDir() {
			also(path, 0o050)
		} else {
			also(path, 0o040)
		}
		return nil
	})
}

// kept tells of a file of the program whether the tool, as nobody in
// root's group, is kept from reading it. A container may keep a program or
// a library to its own user; the describer, as root, opens it all the
// same, and the tool then fails to: its frames show addresses, and the
// description names the file so that the reader knows why. Only programs
// and libraries are told: a core maps data files too, which have no frames.
func kept(f *os.File) bool {
	if !lowered() {
		return false
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	magic := make([]byte, 4)
	if _, err := f.ReadAt(magic, 0); err != nil || string(magic) != "\x7fELF" {
		return false
	}
	stat, _ := info.Sys().(*syscall.Stat_t)
	if stat == nil {
		return false
	}
	return !readableAs(info.Mode().Perm(), stat.Uid, stat.Gid)
}

// readableAs tells whether nobody, in root's group, may read a file of
// the permissions, the owner and the group: as everyone, as a member of
// root's group, or as the file's owner.
func readableAs(mode fs.FileMode, uid, gid uint32) bool {
	return mode&0o004 != 0 || gid == 0 && mode&0o040 != 0 || uid == nobody && mode&0o400 != 0
}

// writable lets a tool that runs as nobody, in root's group, write into a
// directory that the describer made for it, and pass through those above
// it from scratch down.
func writable(scratch, dir string) {
	if !lowered() {
		return
	}
	passable(scratch, dir)
	if info, err := os.Stat(dir); err == nil {
		os.Chmod(dir, info.Mode().Perm()|0o070)
	}
}
