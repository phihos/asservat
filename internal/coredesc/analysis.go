// Package coredesc describes core dumps. A core is a memory image: without
// the program's executable and libraries a debugger shows addresses, not
// functions. Those files are on the node while the pod exists. So the
// agent has gdb describe each core right after recording it, when the
// files are at hand, and uploads the description next to the core:
// threads, call stacks, registers, variables where the program has debug
// information, modules and the memory map. The console's viewer shows it
// like a debugger does. For a Go program, Delve adds the goroutines
// (goroutines.go).
//
// The agent also uploads the program's files themselves (files.go). With
// them the core opens in a debugger wherever it is downloaded to, and the
// hub can describe it again when a later Asservat describes better.
package coredesc

import (
	"bytes"
	"cmp"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	pathpkg "path"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

//go:embed core_analysis.py
var coreAnalysis []byte

const (
	// Suffix is appended to a core's name for its description.
	Suffix = ".analysis.json"
	// Version counts up with what a description holds, so that the hub
	// can tell one that this Asservat would make better:
	// 2: goroutines of Go programs without debug information.
	// 3: stacks through libraries without unwind tables, such as musl.
	// 4: the stacks of Python programs.
	// 5: debug information from the debug packages of distributions.
	// 6: the managed stacks of .NET programs.
	// 7: the threads of language runtimes told to be the core's threads.
	// 8: a stack read from memory is read to the stack's end, not to the page's.
	// 9: no names for Python threads, which were those of unrelated processes.
	Version = 9
)

// Describer describes cores with gdb, Delve, pystack and dotnet-dump.
type Describer struct {
	// Scratch is a directory for the script and what gdb downloads.
	Scratch string
	// ThreadIDs are the numbers of the process's threads inside its
	// container, by their numbers on the node, for a core that numbers
	// them as the node does (threads.go); nil for one that does not.
	ThreadIDs map[int]int
	// PystackPython is the Python interpreter that has pystack; the
	// constant of that name if empty.
	PystackPython string
	// DebuginfodURLs are the debuginfod servers, separated by spaces, that
	// gdb asks for the debug information of stripped files; empty for none,
	// and then no debug packages are downloaded either.
	DebuginfodURLs string
	// DotnetDir is the directory with the .NET runtime and dotnet-dump;
	// the constant of that name if empty.
	DotnetDir string
	// sources are the places of the distributions' debug packages
	// (debugpkgs.go); nil for the public ones.
	sources *debugSources
	// wait is how long a server may be silent, for tests; debugPackageWait if zero.
	wait time.Duration
	// symbols is the symbol server that has the helper libraries of .NET
	// runtimes (dotnet.go); Microsoft's if empty.
	symbols string
}

// NoScripts are the arguments that keep gdb from running scripts it finds
// by itself: a program, a library or a debug file may carry Python for
// gdb or name a file of it (the section .debug_gdb_scripts, a file named
// after the library), and gdb runs it where the file lies in a directory
// it trusts. The directories of debug files are such, and the debug files
// come from servers: one of them was seen to run its script. gdb runs as
// root on a node, on what a workload and those servers hand it; it runs
// the describer's own script, which is named to it, and no other.
var NoScripts = []string{"-iex", "set auto-load off"}

// Describe returns the description of a core. root is the directory in
// which the program's files are found, for example /proc/<pid>/root of a
// process in the same container; empty if there is none.
func (d Describer) Describe(ctx context.Context, core, root string) ([]byte, error) {
	script, err := os.CreateTemp(d.Scratch, "analysis-*.py")
	if err != nil {
		return nil, err
	}
	defer os.Remove(script.Name())
	_, err = script.Write(coreAnalysis)
	if e := script.Close(); err == nil {
		err = e
	}
	if err != nil {
		return nil, err
	}
	out := script.Name() + ".json"
	defer os.Remove(out)
	// gdb is handed its script, the file for its answer and the core open
	// (see unprivileged.go), and after them the program's files.
	hand := make([]*os.File, 3)
	for i, open := range []func() (*os.File, error){
		func() (*os.File, error) { return os.Open(script.Name()) },
		func() (*os.File, error) { return os.OpenFile(out, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600) },
		func() (*os.File, error) { return os.Open(core) },
	} {
		if hand[i], err = open(); err != nil {
			return nil, err
		}
		defer hand[i].Close()
	}
	back, err := given(hand...)
	if err != nil {
		return nil, err
	}
	defer back()
	// gdb reads the program's files through a view of the root.
	view := ""
	var private []string
	if root != "" {
		var held func()
		var files []*os.File
		if view, files, private, held, err = d.view(ctx, hand[2], root, len(hand)); err != nil {
			return nil, err
		}
		defer held()
		hand = append(hand, files...)
	}
	dirs := d.debugDirs(ctx, core, root)
	for _, dir := range dirs {
		passable(d.Scratch, dir)
	}
	cmd := exec.CommandContext(ctx, "gdb", append(slices.Clone(NoScripts), "--batch", "-nx", "-ex", "python exec(open('"+handed(0)+"').read())")...)
	// gdb tells a script's language by its name's ending, which a file
	// handed over open has none of: Python is told to run it.
	cmd.ExtraFiles = hand
	asNobody(cmd)
	cmd.Env = append(os.Environ(), "ASSERVAT_CORE="+handed(2), "ASSERVAT_ROOT="+view, "ASSERVAT_OUT="+handed(1),
		"ASSERVAT_DEBUG_DIRS="+strings.Join(dirs, ":"),
		// gdb asks no debuginfod server: the describer has (debugDirs).
		"DEBUGINFOD_URLS=")
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("gdb: %w: %s", err, tail(output))
	}
	report, err := os.ReadFile(out)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(report, &fields); err != nil {
		return nil, err
	}
	fields["describer"] = json.RawMessage(fmt.Sprint(Version))
	if len(private) > 0 {
		if fields["unreadable"], err = json.Marshal(private); err != nil {
			return nil, err
		}
	}
	if len(d.ThreadIDs) > 0 {
		if fields["threadIds"], err = json.Marshal(d.ThreadIDs); err != nil {
			return nil, err
		}
	}
	if report, err = json.Marshal(fields); err != nil {
		return nil, err
	}
	// gdb's description stands without the parts of the language runtimes.
	if with, err := describeGo(ctx, report, core, root); err != nil {
		slog.Warn("goroutines not described", "core", core, "error", err)
	} else {
		report = with
	}
	return d.runtimes(ctx, report, core, root), nil
}

// runtimes adds to a description the stacks of the language runtimes that
// are read with a tool of their own. Where the tool is not installed, as
// in the agent's image, or fails, the description says that it awaits them.
func (d Describer) runtimes(ctx context.Context, report []byte, core, root string) []byte {
	for _, runtime := range []struct {
		name     string
		describe func(context.Context, []byte, string, string) ([]byte, error)
	}{{runtimePython, d.describePython}, {runtimeDotnet, d.describeDotnet}} {
		with, err := runtime.describe(ctx, report, core, root)
		if err != nil {
			// What the tool failed at this time it may read another time:
			// the stacks stay awaited.
			slog.Warn("a runtime's stacks not described", "runtime", runtime.name, "core", core, "error", err)
			if with, err = await(report, runtime.name); err != nil {
				continue
			}
		}
		report = with
	}
	return report
}

// The tools that read a runtime's stacks, pystack and dotnet-dump with a
// Python and a .NET runtime of their own, are a third of the image that
// has them. The agent's image, which every node pulls, has not: the agent
// describes a core with gdb and Delve, and the hub, which gets the core
// and the program's files anyway, adds the stacks of the runtimes.
const (
	runtimePython = "python"
	runtimeDotnet = "dotnet"
)

// has tells whether the tool that reads the runtime's stacks is installed.
func (d Describer) has(runtime string) bool {
	tool := cmp.Or(d.PystackPython, PystackPython)
	if runtime == runtimeDotnet {
		tool = filepath.Join(cmp.Or(d.DotnetDir, DotnetDir), "dotnet")
	}
	_, err := os.Stat(tool)
	return err == nil
}

// await notes in a description that it lacks the runtime's stacks because
// its describer had not the tool.
func await(report []byte, runtime string) ([]byte, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(report, &fields); err != nil {
		return nil, err
	}
	if slices.Contains(Awaits(report), runtime) {
		return report, nil
	}
	awaited, err := json.Marshal(append(Awaits(report), runtime))
	if err != nil {
		return nil, err
	}
	fields["awaits"] = awaited
	return json.Marshal(fields)
}

// Awaits lists the runtimes whose stacks a description lacks because its
// describer had not their tool.
func Awaits(report []byte) []string {
	var fields struct{ Awaits []string }
	json.Unmarshal(report, &fields)
	return fields.Awaits
}

// Completes tells whether this describer has the tool of a runtime that
// the description awaits.
func (d Describer) Completes(report []byte) bool {
	return slices.ContainsFunc(Awaits(report), d.has)
}

// Complete adds the stacks of the runtimes that a description awaits, as
// far as this describer has their tools, from the core and the program's
// files under root. What a tool fails at is logged and stays awaited.
func (d Describer) Complete(ctx context.Context, report []byte, core, root string) []byte {
	var fields map[string]json.RawMessage
	if json.Unmarshal(report, &fields) != nil {
		return report
	}
	delete(fields, "awaits")
	if d.ThreadIDs == nil {
		d.ThreadIDs = ThreadIDs(report)
	}
	without, err := json.Marshal(fields)
	if err != nil {
		return report
	}
	return d.runtimes(ctx, without, core, root)
}

// view makes a directory that holds, for every file that gdb looks for
// under the root, a link at the name the program saw it by to the file in
// the root that the name leads to (resolve). gdb takes the view for the
// root: it follows links as the kernel does, from its own root, so that
// under /proc/<pid>/root a container's link to an absolute path would have
// it read the node's file as the program's. The names are those of the
// files that the core maps, those by which the program asked for its
// libraries, often links to the mapped files, and the directory of debug
// files. Only gdb knows the names asked by, from the program's memory: it
// lists them first, with an empty view in which it finds no file.
//
// The files are handed to gdb open, after first others: a link of the view
// leads to its file by the place it has among them.
func (d Describer) view(ctx context.Context, held *os.File, root string, first int) (string, []*os.File, []string, func(), error) {
	core := held.Name()
	root, err := filepath.Abs(root)
	if err != nil {
		return "", nil, nil, nil, err
	}
	view, err := os.MkdirTemp(d.Scratch, "view-*")
	if err != nil {
		return "", nil, nil, nil, err
	}
	var private []string
	// A link of the view leads to the file as this process holds it open,
	// not to its path: the container can put a link in the path's place
	// while gdb reads, and gdb would follow that from the node's root.
	var open []*os.File
	done := func() {
		for _, f := range open {
			f.Close()
		}
		os.RemoveAll(view)
	}
	names := append(coreFiles(core), "/usr/lib/debug")
	// Without the libraries gdb still describes, as it does without a
	// root, but then without their functions: that is said.
	passable(d.Scratch, view)
	list := exec.CommandContext(ctx, "gdb", append(slices.Clone(NoScripts), "--batch", "-nx", "-ex", "set debuginfod enabled off", "-ex", "set sysroot "+view, "-ex", "core-file "+handed(0), "-ex", "info sharedlibrary")...)
	list.ExtraFiles = []*os.File{held}
	asNobody(list)
	listed, err := list.Output()
	if err != nil {
		slog.Warn("the libraries that a core's program asked for are not known", "core", core, "error", err)
	}
	for _, line := range strings.Split(string(listed), "\n") {
		// A library that was not found is listed without addresses.
		if _, name, found := strings.Cut(line, " No "); found {
			names = append(names, strings.TrimSpace(name))
		}
	}
	for _, name := range names {
		name = pathpkg.Clean("/" + strings.TrimSuffix(name, " (deleted)"))
		file, _ := resolve(root, name)
		if file == "" || name == "/" {
			continue
		}
		at := filepath.Join(view, name)
		f, err := openIn(root, file)
		if err == nil {
			open = append(open, f)
			if kept(f) {
				private = append(private, name)
			}
			err = os.MkdirAll(filepath.Dir(at), 0o700)
		}
		if err == nil {
			err = os.Symlink(handed(first+len(open)-1), at)
		}
		// As a name under one that is a file's: gdb then does not find it.
		if err != nil && !errors.Is(err, os.ErrExist) {
			slog.Debug("a file of a core's program is not shown to gdb", "core", core, "file", name, "error", err)
		}
	}
	passable(d.Scratch, view)
	return view, open, private, done, nil
}

// DescribedBy tells which version of the describer made a description; 1
// for those from before they said.
func DescribedBy(report []byte) int {
	var fields struct{ Describer int }
	if json.Unmarshal(report, &fields) != nil || fields.Describer == 0 {
		return 1
	}
	return fields.Describer
}

// tail is the end of a tool's output, for an error message.
func tail(b []byte) string {
	b = bytes.TrimSpace(b)
	if len(b) > 400 {
		b = b[len(b)-400:]
	}
	return string(b)
}
