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
	"strings"
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
	Version = 6
)

// Describer describes cores with gdb, Delve, pystack and dotnet-dump.
type Describer struct {
	// Scratch is a directory for the script and what gdb downloads.
	Scratch string
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
	// symbols is the symbol server that has the helper libraries of .NET
	// runtimes (dotnet.go); Microsoft's if empty.
	symbols string
}

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
	// gdb reads the program's files through a view of the root.
	view := ""
	if root != "" {
		if view, err = d.view(ctx, core, root); err != nil {
			return nil, err
		}
		defer os.RemoveAll(view)
	}
	cmd := exec.CommandContext(ctx, "gdb", "--batch", "-nx", "-x", script.Name())
	cmd.Env = append(os.Environ(), "ASSERVAT_CORE="+core, "ASSERVAT_ROOT="+view, "ASSERVAT_OUT="+out,
		"ASSERVAT_DEBUG_DIRS="+strings.Join(d.debugDirs(ctx, core, root), ":"),
		// The script turns debuginfod on where servers are named.
		"DEBUGINFOD_URLS="+d.DebuginfodURLs, "DEBUGINFOD_CACHE_PATH="+filepath.Join(d.Scratch, "debuginfod"),
		// A server that does not answer is given up after this many
		// seconds, not after the client's 90: gdb asks for every file a
		// core maps, and a cluster may have no way out.
		"DEBUGINFOD_TIMEOUT=10")
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
	if report, err = json.Marshal(fields); err != nil {
		return nil, err
	}
	// gdb's description stands without the parts of the language runtimes.
	if with, err := describeGo(ctx, report, core, root); err != nil {
		slog.Warn("goroutines not described", "core", core, "error", err)
	} else {
		report = with
	}
	if with, err := d.describePython(ctx, report, core, root); err != nil {
		slog.Warn("Python stacks not described", "core", core, "error", err)
	} else {
		report = with
	}
	if with, err := d.describeDotnet(ctx, report, core, root); err != nil {
		slog.Warn(".NET stacks not described", "core", core, "error", err)
	} else {
		report = with
	}
	return report, nil
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
func (d Describer) view(ctx context.Context, core, root string) (string, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	view, err := os.MkdirTemp(d.Scratch, "view-*")
	if err != nil {
		return "", err
	}
	names := append(coreFiles(core), "/usr/lib/debug")
	// Without the libraries gdb still describes, as it does without a
	// root, but then without their functions: that is said.
	listed, err := exec.CommandContext(ctx, "gdb", "--batch", "-nx", "-ex", "set debuginfod enabled off", "-ex", "set sysroot "+view, "-ex", "core-file "+core, "-ex", "info sharedlibrary").Output()
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
		err := os.MkdirAll(filepath.Dir(at), 0o700)
		if err == nil {
			err = os.Symlink(filepath.Join(root, file), at)
		}
		// As a name under one that is a file's: gdb then does not find it.
		if err != nil && !errors.Is(err, os.ErrExist) {
			slog.Debug("a file of a core's program is not shown to gdb", "core", core, "file", name, "error", err)
		}
	}
	return view, nil
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
