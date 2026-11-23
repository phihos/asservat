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
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
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
	Version = 4
)

// Describer describes cores with gdb and Delve.
type Describer struct {
	// Scratch is a directory for the script and what gdb downloads.
	Scratch string
	// PystackPython is the Python interpreter that has pystack; the
	// constant of that name if empty.
	PystackPython string
	// DebuginfodURLs are the debuginfod servers, separated by spaces, that
	// gdb asks for the debug information of stripped files; empty for none.
	DebuginfodURLs string
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
	cmd := exec.CommandContext(ctx, "gdb", "--batch", "-nx", "-x", script.Name())
	cmd.Env = append(os.Environ(), "ASSERVAT_CORE="+core, "ASSERVAT_ROOT="+root, "ASSERVAT_OUT="+out,
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
	return report, nil
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
