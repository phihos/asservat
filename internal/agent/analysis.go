package agent

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
)

// A core is a memory image: without the program's executable and libraries
// a debugger shows addresses, not functions. Those files are on the node
// while the pod exists and are not part of the evidence. So the agent has
// gdb describe each core right after recording it, when the files are at
// hand, and uploads the description next to the core: threads, call stacks,
// registers, variables where the program has debug information, modules and
// the memory map. The console's viewer shows it like a debugger does.

//go:embed core_analysis.py
var coreAnalysis []byte

// analysisSuffix is appended to a core's name for its description.
const analysisSuffix = ".analysis.json"

// analyze returns gdb's description of a core. root is the directory in
// which the program's files are found, for example /proc/<pid>/root of a
// process in the same container; empty if there is none.
func (a *Agent) analyze(ctx context.Context, core, root string) ([]byte, error) {
	script, err := os.CreateTemp(a.Scratch, "analysis-*.py")
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
	cmd.Env = append(os.Environ(), "ASSERVAT_CORE="+core, "ASSERVAT_ROOT="+root, "ASSERVAT_OUT="+out)
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("gdb: %w: %s", err, tail(output))
	}
	return os.ReadFile(out)
}

// describe uploads gdb's description of a core that was uploaded as name.
// The core is the evidence; a description that fails is only logged.
func (a *Agent) describe(ctx context.Context, core, root, name string, up func(string, io.Reader) error) {
	report, err := a.analyze(ctx, core, root)
	if err == nil {
		err = up(name+analysisSuffix, bytes.NewReader(report))
	}
	if err != nil {
		slog.Warn("core not described", "core", name, "error", err)
	}
}
