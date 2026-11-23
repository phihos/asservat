package coredesc

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// A core of a Python program shows gdb the interpreter: threads that all
// stand in _PyEval_EvalFrameDefault. What the program did is in the
// interpreter's memory: its frames, with their functions, files, lines and
// variables. pystack (Bloomberg, Apache-2.0) reads them from a core and the
// interpreter's files, for CPython 3.7 to 3.14, stripped or not; the
// describer adds its threads to the description. Nothing is needed of the
// image but the interpreter and its libraries, which the core maps.

//go:embed python_stacks.py
var pythonStacks []byte

// PystackPython is the Python interpreter that has pystack, in Asservat's
// image. Where it is not there, Python stacks are not described.
const PystackPython = "/opt/pystack/bin/python"

// A core is of a Python program if it maps the interpreter or its library.
var pythonFile = regexp.MustCompile(`^(lib)?python[0-9.]*(\.so[0-9.]*)?$`)

// runtimeStack is the stacks of the threads of a language runtime, as the
// runtime sees them: what a debugger of that language would show.
type runtimeStack struct {
	Runtime string          `json:"runtime"`
	Title   string          `json:"title"`
	Version string          `json:"version"`
	Threads json.RawMessage `json:"threads"`
}

// describePython adds the Python stacks of a Python program to gdb's
// report of its core. The report of another program returns unchanged.
func (d Describer) describePython(ctx context.Context, report []byte, core, root string) ([]byte, error) {
	python := d.PystackPython
	if python == "" {
		python = PystackPython
	}
	var fields struct {
		Executable string
		Mappings   []struct{ File string }
	}
	if err := json.Unmarshal(report, &fields); err != nil {
		return nil, err
	}
	interpreted := false
	for _, m := range fields.Mappings {
		interpreted = interpreted || pythonFile.MatchString(filepath.Base(m.File))
	}
	if _, err := os.Stat(python); !interpreted || err != nil || fields.Executable == "" || root == "" {
		return report, nil
	}
	// pystack looks for the libraries in directories: those of the files
	// that the core maps.
	var dirs []string
	seen := map[string]bool{}
	for _, file := range Files(report, root) {
		if dir := filepath.Join(root, filepath.Dir(file)); !seen[dir] {
			seen[dir] = true
			dirs = append(dirs, dir)
		}
	}
	script, err := os.CreateTemp(d.Scratch, "python-stacks-*.py")
	if err != nil {
		return nil, err
	}
	defer os.Remove(script.Name())
	_, err = script.Write(pythonStacks)
	if e := script.Close(); err == nil {
		err = e
	}
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, python, script.Name(), core, filepath.Join(root, fields.Executable), strings.Join(dirs, ":"), strconv.Itoa(maxFrames), strconv.Itoa(maxValue))
	// Not in a directory of the program's: Python would import from it.
	cmd.Dir = d.Scratch
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("pystack: %w: %s", err, tail(stderr.Bytes()))
	}
	var stack runtimeStack
	if err := json.Unmarshal(out, &stack); err != nil {
		return nil, fmt.Errorf("pystack: %w", err)
	}
	return addRuntimeStack(report, stack)
}

// addRuntimeStack adds the stacks of a language runtime to a report, after
// those of other runtimes that it may hold.
func addRuntimeStack(report []byte, stack runtimeStack) ([]byte, error) {
	var all map[string]json.RawMessage
	if err := json.Unmarshal(report, &all); err != nil {
		return nil, err
	}
	var stacks []runtimeStack
	if held := all["runtimeStacks"]; held != nil {
		if err := json.Unmarshal(held, &stacks); err != nil {
			return nil, err
		}
	}
	added, err := json.Marshal(append(stacks, stack))
	if err != nil {
		return nil, err
	}
	all["runtimeStacks"] = added
	return json.Marshal(all)
}
