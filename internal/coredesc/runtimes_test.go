package coredesc

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// Stands in for the Python that has pystack: it answers as the script
// that reads a core's Python stacks does.
const pystackStandIn = `#!/bin/sh
echo '{"runtime":"python","title":"Python threads","version":"3.12.1","threads":[{"id":1,"threadSystemId":1,"frames":[{"function":"handle_order","line":7}]}]}'
`

// A describer without a runtime's tool, as the agent's, leaves that
// runtime's stacks to one that has it, as the hub's, and says so in the
// description. The one with the tool adds them and the description awaits
// nothing more; one without leaves it as it is.
func TestRuntimeStacksAwaitADescriberWithTheirTool(t *testing.T) {
	root, tools := t.TempDir(), t.TempDir()
	const python, coreclr, plain = "/usr/bin/python3.12", "/usr/share/dotnet/shared/Microsoft.NETCore.App/8.0.1/libcoreclr.so", "/usr/bin/shop"
	for _, name := range []string{python, coreclr, plain} {
		os.MkdirAll(filepath.Join(root, filepath.Dir(name)), 0o755)
		if err := os.WriteFile(filepath.Join(root, name), []byte("\x7fELF synthetic"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	pystack := filepath.Join(tools, "python")
	if err := os.WriteFile(pystack, []byte(pystackStandIn), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	without := Describer{Scratch: t.TempDir(), PystackPython: filepath.Join(tools, "none"), DotnetDir: filepath.Join(tools, "none"), DebuginfodURLs: "https://debuginfod.invalid/"}
	with := without
	with.PystackPython = pystack
	described := func(file string) []byte {
		return []byte(`{"describer":8,"executable":"` + file + `","mappings":[{"file":"` + file + `"}]}`)
	}
	for file, awaited := range map[string][]string{python: {"python"}, coreclr: {"dotnet"}, plain: nil} {
		if got := Awaits(without.runtimes(ctx, described(file), "core", root)); !slices.Equal(got, awaited) {
			t.Errorf("a describer without the tools leaves of a core of %s: %v, not %v", file, got, awaited)
		}
	}
	report := without.runtimes(ctx, described(python), "core", root)
	if without.Completes(report) || !with.Completes(report) || with.Completes(described(python)) {
		t.Fatal("who completes it:", without.Completes(report), with.Completes(report), with.Completes(described(python)))
	}
	if left := without.Complete(ctx, report, "core", root); !slices.Equal(Awaits(left), []string{"python"}) {
		t.Errorf("a describer without the tool left: %s", left)
	}
	var completed struct {
		Describer     int
		RuntimeStacks []struct {
			Runtime string
			Threads []struct{ Frames []struct{ Function string } }
		}
	}
	report = with.Complete(ctx, report, "core", root)
	if err := json.Unmarshal(report, &completed); err != nil {
		t.Fatal(err)
	}
	if len(Awaits(report)) != 0 || completed.Describer != 8 || len(completed.RuntimeStacks) != 1 || completed.RuntimeStacks[0].Runtime != "python" || completed.RuntimeStacks[0].Threads[0].Frames[0].Function != "handle_order" {
		t.Fatalf("completed: %s", report)
	}
	// A tool that fails leaves the stacks awaited, for another try.
	broken := with
	broken.PystackPython = filepath.Join(tools, "broken")
	if err := os.WriteFile(broken.PystackPython, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if left := broken.Complete(ctx, without.runtimes(ctx, described(python), "core", root), "core", root); !slices.Equal(Awaits(left), []string{"python"}) {
		t.Errorf("after the tool failed: %s", left)
	}
}
