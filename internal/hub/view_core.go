package hub

import (
	"cmp"
	"encoding/json"
	"fmt"
	"strings"
)

// coreText tells a core's description as text, for a reader without the
// viewer: why the process stopped, then the stacks of its program as its
// language runtime sees them, then the machine's threads. Stacks that are
// alike, as those of a pool's idle workers, are told once with their
// number. The memory map is left out: it is most of a description and
// tells little; the description itself has it.
func coreText(report []byte) string {
	type variable struct{ Name, Value string }
	type frame struct {
		PC, Function, File, Module string
		Line                       int
		Scanned                    bool
		Arguments, Locals          []variable
	}
	type thread struct {
		ID                       int64
		Name, Status             string
		Current                  bool
		SystemID, ThreadSystemID int
		Frames                   []frame
		Cut                      bool
	}
	var core struct {
		CommandLine, Executable, Stopped, Runtime string
		Symbols, WithoutDebugInfo, GoroutinesCut  bool
		Goroutines, Threads                       []thread
		RuntimeStacks                             []struct {
			Title, Version string
			Threads        []thread
		}
		Modules []struct {
			File    string
			Symbols bool
		}
	}
	if err := json.Unmarshal(report, &core); err != nil {
		return "the core's description cannot be read: " + err.Error()
	}
	var b strings.Builder
	stopped := core.Stopped
	if stopped == "" {
		stopped = "Snapshot of a running process; it continued afterwards."
	}
	fmt.Fprintf(&b, "%s\n%s\n", stopped, cmp.Or(core.CommandLine, core.Executable))
	if core.Runtime != "" {
		b.WriteString(core.Runtime)
		if core.WithoutDebugInfo {
			b.WriteString(", built without debug information: functions and lines, no variables")
		}
		b.WriteString("\n")
	}
	stack := func(t thread) string {
		var s strings.Builder
		for i, f := range t.Frames {
			fmt.Fprintf(&s, "  #%d %s", i, cmp.Or(f.Function, f.PC, "??"))
			switch {
			case f.File != "":
				fmt.Fprintf(&s, " %s:%d", f.File, f.Line)
			case f.Module != "":
				fmt.Fprintf(&s, " in %s", f.Module)
			}
			if f.Scanned {
				s.WriteString(" (found by reading the stack)")
			}
			s.WriteString("\n")
			for _, v := range append(f.Arguments, f.Locals...) {
				fmt.Fprintf(&s, "       %s = %s\n", v.Name, v.Value)
			}
		}
		if t.Cut {
			s.WriteString("  … the stack goes deeper\n")
		}
		return s.String()
	}
	list := func(title, one string, threads []thread, more string) {
		if len(threads) == 0 {
			return
		}
		fmt.Fprintf(&b, "\n%s (%d)%s\n", title, len(threads), more)
		// Those with the same state and stack, in the order of the first.
		type group struct {
			first thread
			ids   []string
		}
		var groups []*group
		by := map[string]*group{}
		for _, t := range threads {
			key := t.Status + "\x00" + stack(t)
			if t.Current || t.Name != "" {
				key += fmt.Sprint("\x00", t.ID) // told on its own
			}
			g := by[key]
			if g == nil {
				g = &group{first: t}
				by[key] = g
				groups = append(groups, g)
			}
			g.ids = append(g.ids, fmt.Sprint(t.ID))
		}
		for _, g := range groups {
			t := g.first
			status := ""
			if t.Status != "" {
				status = " [" + t.Status + "]"
			}
			if len(g.ids) > 1 {
				fmt.Fprintf(&b, "%d %ss%s: %s\n", len(g.ids), one, status, strings.Join(g.ids, ", "))
			} else {
				fmt.Fprintf(&b, "%s %d", one, t.ID)
				if t.Name != "" {
					fmt.Fprintf(&b, " %q", t.Name)
				}
				b.WriteString(status)
				if lwp := max(t.SystemID, t.ThreadSystemID); lwp != 0 {
					fmt.Fprintf(&b, " LWP %d", lwp)
				}
				if t.Current {
					b.WriteString(", the one the core selects")
				}
				b.WriteString("\n")
			}
			b.WriteString(stack(t))
		}
	}
	for _, runtime := range core.RuntimeStacks {
		list(strings.TrimSpace(runtime.Title+" "+runtime.Version), "thread", runtime.Threads, "")
	}
	more := ""
	if core.GoroutinesCut {
		more = "; the program has more"
	}
	list("Goroutines", "goroutine", core.Goroutines, more)
	list("Threads", "thread", core.Threads, "")
	var without []string
	for _, m := range core.Modules {
		if !m.Symbols {
			without = append(without, m.File)
		}
	}
	if len(without) > 0 {
		fmt.Fprintf(&b, "\nWithout symbols: %s\n", strings.Join(without, ", "))
	}
	return b.String()
}
