package coredesc

import (
	"context"
	"debug/buildinfo"
	"encoding/json"
	"fmt"
	pathpkg "path"
	"slices"
	"sort"
	"strings"

	"github.com/go-delve/delve/pkg/goversion"
	"github.com/go-delve/delve/pkg/proc"
	"github.com/go-delve/delve/pkg/proc/core"
	"github.com/go-delve/delve/service/api"
)

// gdb unwinds the stacks of a Go program poorly and knows nothing of
// goroutines. Delve, the Go debugger, does: for the core of a Go program the
// agent adds Delve's goroutines to gdb's description. gdb's threads, modules
// and memory map stay.

const (
	// As in core_analysis.py: a runaway recursion repeats the same frames
	// until the stack ends; the innermost frames show it.
	maxFrames = 256
	// As in core_analysis.py: one line per value.
	maxValue = 200
	// A Go server can have hundreds of thousands of goroutines. The viewer
	// reads at most 64 MiB of a description, and a goroutine takes about
	// 4 KiB of it with its stack and variables. Those running on a thread
	// come first; a description without the others is marked as cut.
	maxGoroutines = 10000
)

// Values are cut after maxValue characters, so more than this is not shown.
var loadValue = proc.LoadConfig{FollowPointers: true, MaxVariableRecurse: 1, MaxStringLen: maxValue, MaxArrayValues: 16, MaxStructFields: 16}

type goVariable struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

type goFrame struct {
	Level     int          `json:"level"`
	PC        string       `json:"pc"`
	Function  string       `json:"function"`
	File      string       `json:"file"`
	Line      int          `json:"line"`
	Arguments []goVariable `json:"arguments"`
	Locals    []goVariable `json:"locals"`
}

type goroutine struct {
	ID int64 `json:"id"`
	// Status is why the goroutine waits, as the Go runtime names it, or
	// "running", "runnable", "syscall".
	Status string `json:"status"`
	// Function is the innermost function outside the Go runtime.
	Function string `json:"function"`
	// Current marks the goroutine of the thread that the core selects: for
	// a crash, the one that crashed.
	Current        bool      `json:"current"`
	ThreadSystemID int       `json:"threadSystemId,omitempty"`
	Frames         []goFrame `json:"frames"`
	Cut            bool      `json:"cut"`
}

// describeGo adds the goroutines of a Go program to gdb's report of its
// core. The report of another program returns unchanged.
func describeGo(ctx context.Context, report []byte, corePath, root string) ([]byte, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(report, &fields); err != nil {
		return nil, err
	}
	var exe string
	json.Unmarshal(fields["executable"], &exe)
	if exe == "" || root == "" {
		return report, nil
	}
	program := exe
	if exe, _ = resolve(root, exe); exe == "" {
		return report, nil
	}
	// Delve reads the program by a path: the path of the file as it is
	// held open here, which the container cannot put a link in the place of.
	held, err := openIn(root, exe)
	if err != nil {
		return report, nil
	}
	defer held.Close()
	exe = fmt.Sprintf("/proc/self/fd/%d", held.Fd())
	info, err := buildinfo.ReadFile(exe)
	if err != nil {
		return report, nil // not a Go program
	}
	goroutines, threads, cut, err := goroutines(ctx, corePath, exe, info.GoVersion)
	if err != nil {
		return nil, err
	}
	add := map[string]any{"runtime": info.GoVersion, "goroutines": goroutines, "goroutinesCut": cut}
	if threads != nil {
		// Functions and lines are from the line table; there are no
		// variables. gdb's stacks of the threads give way to those walked
		// along the frame pointers; its registers and instructions stay
		// with each thread's innermost frame.
		add["withoutDebugInfo"] = true
		// The threads' stacks are then the describer's own as well, read
		// from the program whoever its container keeps it to: no frame of
		// it is left that shows an address for want of reading it, and it
		// is not told as a file that gdb could not read. Where the
		// program has debug information, gdb's stacks of the threads
		// stay, and so does the reason for their addresses.
		readAllTheSame(fields, program)
		var described []map[string]json.RawMessage
		if json.Unmarshal(fields["threads"], &described) == nil {
			for _, thread := range described {
				var id int
				var frames []map[string]any
				json.Unmarshal(thread["systemId"], &id)
				json.Unmarshal(thread["frames"], &frames)
				walked := threads[id].frames
				if len(walked) == 0 {
					continue
				}
				thread["cut"], _ = json.Marshal(threads[id].cut)
				with := make([]any, len(walked))
				for i, frame := range walked {
					with[i] = frame
				}
				if len(frames) > 0 && frames[0]["pc"] == walked[0].PC {
					for _, name := range []string{"function", "file", "line"} {
						delete(frames[0], name)
					}
					first, _ := json.Marshal(walked[0])
					json.Unmarshal(first, &frames[0])
					with[0] = frames[0]
				}
				thread["frames"], _ = json.Marshal(with)
			}
			add["threads"] = described
		}
	}
	for name, value := range add {
		if fields[name], err = json.Marshal(value); err != nil {
			return nil, err
		}
	}
	return json.Marshal(fields)
}

// goroutines reads a core's goroutines with Delve; cut reports that there
// are more than maxGoroutines. For a program without debug information
// they are read without it, and so are the stacks of its threads, which
// are otherwise nil.
func goroutines(ctx context.Context, corePath, exe, version string) (out []goroutine, threads map[int]goStack, cut bool, err error) {
	// Delve reads the memory of a program that may have crashed because that
	// memory is damaged.
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("delve: %v", r)
		}
	}()
	group, err := core.OpenCore(corePath, exe, nil)
	if err != nil {
		return nil, nil, false, err
	}
	defer group.Detach(false)
	target := group.Selected
	runtime, _ := goversion.Parse(version)
	all, _, err := proc.GoroutinesInfo(target, 0, 0)
	if err != nil {
		// Delve finds no goroutines without debug information.
		out, threads, cut, e := lineTableGoroutines(ctx, target, exe, runtime)
		if e != nil {
			return nil, nil, false, fmt.Errorf("%w; without debug information: %v", err, e)
		}
		return out, threads, cut, nil
	}
	gs := all[:0:0]
	for _, g := range all {
		if g.Unreadable == nil {
			gs = append(gs, g)
		}
	}
	if len(gs) > maxGoroutines {
		sort.SliceStable(gs, func(i, j int) bool { return gs[i].Thread != nil && gs[j].Thread == nil })
		gs, cut = gs[:maxGoroutines], true
	}
	sort.Slice(gs, func(i, j int) bool { return gs[i].ID < gs[j].ID })
	selected := target.SelectedGoroutine()
	out = make([]goroutine, 0, len(gs))
	for _, g := range gs {
		if err := ctx.Err(); err != nil {
			return nil, nil, false, err
		}
		d := goroutine{ID: g.ID, Status: goStatus(g, runtime), Current: selected != nil && g.ID == selected.ID, Frames: []goFrame{}}
		if fn := g.UserCurrent().Fn; fn != nil {
			d.Function = fn.Name
		}
		if g.Thread != nil {
			d.ThreadSystemID = g.Thread.ThreadID()
		}
		// Delve returns one frame more than asked for, which tells a deeper stack.
		frames, _ := proc.GoroutineStacktrace(target, g, maxFrames, 0)
		if len(frames) > maxFrames {
			frames, d.Cut = frames[:maxFrames], true
		}
		for i, f := range frames {
			frame := goFrame{Level: i, PC: fmt.Sprintf("0x%016x", f.Current.PC), File: f.Call.File, Line: f.Call.Line}
			if f.Call.Fn != nil {
				frame.Function = f.Call.Fn.Name
			}
			scope := proc.FrameToScope(target, target.Memory(), g, d.ThreadSystemID, frames[i:]...)
			arguments, _ := scope.FunctionArguments(loadValue)
			locals, _ := scope.LocalVariables(loadValue)
			frame.Arguments, frame.Locals = goVariables(arguments), goVariables(locals)
			d.Frames = append(d.Frames, frame)
		}
		out = append(out, d)
	}
	return out, nil, cut, nil
}

func goStatus(g *proc.G, runtime goversion.GoVersion) string {
	switch g.Status {
	case proc.Gwaiting:
		return api.WaitReasonString(&runtime, g.WaitReason)
	case proc.Grunnable:
		return "runnable"
	case proc.Grunning:
		return "running"
	case proc.Gsyscall:
		return "syscall"
	case proc.Gcopystack:
		return "copystack"
	}
	return fmt.Sprintf("status %d", g.Status)
}

func goVariables(vars []*proc.Variable) []goVariable {
	out := make([]goVariable, 0, len(vars))
	for _, v := range vars {
		converted := api.ConvertVar(v)
		value := []rune(converted.SinglelineString())
		if v.Unreadable != nil {
			// As gdb's part says it, mostly of a variable that the compiler optimized away.
			value = []rune("<" + v.Unreadable.Error() + ">")
		}
		if len(value) > maxValue {
			value = append(value[:maxValue], '…')
		}
		out = append(out, goVariable{Name: converted.Name, Type: converted.Type, Value: string(value)})
	}
	return out
}

// readAllTheSame takes a file from those that the description tells as not
// readable to gdb, because its stacks were read another way.
func readAllTheSame(fields map[string]json.RawMessage, name string) {
	var unreadable []string
	if json.Unmarshal(fields["unreadable"], &unreadable) != nil || len(unreadable) == 0 {
		return
	}
	// As the files are named there: without the kernel's word for a file
	// that was replaced, and without detours.
	name = pathpkg.Clean("/" + strings.TrimSuffix(name, " (deleted)"))
	left := slices.DeleteFunc(unreadable, func(file string) bool { return file == name })
	if len(left) == 0 {
		delete(fields, "unreadable")
		return
	}
	fields["unreadable"], _ = json.Marshal(left)
}
