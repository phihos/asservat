package agent

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/pprof/profile"
	"go.opentelemetry.io/ebpf-profiler/libpf"
)

// Sampled stacks become a profile that pprof reads: interpreted frames by
// their names, native ones by the symbols of their binary, and a binary
// without symbols by its addresses.
func TestSampledAsProfile(t *testing.T) {
	binary := libpf.NewFrameMappingFile(libpf.FrameMappingFileData{FileID: libpf.NewFileID(1, 2), FileName: libpf.Intern("libwork.so"), GnuBuildID: "abc"})
	mapping := libpf.NewFrameMapping(libpf.FrameMappingData{File: binary, Start: 0x1000, End: 0x9000})
	var python, native libpf.Frames
	python.Append(&libpf.Frame{Type: libpf.PythonFrame, FunctionName: libpf.Intern("render"), SourceFile: libpf.Intern("/app/views.py"), SourceLine: 42})
	python.Append(&libpf.Frame{Type: libpf.NativeFrame, Mapping: mapping, AddressOrLineno: 0x2010})
	python.Append(&libpf.Frame{Type: libpf.PythonFrame, FunctionName: libpf.Intern("main"), SourceFile: libpf.Intern("/app/main.py"), SourceLine: 7})
	native.Append(&libpf.Frame{Type: libpf.NativeFrame, Mapping: mapping, AddressOrLineno: 0x5000})
	stacks := map[stackKey]*sampledStack{
		{(&libpf.Trace{Frames: python}).Hash(), 10}: {frames: python, pid: 10, comm: "python3", count: 3},
		{(&libpf.Trace{Frames: native}).Hash(), 11}: {frames: native, pid: 11, comm: "worker", count: 1},
	}
	name := func(file libpf.FileID, address uint64) string {
		if file == libpf.NewFileID(1, 2) && address == 0x2010 {
			return "compress"
		}
		return ""
	}
	began := time.Unix(1700000000, 0)
	var packed bytes.Buffer
	if err := sampledAsProfile(sampledCPU, stacks, began, 30*time.Second, name).Write(&packed); err != nil {
		t.Fatal(err)
	}
	prof, err := profile.Parse(&packed)
	if err != nil {
		t.Fatal("pprof does not read the profile:", err)
	}
	if len(prof.Sample) != 2 || prof.DurationNanos != (30*time.Second).Nanoseconds() || prof.Period != int64(time.Second/sampleRate) {
		t.Fatal(prof)
	}
	// The stack seen most comes first, its innermost frame first.
	first := prof.Sample[0]
	var names []string
	for _, l := range first.Location {
		names = append(names, l.Line[0].Function.Name)
	}
	if strings.Join(names, " < ") != "render < compress < main" || first.Value[0] != 3 || first.Value[1] != 3*prof.Period {
		t.Fatal(names, first.Value)
	}
	if first.Label["process"][0] != "python3" || first.NumLabel["pid"][0] != 10 || first.Location[0].Line[0].Line != 42 || first.Location[0].Line[0].Function.Filename != "/app/views.py" {
		t.Fatal(first.Label, first.NumLabel, first.Location[0].Line[0])
	}
	if m := first.Location[1].Mapping; m == nil || m.File != "libwork.so" || m.BuildID != "abc" {
		t.Fatal("the native frame's binary", m)
	}
	if got := prof.Sample[1].Location[0].Line[0].Function.Name; got != "libwork.so+0x5000" {
		t.Fatal("a function without a symbol", got)
	}
	// The same stacks at page faults count pages of memory.
	grown := sampledAsProfile(sampledMemory, stacks, began, 30*time.Second, name)
	if got := grown.SampleType[1]; got.Type != "memory" || got.Unit != "bytes" || grown.Sample[0].Value[1] != 3*int64(os.Getpagesize()) || grown.CheckValid() != nil {
		t.Fatal("memory growth", got, grown.Sample[0].Value, grown.CheckValid())
	}
}

// The functions of a binary are found by an address inside them. The test
// binary itself is the binary; go test links it with few symbols.
func TestSymbolTable(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	table := readSymbols(self)
	if len(table) == 0 {
		t.Skip("the test binary carries no symbols")
	}
	for i, s := range table {
		if s.Size > 1 && (i+1 == len(table) || table[i+1].Value > s.Value) {
			if got := table.name(s.Value + 1); got != s.Name {
				t.Fatal("inside", s.Name, "is", got)
			}
		}
	}
}

func TestSymbolTableBounds(t *testing.T) {
	if got := (symbolTable{{Name: "_ZN3foo3barEv", Value: 0x100, Size: 0x10}}).name(0x108); got != "foo::bar()" {
		t.Fatal("a C++ name", got)
	}
	table := symbolTable{{Name: "f", Value: 0x100, Size: 0x10}}
	if table.name(0xff) != "" || table.name(0x110) != "" || readSymbols("/nonexistent") != nil || symbolTable(nil).name(1) != "" {
		t.Fatal("an address outside every function got a name")
	}
}

// A profile that is kept running for a watch holds the seconds of its
// window and drops what is older; a capture takes the stacks from a moment
// on, each with how often it was seen.
func TestKeptProfileHoldsItsWindow(t *testing.T) {
	p := newSampledProfile(sampledCPU, 10*time.Second)
	start := time.Unix(1700000000, 0)
	at := func(second int) time.Time { return start.Add(time.Duration(second) * time.Second) }
	busy, idle := stackKey{pid: 1}, stackKey{pid: 2}
	stack := func(comm string) func() *sampledStack {
		return func() *sampledStack { return &sampledStack{comm: comm} }
	}
	for second := 0; second < 30; second++ {
		p.add(busy, at(second), stack("busy"))
		p.add(busy, at(second), stack("busy"))
		if second == 25 {
			p.add(idle, at(second), stack("idle"))
		}
	}
	if len(p.seconds) != 11 {
		t.Fatalf("a window of 10 seconds holds %d seconds", len(p.seconds))
	}
	if len(p.stacks) != 2 {
		t.Fatal("stacks held:", len(p.stacks))
	}
	// A stack goes with the last second that saw it.
	short := newSampledProfile(sampledCPU, 2*time.Second)
	short.add(idle, at(0), stack("idle"))
	for second := 0; second < 5; second++ {
		short.add(busy, at(second), stack("busy"))
	}
	if len(short.stacks) != 1 || short.stacks[idle] != nil || short.since(time.Time{})[busy].count != 3 {
		t.Fatal("stacks held after the idle one's second went:", len(short.stacks))
	}
	all := p.since(time.Time{})
	if len(all) != 2 || all[busy].count != 22 || all[idle].count != 1 || all[busy].comm != "busy" {
		t.Fatal("everything in the window", all[busy], all[idle])
	}
	if recent := p.since(at(27)); len(recent) != 1 || recent[busy].count != 6 {
		t.Fatal("the last three seconds", recent)
	}
	// Taking the stacks leaves the profile as it is.
	if again := p.since(at(27)); again[busy].count != 6 {
		t.Fatal("taken twice", again[busy])
	}
	// Without a window everything is kept.
	whole := newSampledProfile(sampledCPU, 0)
	for second := 0; second < 100; second++ {
		whole.add(busy, at(second), stack("busy"))
	}
	if got := whole.since(time.Time{})[busy].count; got != 100 {
		t.Fatal("a profile without a window", got)
	}
}

// The processes of a pod are looked for without the lock that every sample
// of the node waits for.
func TestCoverSearchesOutsideTheSamplersLock(t *testing.T) {
	proc, _ := fakeProc(t, "0123abcd", 0)
	// The cgroup file of a process is a pipe here: the search waits at it
	// until this test has written it.
	pipe := filepath.Join(proc, "1201", "cgroup")
	os.Remove(pipe)
	if err := syscall.Mkfifo(pipe, 0o600); err != nil {
		t.Fatal(err)
	}
	a, p := &Agent{Proc: proc}, newSampledProfile(sampledCPU, 0)
	covered := make(chan struct{})
	go func() {
		a.cover(p, runningPod("app", "0123abcd"), nil)
		close(covered)
	}()
	writer, err := os.OpenFile(pipe, os.O_WRONLY, 0) // returns once the search reads the pipe
	if err != nil {
		t.Fatal(err)
	}
	free := a.sampler.mu.TryLock()
	if free {
		a.sampler.mu.Unlock()
	}
	writer.WriteString("0::/kubelet.slice/cri-containerd-0123abcd.scope\n")
	writer.Close()
	<-covered
	if !free {
		t.Fatal("the sampler's lock was held during the search")
	}
	if !p.containers["0123abcd"] || !p.pids[1200] || !p.pids[1201] {
		t.Fatal("covered", p.containers, p.pids)
	}
}

// busyProfile fills a kept profile as a busy pod does: so many stacks of 40
// frames, each seen in every second, for some seconds more than the window.
func busyProfile(stacks int, window time.Duration) *sampledProfile {
	var frames libpf.Frames
	for line := range 40 {
		frames.Append(&libpf.Frame{Type: libpf.PythonFrame, FunctionName: libpf.Intern("work"), SourceLine: libpf.SourceLineno(line)})
	}
	p := newSampledProfile(sampledCPU, window)
	start := time.Unix(1700000000, 0)
	for second := range int(window/time.Second) + 10 {
		for i := range stacks {
			p.add(stackKey{trace: libpf.NewTraceHash(0, uint64(i)), pid: 1}, start.Add(time.Duration(second)*time.Second), func() *sampledStack {
				return &sampledStack{frames: slices.Clone(frames), pid: 1, comm: "busy"}
			})
		}
	}
	return p
}

// A kept profile holds the frames of a stack once, however many seconds
// saw it.
func TestKeptProfileHoldsEachStackOnce(t *testing.T) {
	held := func() uint64 {
		var m runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&m)
		return m.HeapAlloc
	}
	before := held()
	p := busyProfile(1600, 70*time.Second)
	holds := held() - before
	t.Logf("1,600 stacks of 40 frames per second over a window of 70 seconds: %.1f MiB", float64(holds)/(1<<20))
	if holds > 16<<20 {
		t.Fatalf("the profile holds %d bytes", holds)
	}
	seventh := stackKey{trace: libpf.NewTraceHash(0, 7), pid: 1}
	if all := p.since(time.Time{}); len(all) != 1600 || all[seventh].count != 71 || len(all[seventh].frames) != 40 {
		t.Fatal("the stacks of the window", len(all))
	}
	runtime.KeepAlive(p)
}

func BenchmarkKeptProfile(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		busyProfile(1600, 70*time.Second)
	}
}
