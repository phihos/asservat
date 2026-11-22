package agent

import (
	"bytes"
	"os"
	"strings"
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
