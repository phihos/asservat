package packets

import (
	"sync"
	"testing"

	value "asservat.local/asservat/internal/domain/planning"
	"golang.org/x/net/bpf"
)

// libpcap "greater 1000": ld len; jge #1000; ret #65535; ret #0.
var greater1000 = []value.BPFInstruction{{Code: 0x80}, {Code: 0x35, Jt: 0, Jf: 1, K: 1000}, {Code: 0x06, K: 65535}, {Code: 0x06}}

// Gitar #95: a program with ld len is specialized once per wire length and
// reused, not rebuilt and re-verified per frame; concurrent use is safe.
func TestFilterLengthProgramIsBuiltOncePerWireLength(t *testing.T) {
	f, err := NewFilter(greater1000)
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 60)
	f.Match(frame, 1500)
	if allocs := testing.AllocsPerRun(1000, func() { f.Match(frame, 1500) }); allocs != 0 {
		t.Fatalf("a cached wire length allocates %v per frame", allocs)
	}
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for wire := range 2000 {
				if f.Match(frame, wire+g) != (wire+g >= 1000) {
					t.Error("wrong verdict", wire+g)
					return
				}
			}
		}()
	}
	wg.Wait()
	if len(f.byWire) > maxWireVMs || len(f.byWire) < 2000 {
		t.Fatal("cache size", len(f.byWire))
	}
}

// BenchmarkFilterLengthMatch is the per-frame cost with the cache;
// BenchmarkFilterLengthRebuild is the former per-frame VM construction.
func BenchmarkFilterLengthMatch(b *testing.B) {
	f, err := NewFilter(greater1000)
	if err != nil {
		b.Fatal(err)
	}
	frame := make([]byte, Snaplen)
	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		f.Match(frame, 60+i%1455)
	}
}

func BenchmarkFilterLengthRebuild(b *testing.B) {
	f, err := NewFilter(greater1000)
	if err != nil {
		b.Fatal(err)
	}
	frame := make([]byte, Snaplen)
	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		program := append([]bpf.Instruction(nil), f.program...)
		for _, j := range f.lengths {
			program[j] = bpf.LoadConstant{Dst: bpf.RegA, Val: uint32(60 + i%1455)}
		}
		vm, _ := bpf.NewVM(program)
		_, _ = vm.Run(frame)
	}
}
