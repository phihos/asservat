package syscalls

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func argumentProbe(phase uint32, tid uint32, start, mono uint64) ArgumentProbe {
	return ArgumentProbe{Event: ArgumentRecord{Type: phase, Phase: uint8(phase), PID: 20, TID: tid, TaskStart: start, ProcessStart: 50, Monotonic: mono, Boot: 1000 + uint64(phase), Number: 1, ScalarMask: 5, Scalar: [6]uint64{3, 0, 2}}, Memory: &ArgumentRecord{Data: []byte{0xff, 0}, Truncated: false}}
}
func TestArgumentPairerRepeatedHalvesStayBounded(t *testing.T) {
	p, _ := NewArgumentPairer(1)
	for i := 0; i < 20; i++ {
		p.Add(argumentProbe(EventEnter, 1, 10, 100))
		if len(p.order) > 2 {
			t.Fatalf("unbounded pending order: %d", len(p.order))
		}
	}
}
func TestArgumentPairerReverseDeliveryAndIncarnation(t *testing.T) {
	p, _ := NewArgumentPairer(8)
	p.Add(argumentProbe(EventExit, 1, 10, 100))
	p.Add(argumentProbe(EventEnter, 2, 10, 100))
	p.Add(argumentProbe(EventEnter, 1, 11, 100))
	out := p.Add(argumentProbe(EventEnter, 1, 10, 100))
	if len(out) != 1 || out[0].Entry == nil || out[0].Exit == nil || out[0].Entry.Event.TaskStart != 10 {
		t.Fatal(out)
	}
	count := 0
	p.Flush(func(c ArgumentCall) {
		count++
		if c.Entry == nil || c.Exit != nil {
			t.Fatal(c)
		}
	})
	if count != 2 || len(p.pending) != 0 {
		t.Fatal(count)
	}
}
func TestArgumentEventKeepsBinaryAndDistinctFaultWithoutPointer(t *testing.T) {
	defs, _ := ArgumentDefinitions([]string{"write"}, true, 128)
	enter, exit := argumentProbe(EventEnter, 1, 10, 100), argumentProbe(EventExit, 1, 10, 100)
	exit.Memory = nil
	enter.Event.Scalar[1] = 0xdeadbeef
	meta := ArgumentHeader{PodUID: "pod", BootID: "boot", SourceEpoch: "source"}
	event, err := ArgumentEvent(ArgumentCall{Entry: &enter, Exit: &exit}, meta, time.Unix(0, 0), defs)
	if err != nil || event.Outcome != "success" || *event.DurationNS != 1 || len(event.Arguments) != 3 || event.Arguments[2].Value != "base64:/wA=" {
		t.Fatal(event, err)
	}
	raw, _ := AppendArgumentLine(nil, ArgumentEventLine{Record: "event", Event: event})
	if bytes.Contains(raw, []byte("deadbeef")) || strings.Contains(string(raw), "3735928559") {
		t.Fatal("pointer persisted")
	}
	enter.Memory.Failed = true
	event, _ = ArgumentEvent(ArgumentCall{Entry: &enter, Exit: &exit}, meta, time.Unix(0, 0), defs)
	if event.Arguments[2].Value != "unavailable:fault" {
		t.Fatal(event)
	}
}
