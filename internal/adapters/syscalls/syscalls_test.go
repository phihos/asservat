package syscalls

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// rawStruct builds a syscall_event_t at the documented offsets, filling the
// argument registers and comm with markers that must never be decoded.
func rawStruct(typ uint32, nr uint16, pid uint32, mono, boot uint64, arg0 uint64) []byte {
	b := make([]byte, EventSize)
	le := binary.LittleEndian
	le.PutUint32(b[0:], typ)
	le.PutUint32(b[4:], 0xdeadbeef) // alignment hole
	le.PutUint64(b[8:], arg0)
	for i := 1; i < 6; i++ {
		le.PutUint64(b[8+8*i:], 0x4141414141414141)
	}
	le.PutUint64(b[56:], mono)
	le.PutUint64(b[64:], boot)
	le.PutUint32(b[72:], pid)
	le.PutUint16(b[76:], 7) // cpu
	le.PutUint16(b[78:], nr)
	copy(b[80:96], "secret-comm-xyz!")
	return b
}

func TestDecodeEventLayout(t *testing.T) {
	enter := rawStruct(EventEnter, 257, 4242, 1000, 5000, 0x7fff0000beef)
	exit := rawStruct(EventExit, 257, 4242, 1000, 9000, uint64(^uint64(1))) // -2
	cont := rawStruct(EventCont, 0, 0, 1000, 0, 0)
	cases := []struct {
		name string
		b    []byte
		want RawEvent
		err  error
	}{
		{"enter hides first argument", enter, RawEvent{Type: EventEnter, Number: 257, PID: 4242, Monotonic: 1000, Boot: 5000}, nil},
		{"exit carries ret", exit, RawEvent{Type: EventExit, Number: 257, PID: 4242, Monotonic: 1000, Boot: 9000, Ret: -2}, nil},
		{"perf padded sample", append(bytes.Clone(exit), 1, 2, 3, 4), RawEvent{Type: EventExit, Number: 257, PID: 4242, Monotonic: 1000, Boot: 9000, Ret: -2}, nil},
		{"cont decoded for counting", cont, RawEvent{Type: EventCont, Monotonic: 1000}, nil},
		{"empty", nil, RawEvent{}, ErrEventSize},
		{"short", enter[:EventSize-1], RawEvent{}, ErrEventSize},
		{"unpadded C size", enter[:157], RawEvent{}, ErrEventSize},
		{"between sizes", append(bytes.Clone(enter), 0), RawEvent{}, ErrEventSize},
		{"too long", append(bytes.Clone(enter), make([]byte, 8)...), RawEvent{}, ErrEventSize},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeEvent(tc.b)
			if !errors.Is(err, tc.err) || got != tc.want {
				t.Fatalf("got %+v, %v; want %+v, %v", got, err, tc.want, tc.err)
			}
		})
	}
}

func ev(typ uint32, nr uint16, pid uint32, mono, boot uint64, ret int64) RawEvent {
	return RawEvent{Type: typ, Number: nr, PID: pid, Monotonic: mono, Boot: boot, Ret: ret}
}

func TestPairer(t *testing.T) {
	type step struct {
		e    RawEvent
		want *Call
	}
	cases := []struct {
		name    string
		max     int
		steps   []step
		stats   Stats
		gaps    uint64
		flushed []Call
	}{
		{name: "enter then exit", max: 4, steps: []step{
			{ev(EventEnter, 0, 10, 100, 1000, 0), nil},
			{ev(EventExit, 0, 10, 100, 1500, 42), &Call{Number: 0, Status: Returned, PID: 10, EnteredBoot: 1000, ExitedBoot: 1500, Ret: 42}},
		}, stats: Stats{Calls: 1}},
		{name: "exit before enter (cross-CPU order)", max: 4, steps: []step{
			{ev(EventExit, 1, 10, 100, 1500, -9), nil},
			{ev(EventEnter, 1, 10, 100, 1000, 0), &Call{Number: 1, Status: Returned, PID: 10, EnteredBoot: 1000, ExitedBoot: 1500, Ret: -9}},
		}, stats: Stats{Calls: 1}},
		{name: "same timestamp different pid", max: 4, steps: []step{
			{ev(EventEnter, 0, 10, 100, 1000, 0), nil},
			{ev(EventEnter, 1, 11, 100, 1001, 0), nil},
			{ev(EventExit, 1, 11, 100, 1100, 0), &Call{Number: 1, Status: Returned, PID: 11, EnteredBoot: 1001, ExitedBoot: 1100}},
			{ev(EventExit, 0, 10, 100, 1200, 0), &Call{Number: 0, Status: Returned, PID: 10, EnteredBoot: 1000, ExitedBoot: 1200}},
		}, stats: Stats{Calls: 2}},
		{name: "nonreturning calls complete at enter", max: 4, steps: []step{
			{ev(EventEnter, 60, 10, 1, 10, 0), &Call{Number: 60, Status: NoReturn, PID: 10, EnteredBoot: 10}},
			{ev(EventEnter, 231, 10, 2, 20, 0), &Call{Number: 231, Status: NoReturn, PID: 10, EnteredBoot: 20}},
			{ev(EventEnter, 15, 10, 3, 30, 0), &Call{Number: 15, Status: NoReturn, PID: 10, EnteredBoot: 30}},
		}, stats: Stats{Calls: 3}},
		{name: "cont and unknown types are invariant violations", max: 4, steps: []step{
			{ev(EventCont, 0, 10, 1, 10, 0), nil},
			{ev(7, 0, 10, 1, 10, 0), nil},
		}, stats: Stats{Invalid: 2}, gaps: 2},
		{name: "overflow evicts the first waiting half", max: 2, steps: []step{
			{ev(EventEnter, 0, 10, 300, 3000, 0), nil},
			{ev(EventEnter, 1, 10, 100, 1000, 0), nil},
			{ev(EventEnter, 2, 10, 200, 2000, 0), nil}, // evicts mono 300 (first in)
			{ev(EventExit, 0, 10, 300, 3300, 0), nil},  // its EXIT now waits (evicts 100)
			{ev(EventExit, 2, 10, 200, 2200, 0), &Call{Number: 2, Status: Returned, PID: 10, EnteredBoot: 2000, ExitedBoot: 2200}},
		}, stats: Stats{Calls: 1, Overflow: 2, Unmatched: 1}, gaps: 3,
			flushed: []Call{{Number: 0, Status: Unmatched, PID: 10, ExitedBoot: 3300}}},
		{name: "duplicate exit replaces and counts unmatched", max: 4, steps: []step{
			{ev(EventExit, 0, 10, 100, 1500, 1), nil},
			{ev(EventExit, 0, 10, 100, 1600, 2), nil},
		}, stats: Stats{Unmatched: 2}, gaps: 2,
			flushed: []Call{{Number: 0, Status: Unmatched, PID: 10, ExitedBoot: 1600, Ret: 2}}},
		{name: "duplicate enter keeps newer", max: 4, steps: []step{
			{ev(EventEnter, 0, 10, 100, 1000, 0), nil},
			{ev(EventEnter, 3, 10, 100, 1001, 0), nil},
		}, stats: Stats{Unfinished: 2},
			flushed: []Call{{Number: 3, Status: Unfinished, PID: 10, EnteredBoot: 1001}}},
		{name: "flush orders unfinished and unmatched by time", max: 8, steps: []step{
			{ev(EventEnter, 232, 12, 500, 5000, 0), nil},
			{ev(EventExit, 0, 11, 50, 4000, -4), nil},
			{ev(EventEnter, 7, 10, 400, 4000, 0), nil},
		}, stats: Stats{Unfinished: 2, Unmatched: 1}, gaps: 1,
			flushed: []Call{
				{Number: 7, Status: Unfinished, PID: 10, EnteredBoot: 4000},
				{Number: 0, Status: Unmatched, PID: 11, ExitedBoot: 4000, Ret: -4},
				{Number: 232, Status: Unfinished, PID: 12, EnteredBoot: 5000},
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := NewPairer(tc.max)
			for i, s := range tc.steps {
				got, ok := p.Add(s.e)
				if ok != (s.want != nil) || (ok && got != *s.want) {
					t.Fatalf("step %d: got %+v %v, want %+v", i, got, ok, s.want)
				}
				if p.Pending() > tc.max {
					t.Fatalf("step %d: %d pending beyond bound %d", i, p.Pending(), tc.max)
				}
			}
			flushed := p.Flush()
			if len(flushed) != len(tc.flushed) {
				t.Fatalf("flushed %+v, want %+v", flushed, tc.flushed)
			}
			for i := range flushed {
				if flushed[i] != tc.flushed[i] {
					t.Fatalf("flushed %+v, want %+v", flushed, tc.flushed)
				}
			}
			if p.Stats() != tc.stats {
				t.Fatalf("stats %+v, want %+v", p.Stats(), tc.stats)
			}
			if g := p.TakeGaps(); g != tc.gaps {
				t.Fatalf("gaps %d, want %d", g, tc.gaps)
			}
			if p.TakeGaps() != 0 || p.Pending() != 0 {
				t.Fatal("gaps/pending not reset")
			}
		})
	}
}

func TestPairerMinimumBound(t *testing.T) {
	p := NewPairer(0)
	p.Add(ev(EventEnter, 0, 1, 1, 1, 0))
	p.Add(ev(EventEnter, 0, 1, 2, 2, 0))
	if p.Pending() != 1 || p.Stats().Overflow != 1 {
		t.Fatalf("pending %d stats %+v", p.Pending(), p.Stats())
	}
}

func TestRecordRoundTrip(t *testing.T) {
	calls := []Call{
		{Number: 0, Status: Returned, PID: 1, EnteredBoot: 1, ExitedBoot: 2, Ret: 0},
		{Number: 0xffff, Status: Returned, PID: 0xffffffff, EnteredBoot: ^uint64(0) - 1, ExitedBoot: ^uint64(0), Ret: -4095},
		{Number: 9, Status: Returned, PID: 2, EnteredBoot: 5, ExitedBoot: 6, Ret: 0x7fffdeadb000},
		{Number: 60, Status: NoReturn, PID: 3, EnteredBoot: 7},
		{Number: 7, Status: Unfinished, PID: 4, EnteredBoot: 8},
		{Number: 1, Status: Unmatched, PID: 5, ExitedBoot: 9, Ret: -1 << 63},
	}
	var ring []byte
	for _, c := range calls {
		b := MarshalRecord(c)
		if len(b) != RecordSize || RecordSize > 48 {
			t.Fatal("record size", len(b))
		}
		got, err := UnmarshalRecord(b)
		if err != nil || got != c {
			t.Fatalf("round trip %+v -> %+v, %v", c, got, err)
		}
		ring = AppendRecord(ring, c)
	}
	for i, c := range calls {
		if got, err := UnmarshalRecord(ring[i*RecordSize : (i+1)*RecordSize]); err != nil || got != c {
			t.Fatalf("appended record %d: %+v %v", i, got, err)
		}
	}
	good := MarshalRecord(calls[0])
	for name, b := range map[string][]byte{
		"empty":         nil,
		"short":         good[:RecordSize-1],
		"long":          append(bytes.Clone(good), 0),
		"zero status":   append([]byte{0}, good[1:]...),
		"status 5":      append([]byte{5}, good[1:]...),
		"reserved byte": append([]byte{good[0], 1}, good[2:]...),
	} {
		if _, err := UnmarshalRecord(b); !errors.Is(err, ErrRecord) {
			t.Fatal("accepted malformed record:", name)
		}
	}
}

func TestErrno(t *testing.T) {
	cases := []struct {
		ret    int64
		name   string
		failed bool
	}{
		{0, "", false},
		{42, "", false},
		{0x7fffdeadb000, "", false}, // mmap address
		{-4096, "", false},          // outside the errno range
		{-1 << 63, "", false},
		{-1, "EPERM", true},
		{-2, "ENOENT", true},
		{-11, "EAGAIN", true},
		{-110, "ETIMEDOUT", true},
		{-512, "ERESTARTSYS", true},
		{-513, "ERESTARTNOINTR", true},
		{-514, "ERESTARTNOHAND", true},
		{-515, "ENOIOCTLCMD", true},
		{-516, "ERESTART_RESTARTBLOCK", true},
		{-4000, "errno_4000", true},
		{-4095, "errno_4095", true},
	}
	for _, tc := range cases {
		name, failed := Errno(tc.ret)
		if name != tc.name || failed != tc.failed {
			t.Errorf("Errno(%d) = %q %v, want %q %v", tc.ret, name, failed, tc.name, tc.failed)
		}
	}
}

func TestName(t *testing.T) {
	for nr, want := range map[uint16]string{0: "read", 1: "write", 15: "rt_sigreturn", 59: "execve", 60: "exit", 231: "exit_group", 257: "openat", 0xfff: "syscall_fff"} {
		if got := Name(nr); got != want {
			t.Errorf("Name(%d) = %q, want %q", nr, got, want)
		}
	}
}

// Orphaned halves (killed threads, lost partners) cycle through a full table
// in constant time per event: each insert evicts at most a few queue entries.
func TestPairerFullTableStaysBounded(t *testing.T) {
	p := NewPairer(4)
	for i := uint64(1); i <= 10_000; i++ {
		p.Add(RawEvent{Type: EventEnter, Number: 0, PID: 10, Monotonic: i, Boot: i})
		if p.Pending() > 4 || len(p.order) > 8 {
			t.Fatalf("event %d: pending %d, queue %d", i, p.Pending(), len(p.order))
		}
	}
	if p.Stats().Overflow != 10_000-4 {
		t.Fatalf("overflow %d", p.Stats().Overflow)
	}
}
