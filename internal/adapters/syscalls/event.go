// Package syscalls holds the user-space steps of syscall metadata recording:
// decoding Inspektor Gadget traceloop v0.57.0 kernel records, pairing enter
// and exit, a fixed ring record, errno/syscall naming, the JSON Lines window
// encoder (syscall-results.schema.json#/$defs/event) and an event rate
// bucket. It performs no I/O and loads no eBPF. Only metadata leaves this
// package: the task name (comm) and argument registers are never retained.
package syscalls

import (
	"encoding/binary"
	"errors"
)

// Event types of traceloop's `enum event_type`.
const (
	EventEnter uint32 = 0
	EventExit  uint32 = 1
	EventCont  uint32 = 2 // only with argument definitions (wasm layer); never expected
)

// Layout of traceloop's `struct syscall_event_t` (x86_64/arm64 C ABI, little
// endian). Derived from program.bpf.c; the 8-byte alignment of the __u64
// members inserts padding after event_type and rounds the size up:
//
//	off  size  field
//	  0     4  enum event_type event_type
//	  4     4  (alignment padding for args)
//	  8    48  __u64 args[6]          (EXIT: args[0] = ret)
//	 56     8  __u64 monotonic_timestamp (EXIT: copy of the ENTER value)
//	 64     8  __u64 boot_timestamp
//	 72     4  __u32 pid               (tgid: pid_tgid >> 32)
//	 76     2  __u16 cpu
//	 78     2  __u16 id                (syscall number)
//	 80    16  __u8 comm[16]           (not decoded)
//	 96     1  __u8 cont_nr
//	 97    60  __u8 padding[60]
//	157     3  (tail padding to 8-byte alignment)
//	160        sizeof
//
// Cross-check: syscall_event_cont_t is event_type (0..4) + param[128] (4..132),
// pad to 136, two __u64 (136..152), index, failed (..154), rounded to 160,
// matching the C _Static_assert that both structs have the same size.
const (
	EventSize = 160
	// A perf PERF_SAMPLE_RAW payload is padded so that its u32 size header
	// plus data end on 8 bytes: round_up(160+4, 8)-4 = 164. cilium/ebpf's
	// Record.RawSample includes those 4 unspecified padding bytes.
	PerfSampleSize = EventSize + 4

	offType   = 0
	offArg0   = 8
	offMono   = 56
	offBoot   = 64
	offPID    = 72
	offNumber = 78
)

// ErrEventSize rejects a record that is neither the struct nor its perf sample.
var ErrEventSize = errors.New("syscalls: unexpected traceloop event size")

// RawEvent is the metadata of one traceloop record. Ret is set only for EXIT;
// for ENTER args[0] is the first argument register and is not decoded.
type RawEvent struct {
	Type      uint32
	Number    uint16
	PID       uint32
	Monotonic uint64 // pairing key; EXIT carries the ENTER value
	Boot      uint64 // CLOCK_BOOTTIME ns at this event
	Ret       int64
}

// DecodeEvent decodes one record of exactly EventSize or PerfSampleSize bytes.
// Type is not range-checked here; the Pairer counts non-ENTER/EXIT events.
func DecodeEvent(b []byte) (RawEvent, error) {
	if len(b) != EventSize && len(b) != PerfSampleSize {
		return RawEvent{}, ErrEventSize
	}
	le := binary.LittleEndian
	e := RawEvent{
		Type:      le.Uint32(b[offType:]),
		Number:    le.Uint16(b[offNumber:]),
		PID:       le.Uint32(b[offPID:]),
		Monotonic: le.Uint64(b[offMono:]),
		Boot:      le.Uint64(b[offBoot:]),
	}
	if e.Type == EventExit {
		e.Ret = int64(le.Uint64(b[offArg0:]))
	}
	return e, nil
}
