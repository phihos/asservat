package artifact

import "testing"

// B3: a finite syscall metadata recording carries sorted names and budgets,
// no filter program, the fixed record size and at most 60 seconds; a packet
// recording cannot carry a syscall selection.
func TestSyscallRecordingBounds(t *testing.T) {
	ok := Recording{Kind: "syscallTrace", Profile: "metadata", Composition: []byte("{}"), DurationMillis: 10_000, MaxBytes: 1 << 20, Snaplen: RecordingSyscallSnaplen,
		Syscalls: &RecordingSyscalls{Names: []string{"openat", "read"}, MaxEventsPerSecond: 100, MaxTrackedThreads: 64}}
	if !ok.Valid() || !ok.Clone().Valid() {
		t.Fatal("valid syscall recording refused")
	}
	for name, edit := range map[string]func(*Recording){
		"unsorted names":  func(r *Recording) { r.Syscalls.Names = []string{"read", "openat"} },
		"packet snaplen":  func(r *Recording) { r.Snaplen = RecordingSnaplen },
		"filter program":  func(r *Recording) { r.Filter = &RecordingFilter{Expression: "tcp", Program: []FilterInstruction{{}}} },
		"no budgets":      func(r *Recording) { r.Syscalls = nil },
		"packet selector": func(r *Recording) { r.Kind, r.Profile, r.Snaplen = "packetCapture", "networkHeaders", RecordingSnaplen },
	} {
		r := ok.Clone()
		edit(r)
		if r.Valid() {
			t.Fatal(name, "accepted")
		}
	}
}
