package planning

import "testing"

func TestSyscallArgumentsEditBoundsAndClone(t *testing.T) {
	c := &ProfileComposition{Components: []ProfileComponent{{ID: "calls", Profile: ProfileRef{Catalog: "namespace", Name: "calls", Version: "v1"}, Edits: []ProfileEdit{{ActionID: "syscalls", Field: "syscallArguments", SyscallArguments: &SyscallArgumentsEdit{MaxBytesPerEvent: 128, CaptureBuffers: false}}}}}, MaxTotalBytes: 1024, MaxDuration: "5s"}
	if !c.Valid() {
		t.Fatal("bounded argument edit invalid")
	}
	clone := c.Clone()
	clone.Components[0].Edits[0].SyscallArguments.MaxBytesPerEvent = 4096
	clone.Components[0].Edits[0].SyscallArguments.CaptureBuffers = true
	if c.Components[0].Edits[0].SyscallArguments.MaxBytesPerEvent != 128 || c.Components[0].Edits[0].SyscallArguments.CaptureBuffers {
		t.Fatal("clone mutated original argument edit")
	}
	for _, bound := range []int64{-1, 0, 4097} {
		clone.Components[0].Edits[0].SyscallArguments.MaxBytesPerEvent = bound
		if clone.Valid() {
			t.Fatal("unbounded argument edit", bound)
		}
	}
	clone = c.Clone()
	clone.Components[0].Edits[0].Number = 1
	if clone.Valid() {
		t.Fatal("mixed edit value accepted")
	}
}
