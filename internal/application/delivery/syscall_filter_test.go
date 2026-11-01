package delivery

import (
	"testing"

	"asservat.local/asservat/internal/domain/collector"
)

func TestSyscallFilterDigestBindsTheWholeSelection(t *testing.T) {
	base := collector.SyscallFilter{MaxEvents: 100_000, MaxTrackedThreads: 4096}
	empty := base
	empty.Names = []string{}
	if SyscallFilterDigest(empty) != SyscallFilterDigest(base) {
		t.Fatal("nil and empty all-syscalls selections differ")
	}
	seen := map[[32]byte]bool{SyscallFilterDigest(base): true}
	for _, edit := range []func(*collector.SyscallFilter){
		func(f *collector.SyscallFilter) { f.Names = []string{"openat", "read"} },
		func(f *collector.SyscallFilter) { f.ErrorsOnly = true },
		func(f *collector.SyscallFilter) { f.MaxEvents = 10 },
		func(f *collector.SyscallFilter) { f.MaxTrackedThreads = 16 },
	} {
		f := base
		edit(&f)
		d := SyscallFilterDigest(f)
		if d == ([32]byte{}) || seen[d] {
			t.Fatalf("digest does not bind %+v", f)
		}
		seen[d] = true
	}
}
