package syscalls

import "testing"

func TestLiveSyscallPreservesKnownZeroAndUnknownPairing(t *testing.T) {
	c := Call{Number: 0, Status: Returned, PID: 10, EnteredBoot: 1, ExitedBoot: 1, Ret: 0}
	out, ok := LiveMetadata(MarshalRecord(c))
	if !ok || out.Error || out.Errno == nil || *out.Errno != 0 || out.Duration == nil || *out.Duration != 0 || !out.Paired {
		t.Fatal(out, ok)
	}
	c.Status = Unmatched
	c.EnteredBoot = 0
	c.Ret = -2
	out, ok = LiveMetadata(MarshalRecord(c))
	if !ok || !out.Error || out.Errno == nil || *out.Errno != 2 || out.Paired || out.Duration != nil {
		t.Fatal(out, ok)
	}
	for _, status := range []Status{NoReturn, Unfinished} {
		c.Status = status
		if _, ok = LiveMetadata(MarshalRecord(c)); ok {
			t.Fatal("unknown error classified", status)
		}
	}
}
