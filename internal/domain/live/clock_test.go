package live

import (
	"testing"
	"time"
)

func TestLiveClockProofNeverUsesArrivalAsOriginalTime(t *testing.T) {
	now := time.Now().UTC()
	p := ClockProof{SourceID: "source", BootID: "boot", Clock: "monotonic", RemoteNanos: int64(time.Hour), StartedAt: now, ReceivedAt: now.Add(2 * time.Second), SampleUncertainty: time.Millisecond}
	at, end, ms, ok := p.Place(int64(time.Hour-time.Second), "source", "boot", "monotonic", now.Add(time.Hour), now.Add(time.Hour), now.Add(time.Hour))
	if !ok || !at.Equal(now) || !end.Equal(now.Add(29*time.Second-time.Millisecond)) || ms != 1001 {
		t.Fatal(at, end, ms, ok)
	}
	for name, mut := range map[string]func(*ClockProof){"no sample": func(v *ClockProof) { v.RemoteNanos = 0 }, "new boot": func(v *ClockProof) { v.BootID = "replacement" }, "unbounded transit": func(v *ClockProof) { v.ReceivedAt = now.Add(6 * time.Second) }, "reversed": func(v *ClockProof) { v.ReceivedAt = now.Add(-time.Second) }} {
		t.Run(name, func(t *testing.T) {
			v := p
			mut(&v)
			if _, _, _, ok := v.Place(int64(time.Hour-time.Second), "source", "boot", "monotonic", now.Add(time.Hour), now.Add(time.Hour), now.Add(time.Hour)); ok {
				t.Fatal("unknown mapping accepted")
			}
		})
	}
	if _, _, _, ok := p.Place(int64(time.Hour+time.Second), "source", "boot", "monotonic", now.Add(time.Hour), now.Add(time.Hour), now.Add(time.Hour)); ok {
		t.Fatal("future source stamp")
	}
	if _, _, _, ok := p.Place(int64(time.Hour-time.Minute), "source", "boot", "monotonic", now.Add(time.Hour), now.Add(time.Hour), now.Add(time.Hour)); ok {
		t.Fatal("old row replay")
	}
}

func TestLiveClockRejectsExtremeStampsBeforeDurationArithmetic(t *testing.T) {
	now := time.Now()
	p := ClockProof{SourceID: "source", BootID: "boot", Clock: "monotonic", RemoteNanos: 1<<63 - 1, StartedAt: now, ReceivedAt: now, SampleUncertainty: time.Second}
	if _, _, _, ok := p.Place(1, "source", "boot", "monotonic", now.Add(time.Hour), now.Add(time.Hour), now.Add(time.Hour)); ok {
		t.Fatal("overflowed old timestamp accepted")
	}
}
