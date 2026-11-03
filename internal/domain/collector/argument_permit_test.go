package collector

import (
	"testing"
	"time"
)

func TestArgumentPermitKeepsDistinctOriginalFiniteAuthority(t *testing.T) {
	now := time.Date(2026, 11, 3, 1, 0, 0, 0, time.UTC)
	p := ArgumentObservationPermit{Binding: ArgumentObservationBinding{Scope: [32]byte{1}, ProgramDigest: [32]byte{2}, DefinitionDigest: [32]byte{3}, ExpectationDigest: [32]byte{4}, AccountingRule: ArgumentObservationAccountingRule(), SessionID: "11111111-1111-4111-8111-111111111111", Fence: "22222222-2222-4222-8222-222222222222", CaptureID: "capture", ActionID: "action", PodUID: "pod", NodeUID: "node", BootID: "boot", CollectorPodUID: "collector", CollectorEpoch: "process"}, StartedAt: now, StartBy: now.Add(10 * time.Second), SessionUntil: now.Add(70 * time.Second), LeaseUntil: now.Add(70 * time.Second), Duration: time.Minute, Sequence: 1, EventCredit: 1000, ByteCredit: 512000, EventsPerSecond: 100, BytesPerSecond: 51200, MaxProbeBytes: 512, MaxBytesPerEvent: 128, MaxTrackedThreads: 4096}
	if !p.ValidFinite(now) || p.ValidFinite(p.StartBy) || p.EffectiveEventsPerSecond() != 100 {
		t.Fatal("valid original argument permit or finite cutoff")
	}
	p.BytesPerSecond = 1024
	if p.EffectiveEventsPerSecond() != 2 {
		t.Fatal("byte rate did not constrain probe rate")
	}
	for _, mode := range []string{"packet rule", "definition", "program", "events", "bytes", "event rate", "byte rate", "probe", "memory width", "thread cap", "sequence", "lease", "start", "duration", "future"} {
		t.Run(mode, func(t *testing.T) {
			q, at := p, now
			switch mode {
			case "packet rule":
				q.Binding.AccountingRule = ObservationAccountingRule()
			case "definition":
				q.Binding.DefinitionDigest = [32]byte{}
			case "program":
				q.Binding.ProgramDigest = [32]byte{}
			case "events":
				q.EventCredit = 0
			case "bytes":
				q.ByteCredit = 0
			case "event rate":
				q.EventsPerSecond = 100001
			case "byte rate":
				q.BytesPerSecond = 511
			case "probe":
				q.MaxProbeBytes = 128
			case "memory width":
				q.MaxBytesPerEvent = 127
			case "thread cap":
				q.MaxTrackedThreads = 16385
			case "sequence":
				q.Sequence = 2
			case "lease":
				q.LeaseUntil = q.LeaseUntil.Add(time.Second)
			case "start":
				q.StartBy = q.StartBy.Add(time.Nanosecond)
			case "duration":
				q.Duration = time.Minute + time.Second
			case "future":
				at = now.Add(-time.Nanosecond)
			}
			if q.ValidFinite(at) {
				t.Fatal("invalid argument permit admitted")
			}
		})
	}
}
