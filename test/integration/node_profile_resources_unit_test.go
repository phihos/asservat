package integration

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/collector"
)

func TestProfileResourceStopRequiresExactReceiptsAndPreExpiryJoin(t *testing.T) {
	stopped := time.Now().UTC()
	until := stopped.Add(10 * time.Second)
	work := []collector.Work{{ID: "first", Sequence: 4}, {ID: "second", Sequence: 5}}
	ack := []collector.Receipt{{WorkID: "first", Sequence: 4, Outcome: collector.OutcomeAccepted}, {WorkID: "second", Sequence: 5, Outcome: collector.OutcomeAccepted}}
	for _, tc := range []struct {
		name           string
		observed       time.Time
		receipts       []collector.Receipt
		held           int64
		joined, failed bool
	}{
		{"enqueue alone", stopped.Add(time.Second), nil, 0, false, false},
		{"wrong sequence", stopped.Add(time.Second), []collector.Receipt{{WorkID: "first", Sequence: 3, Outcome: collector.OutcomeAccepted}, ack[1]}, 0, false, false},
		{"still held", stopped.Add(time.Second), ack, 256 << 20, false, false},
		{"old snapshot", stopped, ack, 0, false, false},
		{"deadline cleanup", until, ack, 0, false, true},
		{"after expiry", until.Add(time.Nanosecond), ack, 0, false, true},
		{"refused stop", stopped.Add(time.Second), []collector.Receipt{{WorkID: "first", Sequence: 4, Outcome: collector.OutcomeRefused, Reason: collector.ReasonCaptureFailed}, ack[1]}, 0, false, true},
		{"joined before expiry", until.Add(-time.Nanosecond), ack, 0, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := collector.Report{ObservedAt: tc.observed, Receipts: tc.receipts, Budget: collector.Usage{FrozenReserved: tc.held}}
			joined, err := profileResourceStopJoined(r, stopped, until, work, map[string]bool{})
			if joined != tc.joined || (err != nil) != tc.failed {
				t.Fatal("incorrect Stop qualification", joined, err)
			}
		})
	}
	accepted := map[string]bool{}
	first := collector.Report{ObservedAt: stopped.Add(time.Second), Receipts: ack[:1], Budget: collector.Usage{FrozenReserved: 128 << 20}}
	if joined, err := profileResourceStopJoined(first, stopped, until, work, accepted); joined || err != nil {
		t.Fatal(joined, err)
	}
	second := collector.Report{ObservedAt: stopped.Add(2 * time.Second), Receipts: ack[1:]}
	if joined, err := profileResourceStopJoined(second, stopped, until, work, accepted); !joined || err != nil {
		t.Fatal("separate exact receipts lost", joined, err)
	}
}
