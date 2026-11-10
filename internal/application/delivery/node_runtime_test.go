package delivery

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/collector"
)

func TestLiveRuntimeAggregatesCompleteRatesAndMarksThemUnavailable(t *testing.T) {
	ch, _, clock, _ := newChannel(t)
	peer, _ := enroll(t, ch, epochA)
	const cluster = "00000000-0000-4000-8000-000000000001"
	first := report(1, clock.now())
	first.Live = &collector.LiveStatus{WindowStartedAt: first.ObservedAt, Cohorts: 2, ScanEvents: 10, ScanBytes: 100, ScanCPUNanos: 1000, DeliveredRows: 4, DeliveredBytes: 40, LostEvents: 2, DroppedRows: 1, PendingRows: 2}
	if err := ch.Report(peer, epochA, first); err != nil {
		t.Fatal(err)
	}
	initial := ch.LiveRuntime(cluster)
	if !initial.Valid(clock.now()) || initial.Nodes != 1 || initial.RatesUnavailable != 1 || initial.RatesComplete || initial.Live.ScanEvents != 10 || !initial.Rates.Zero() {
		t.Fatal("first report invented a complete rate", initial)
	}
	clock.add(2 * time.Second)
	second := report(2, clock.now())
	second.Live = &collector.LiveStatus{WindowStartedAt: second.ObservedAt, Cohorts: 2, ScanEvents: 15, ScanBytes: 200, ScanCPUNanos: 3000, DeliveredRows: 8, DeliveredBytes: 80, RefusedAdmissions: 2, LostEvents: 6, DroppedRows: 3, PendingRows: 1}
	if err := ch.Report(peer, epochA, second); err != nil {
		t.Fatal(err)
	}
	got := ch.LiveRuntime(cluster)
	rates := collector.LiveActivityRates{ScanEventsPerSecond: 2.5, ScanBytesPerSecond: 50, ScanCPUNanosPerSecond: 1000, DeliveredRowsPerSecond: 2, DeliveredBytesPerSecond: 20, RefusedAdmissionsPerSecond: 1, LostEventsPerSecond: 2, DroppedRowsPerSecond: 1}
	if !got.Valid(clock.now()) || got.Nodes != 1 || got.RatesUnavailable != 0 || !got.RatesComplete || *got.Live != second.Live.Activity() || got.Rates != rates {
		t.Fatal("wrong live aggregate or report rates", got)
	}
	clock.add(2 * time.Second)
	third := report(3, clock.now())
	third.Live = &collector.LiveStatus{WindowStartedAt: third.ObservedAt, ScanEvents: 0, ScanBytes: 200, ScanCPUNanos: 3000, DeliveredRows: 8, DeliveredBytes: 80, RefusedAdmissions: 2}
	if err := ch.Report(peer, epochA, third); err != nil {
		t.Fatal(err)
	}
	if got := ch.LiveRuntime(cluster); got.RatesUnavailable != 1 || got.RatesComplete || !got.Rates.Zero() {
		t.Fatal("counter rollback retained a rate", got)
	}
	clock.add(2 * time.Second)
	fourth := report(4, clock.now())
	if err := ch.Report(peer, epochA, fourth); err != nil {
		t.Fatal(err)
	}
	if got := ch.LiveRuntime(cluster); !got.Valid(clock.now()) || got.Nodes != 0 || got.Live != nil || !got.RatesComplete {
		t.Fatal("disabled live runtime remained visible", got)
	}
}

func TestLiveRuntimeSumsCurrentNodesAndSkipsStaleReports(t *testing.T) {
	now := time.Now().UTC()
	ch := &NodeChannel{now: func() time.Time { return now }, nodes: map[string]*nodeEntry{
		"a":     {reportedAt: now, report: &collector.Report{Live: &collector.LiveStatus{Cohorts: 1, ScanEvents: 10}}, liveRates: &collector.LiveActivityRates{ScanEventsPerSecond: 1}},
		"b":     {reportedAt: now, report: &collector.Report{Live: &collector.LiveStatus{Cohorts: 2, ScanEvents: 20}}, liveRates: &collector.LiveActivityRates{ScanEventsPerSecond: 2}},
		"stale": {reportedAt: now.Add(-collector.StatusStaleAfter - time.Second), report: &collector.Report{Live: &collector.LiveStatus{Cohorts: 4, ScanEvents: 40}}, liveRates: &collector.LiveActivityRates{ScanEventsPerSecond: 4}},
	}}
	got := ch.LiveRuntime("00000000-0000-4000-8000-000000000001")
	if !got.Valid(now) || got.Nodes != 2 || got.Live.Cohorts != 3 || got.Live.ScanEvents != 30 || got.Rates.ScanEventsPerSecond != 3 {
		t.Fatal("current node aggregates are wrong", got)
	}
}
