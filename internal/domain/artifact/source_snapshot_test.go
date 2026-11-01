package artifact

import (
	"testing"
	"time"
)

func snapshotProjectionFixture() (ContextExpectation, SourceSnapshotCoverage, Digest) {
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	l := validLifecycle(now)
	l.After = 0
	l.HistoryCoverage = "unknown"
	l.WindowCoverage = "unknown"
	l.GapReasons = []string{"unknownLoss"}
	request := SourceSnapshotRequest{SourceBindingDigest: Digest{1}, SourceID: l.SourceSessionID, Fence: l.SnapshotID, SnapshotID: l.SnapshotID, SourceStartedAt: l.SourceStartedAt, SourceHardUntil: now.Add(time.Hour), T0: now, IssuedAt: now, StartBy: now.Add(time.Second), ProcessingUntil: now.Add(time.Minute), Before: l.RequestedBefore, MaxBytes: 65536}
	e := ContextExpectation{Snapshot: &request, Lifecycle: &l, TriggeredAt: now}
	d := Digest{5}
	o := SourceSnapshotCoverage{Request: request, AcceptedExpectationDigest: d, NativeBytes: 4096, Retained: 1, AvailableFrom: l.SourceStartedAt, CompletedAt: now}
	return e, o, d
}
func TestSourceSnapshotOutcomeNeverBackfillsUnknownQuietHistory(t *testing.T) {
	e, o, d := snapshotProjectionFixture()
	final, err := ProjectSourceSnapshotCoverage(e, d, o)
	if err != nil || final.Lifecycle.HistoryCoverage != "partial" || final.Lifecycle.WindowCoverage != "partial" || e.Lifecycle.HistoryCoverage != "unknown" {
		t.Fatal("did not preserve immutable admission", final.Lifecycle, err)
	}
	o.Retained = 0
	if _, err = ProjectSourceSnapshotCoverage(e, d, o); err == nil {
		t.Fatal("fabricated wholly absent empty evidence")
	}
	o.HistoryComplete = true
	o.WindowComplete = true
	o.ObservedUntil = e.TriggeredAt
	final, err = ProjectSourceSnapshotCoverage(e, d, o)
	if err != nil || final.Lifecycle.WindowCoverage != "full" {
		t.Fatal("explicit complete quiet proof refused", final.Lifecycle, err)
	}
}
func TestSourceSnapshotOutcomeRefusesUnboundCoverageAndWindowChanges(t *testing.T) {
	for name, change := range map[string]func(*ContextExpectation, *SourceSnapshotCoverage){
		"new anchor":      func(e *ContextExpectation, o *SourceSnapshotCoverage) { o.Request.T0 = o.Request.T0.Add(time.Second) },
		"new fence":       func(e *ContextExpectation, o *SourceSnapshotCoverage) { o.Request.Fence = o.Request.SourceID },
		"wrong admission": func(e *ContextExpectation, o *SourceSnapshotCoverage) { o.AcceptedExpectationDigest = Digest{6} },
		"forged source": func(e *ContextExpectation, o *SourceSnapshotCoverage) {
			e.Lifecycle.SourceSessionID = e.Lifecycle.SnapshotID
		},
		"unproved full history": func(e *ContextExpectation, o *SourceSnapshotCoverage) { o.HistoryComplete = true },
		"full beyond early stop": func(e *ContextExpectation, o *SourceSnapshotCoverage) {
			o.HistoryComplete = true
			o.WindowComplete = true
			o.ObservedUntil = e.TriggeredAt
			o.SourceStoppedAt = e.TriggeredAt.Add(-time.Second)
		},
		"unknown loss claimed full": func(e *ContextExpectation, o *SourceSnapshotCoverage) {
			o.HistoryComplete = true
			o.ObservedUntil = e.TriggeredAt
			o.InputUnknown = true
		},
		"past processing": func(e *ContextExpectation, o *SourceSnapshotCoverage) { o.CompletedAt = o.Request.ProcessingUntil },
		"over output":     func(e *ContextExpectation, o *SourceSnapshotCoverage) { o.NativeBytes = o.Request.MaxBytes + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			e, o, d := snapshotProjectionFixture()
			change(&e, &o)
			if _, err := ProjectSourceSnapshotCoverage(e, d, o); err == nil {
				t.Fatal("accepted forged completion")
			}
		})
	}
}
func TestSourceSnapshotDelayedIncidentKeepsOriginalAnchor(t *testing.T) {
	e, _, _ := snapshotProjectionFixture()
	r := *e.Snapshot
	r.T0 = r.T0.Add(-20 * time.Second)
	if !r.Valid() {
		t.Fatal("delayed event incorrectly requires dispatch five seconds after anchor")
	}
	if !SourceSnapshotAnchor(r).Equal(r.T0.Add(-r.Before)) {
		t.Fatal("retention moved to save time")
	}
}

func TestSourceSnapshotAdmittedNonemptyUnknownInputRemainsPartial(t *testing.T) {
	e, o, d := snapshotProjectionFixture()
	o.InputUnknown = true
	final, err := ProjectSourceSnapshotCoverage(e, d, o)
	if err != nil || final.Lifecycle.WindowCoverage != "partial" || final.Lifecycle.HistoryCoverage != "partial" {
		t.Fatal("lost already admitted nonempty partial evidence", final.Lifecycle, err)
	}
	found := false
	for _, reason := range final.Lifecycle.GapReasons {
		if reason == "unknownLoss" {
			found = true
		}
	}
	if !found || e.Lifecycle.WindowCoverage != "unknown" {
		t.Fatal("lost unknown gap or changed immutable acceptance", final.Lifecycle)
	}
}

func TestSourceSnapshotOutcomeMatchesOriginalClockInstants(t *testing.T) {
	e, o, d := snapshotProjectionFixture()
	zone := time.FixedZone("SQL receiver", 2*60*60)
	o.Request.SourceStartedAt = o.Request.SourceStartedAt.In(zone)
	o.Request.SourceHardUntil = o.Request.SourceHardUntil.In(zone)
	o.Request.T0 = o.Request.T0.In(zone)
	o.Request.IssuedAt = o.Request.IssuedAt.In(zone)
	o.Request.StartBy = o.Request.StartBy.In(zone)
	o.Request.ProcessingUntil = o.Request.ProcessingUntil.In(zone)
	if _, err := ProjectSourceSnapshotCoverage(e, d, o); err != nil {
		t.Fatal("same immutable instants rejected after SQL/wire normalization", err)
	}
}

func TestSourceSnapshotKnownCloseKeepsObservationAndProcessingTimesSeparate(t *testing.T) {
	e, o, d := snapshotProjectionFixture()
	o.SourceClosedAt = o.Request.T0.Add(-time.Second)
	final, err := ProjectSourceSnapshotCoverage(e, d, o)
	if err != nil {
		t.Fatal(err)
	}
	from, until := SourceSnapshotAcquisition(o)
	if !from.Equal(SourceSnapshotAnchor(o.Request)) || !until.Equal(o.SourceClosedAt) || !final.Lifecycle.SourceClosedAt.Equal(o.SourceClosedAt) || !final.Lifecycle.SourceStoppedAt.IsZero() || !o.CompletedAt.Equal(o.Request.T0) {
		t.Fatal("changed original observation or processing times", final, from, until)
	}
	for _, g := range final.Lifecycle.GapReasons {
		if g == "targetGone" {
			t.Fatal("mislabelled authority closure as target gone")
		}
	}
}

func TestSourceSnapshotAcquisitionCannotExceedOriginalHardEnd(t *testing.T) {
	_, o, _ := snapshotProjectionFixture()
	o.Request.After = 20 * time.Second
	o.Request.SourceHardUntil = o.Request.T0.Add(10 * time.Second)
	o.SourceClosedAt = o.Request.T0.Add(15 * time.Second)
	_, end := SourceSnapshotAcquisition(o)
	if !end.Equal(o.Request.SourceHardUntil) {
		t.Fatal("extended observation beyond original source hard end", end)
	}
}

func TestSourceSnapshotEventTimesRetainNanosecondsWithinAuthorityMicrosecond(t *testing.T) {
	for _, natural := range []bool{false, true} {
		t.Run(map[bool]string{false: "close", true: "naturalStop"}[natural], func(t *testing.T) {
			e, o, d := snapshotProjectionFixture()
			e.Snapshot.After = time.Millisecond
			e.Lifecycle.After = time.Millisecond
			o.Request = *e.Snapshot
			event := o.Request.T0.Add(37 * time.Nanosecond)
			o.CompletedAt = o.Request.T0.Add(73 * time.Nanosecond)
			if natural {
				o.SourceStoppedAt = event
			} else {
				o.SourceClosedAt = event
			}
			final, err := ProjectSourceSnapshotCoverage(e, d, o)
			if err != nil {
				t.Fatal("rounded runtime event past actual completion", err)
			}
			_, end := SourceSnapshotAcquisition(o)
			if !end.Equal(event) || !o.CompletedAt.After(end) {
				t.Fatal("lost submicrosecond event", end, o.CompletedAt)
			}
			if natural && !final.Lifecycle.SourceStoppedAt.Equal(event) || !natural && !final.Lifecycle.SourceClosedAt.Equal(event) {
				t.Fatal("changed observed event precision")
			}
		})
	}
}

func TestSourceSnapshotKnownCloseRetainsUnknownLossAlongsideHistoryGaps(t *testing.T) {
	for _, gap := range []string{"historyEvicted", "warming"} {
		t.Run(gap, func(t *testing.T) {
			e, o, d := snapshotProjectionFixture()
			o.SourceClosedAt = o.Request.T0.Add(-time.Second)
			if gap == "historyEvicted" {
				o.HistoryEvicted = true
			} else {
				e.Snapshot.SourceStartedAt = e.TriggeredAt.Add(-time.Second * 2)
				e.Lifecycle.SourceStartedAt = e.Snapshot.SourceStartedAt
				o.Request = *e.Snapshot
				o.AvailableFrom = e.Snapshot.SourceStartedAt
			}
			final, err := ProjectSourceSnapshotCoverage(e, d, o)
			if err != nil {
				t.Fatal(err)
			}
			found := map[string]bool{}
			for _, g := range final.Lifecycle.GapReasons {
				found[g] = true
			}
			if !found[gap] || !found["unknownLoss"] || found["targetGone"] {
				t.Fatal("lost observation closure behind history gap", final.Lifecycle.GapReasons)
			}
		})
	}
}

func TestSnapshotDispatchStructuralMaximumRetainsIndependentHardEnds(t *testing.T) {
	e, _, _ := snapshotProjectionFixture()
	q := *e.Snapshot
	q.StartBy = q.IssuedAt.Add(15 * time.Second)
	if !q.Valid() {
		t.Fatal("bounded group dispatch structurally refused")
	}
	q.StartBy = q.StartBy.Add(time.Microsecond)
	if q.Valid() {
		t.Fatal("overlong structural interval accepted")
	}
	q.StartBy = q.IssuedAt.Add(15 * time.Second)
	q.SourceHardUntil = q.IssuedAt.Add(10 * time.Second)
	if q.Valid() {
		t.Fatal("structural maximum extended source hardend")
	}
}
