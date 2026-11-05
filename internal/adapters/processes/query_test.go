package processes

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

func TestTargetDiscoveryFullSourceBeforePagingAndBoundCursor(t *testing.T) {
	p, e, from, until := processNativeFixture()
	e.CaptureUID = "10000000-0000-4000-8000-000000000011"
	e.Registration.Location.ArtifactID = "10000000-0000-4000-8000-000000000012"
	for n := 1; n < 3; n++ {
		r := p.Processes[0]
		r.Main = false
		r.Identity.HostPID += uint32(n)
		r.NamespacePID += uint32(n)
		r.ParentPID = p.Processes[0].Identity.HostPID
		p.Processes = append(p.Processes, r)
	}
	raw, _ := json.Marshal(p)
	version := artifact.Digest{1}
	w := query.TargetDiscoveryWindow{Section: "processes", Limit: 1}
	read := func(body []byte, w query.TargetDiscoveryWindow) query.ProjectionResult {
		t.Helper()
		r, err := Query(context.Background(), bytes.NewReader(body), e, from, until, w, version)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	r := read(raw, w)
	page := r.TargetDiscovery
	if page == nil || len(page.Processes) != 1 || page.Processes[0].DisplayPID != 1 || !page.InventoryComplete || page.CoveredPods != 1 || page.Total != 3 {
		t.Fatalf("wrong page: %+v", page)
	}
	next := page.Next(1)
	w2, err := query.NormalizeTargetDiscoveryWindow(query.TargetDiscoveryRequest{CaptureID: e.CaptureUID, Section: "processes", Limit: 1, Cursor: next})
	if err != nil {
		t.Fatal(err)
	}
	second := read(raw, w2).TargetDiscovery
	if second == nil || second.Start != 1 || second.Processes[0].ParentRef != page.Processes[0].ProcessRef {
		t.Fatal("cursor or qualified main parent changed")
	}
	changed := e
	changed.CaptureUID = "10000000-0000-4000-8000-000000000013"
	foreign, err := Query(context.Background(), bytes.NewReader(raw), changed, from, until, w2, version)
	if err != nil || !foreign.InvalidCursor || foreign.TargetDiscovery != nil {
		t.Fatal("cursor crossed source", err)
	}
	// Even limit1 and a foreign cursor must authenticate the complete tail.
	tail := append(append([]byte{}, raw...), []byte(`{}`)...)
	for _, window := range []query.TargetDiscoveryWindow{w, w2} {
		if _, err := Query(context.Background(), bytes.NewReader(tail), e, from, until, window, version); err == nil {
			t.Fatal("malformed tail hidden by paging")
		}
	}
}

func TestTargetDiscoveryCoverageAndEscapedWholeRowRefusal(t *testing.T) {
	p, e, from, until := processNativeFixture()
	e.CaptureUID = "10000000-0000-4000-8000-000000000011"
	e.Registration.Location.ArtifactID = "10000000-0000-4000-8000-000000000012"
	p.Origins[0].Outcome = "unavailable"
	p.Origins[0].MainPID = 0
	p.Processes = []artifact.ProcessRecord{}
	p.Gaps = []string{"sourceUnavailable"}
	raw, _ := json.Marshal(p)
	r, err := Query(context.Background(), bytes.NewReader(raw), e, from, until, query.TargetDiscoveryWindow{Section: "summary", Limit: 20}, artifact.Digest{1})
	if err != nil || r.TargetDiscovery == nil || r.TargetDiscovery.CoveredPods != 0 || r.TargetDiscovery.InventoryComplete {
		t.Fatal("empty source fabricated coverage", err)
	}
	p, e, from, until = processNativeFixture()
	e.CaptureUID = "10000000-0000-4000-8000-000000000011"
	e.Registration.Location.ArtifactID = "10000000-0000-4000-8000-000000000012"
	p.Processes[0].ExecutablePath = "/" + strings.Repeat("<", 4095)
	raw, _ = json.Marshal(p)
	r, err = Query(context.Background(), bytes.NewReader(raw), e, from, until, query.TargetDiscoveryWindow{Section: "processes", Limit: 20}, artifact.Digest{1})
	if err != nil || !r.TooLarge || r.TargetDiscovery != nil {
		t.Fatal("oversized whole row was changed or leaked", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, err = Query(ctx, bytes.NewReader(raw), e, from, until, query.TargetDiscoveryWindow{Section: "processes", Limit: 20}, artifact.Digest{1})
	if err == nil || r.TargetDiscovery != nil {
		t.Fatal("canceled source returned content")
	}
}
