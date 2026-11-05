package presentation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

type discoveryBridgeRoutes struct{ *bridgeFixture }

func (f discoveryBridgeRoutes) ResolveTargetDiscoveryRoute(context.Context, string, identity.Identity, artifact.RecoveryProof) (value.ContextProjectionCandidate, error) {
	c := f.a.Scope.Candidate()
	c.Discovery = value.TargetDiscoveryWindow{}
	return c, nil
}

func discoveryBridgeFixture(t *testing.T) (*AuditedOperations, *bridgeFixture, *presentationAuditGate, []byte) {
	t.Helper()
	s, f, gate, target := bridgeAuditFixture(t)
	source, _ := value.LookupProjectionSource(artifact.ProcessesArtifact)
	f.a.Scope.NativeType, f.a.Scope.SourceFormat, f.a.Scope.DisplayVersion, f.a.Scope.SourceProjectionDigest = source.NativeType, source.Format, source.DisplayVersion, source.ProjectionDigest
	f.a.Scope.Selection = value.LineSelection{}
	f.a.Scope.Discovery = value.TargetDiscoveryWindow{Section: "processes", Limit: 20}
	f.p.Profile.Worker.MemoryBytes = value.TargetDiscoveryWorkerBytes
	f.p.Profile.Worker.WorkerTransientBytes = value.TargetDiscoveryWorkerBytes
	f.s.DiscoveryRoutes = discoveryBridgeRoutes{f}
	reads, _ := f.s.TargetDiscoveries()
	adapter, err := NewContextProjectionOperations(f.s, f.s.Results)
	if err == nil {
		target.adapter, err = adapter.WithTargetDiscovery(reads)
	}
	if err != nil {
		t.Fatal(err)
	}
	input, _ := json.Marshal(TargetDiscoveryOperationInput{CaptureID: f.a.Scope.CaptureID, Section: "processes"})
	return s, f, gate, input
}

func discoveryTestPage(n int) value.TargetDiscoveryPage {
	now := time.Now().UTC().Truncate(time.Microsecond)
	p := value.TargetDiscoveryPage{CaptureID: bridgeID, ArtifactID: bridgeID, PodUID: "pod", Section: "processes", StopReason: "completed", CoveredPods: 1, Version: artifact.Digest{2}, StartedAt: now.Add(-time.Second), EndedAt: now, RetainedBytes: 1048576, InventoryComplete: true, Total: 100, Processes: []value.TargetDiscoveryProcess{}, Gaps: []string{"socketOwnersUnsupported"}}
	for i := range n {
		p.Processes = append(p.Processes, value.TargetDiscoveryProcess{ProcessRef: fmt.Sprintf("%064x", i+1), PodUID: p.PodUID, DisplayPID: uint32(i + 1), ExecutablePath: "/" + strings.Repeat("<", 96), ObservedAt: now})
	}
	return p
}

func TestTargetDiscoveryActualAuditedPendingAndRead(t *testing.T) {
	s, f, gate, input := discoveryBridgeFixture(t)
	f.ready = false
	first, err := s.Call(t.Context(), f, "get_target_discovery", input)
	if err != nil {
		t.Fatalf("actual discovery Begin: %v; admissions=%d starts=%d reads=%d outcomes=%d", err, f.admissions, f.starts, f.reads, len(gate.outcomes))
	}
	if first.Close(t.Context()) != nil || f.admissions != 1 || f.starts != 1 || f.reads != 0 || f.q.Scope.QueryUnits() != 2 || f.q.Scope.ReadBatches() != 1 || len(gate.outcomes) != 1 {
		t.Fatal("pending lost original accounting")
	}
	f.ready = true
	p := discoveryTestPage(1)
	p.StartedAt, p.EndedAt, p.Processes[0].ObservedAt = f.now.Add(-time.Second), f.now, f.now
	f.result = &value.ProjectionResult{TargetDiscovery: &p}
	reply, err := s.Call(t.Context(), f, "get_query_result", bridgePoll(f.q.ID))
	if err != nil {
		t.Fatal("actual discovery poll", err)
	}
	if s.contracts.ValidateOutput("get_query_result", reply.Body) != nil || f.reads != 1 || len(gate.outcomes) != 2 {
		t.Fatal("invalid paid discovery delivery", string(reply.Body))
	}
	if err := reply.Close(t.Context()); err != nil || f.active || f.completions != 1 {
		t.Fatal("discovery did not join", err)
	}
}

func TestTargetDiscoveryEscapedWholeRowsStayWithinDirectAndNestedLimits(t *testing.T) {
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	p := discoveryTestPage(20)
	if !p.Valid(value.TargetDiscoveryWindow{Section: "processes", Limit: 20}) {
		t.Fatal("test page is not a legal upstream result", p.EncodedSize())
	}
	times := queryViewTimes{ObservedAt: p.EndedAt.Add(time.Millisecond), ExpiresAt: p.EndedAt.Add(30 * time.Second)}
	for _, name := range []string{"get_target_discovery", "get_query_result"} {
		body, err := renderTargetDiscoveryPage(bridgeID, name, bridgeID, p, times)
		if err != nil || len(body) > contracts.InvestigationOutputLimit || wire.ValidateOutput(name, body) != nil {
			t.Fatal("bounded discovery output", name, err, len(body), wire.OutputViolation(name, body))
		}
		var outer struct {
			Data      json.RawMessage `json:"data"`
			Next      *string         `json:"next_cursor"`
			Truncated bool            `json:"truncated"`
		}
		if json.Unmarshal(body, &outer) != nil {
			t.Fatal("decode")
		}
		if name == "get_query_result" {
			if outer.Truncated || outer.Next != nil {
				t.Fatal("query wrapper carries page truncation")
			}
			var nested struct {
				Result json.RawMessage `json:"result"`
			}
			_ = json.Unmarshal(outer.Data, &nested)
			_ = json.Unmarshal(nested.Result, &outer)
		}
		var page targetDiscoveryOutput
		if json.Unmarshal(outer.Data, &page) != nil || page.Processes == nil || len(*page.Processes) == 0 || len(*page.Processes) >= len(p.Processes) || !outer.Truncated || outer.Next == nil || *outer.Next != p.Next(len(*page.Processes)) {
			t.Fatal("trimmed prefix/cursor lost", name, string(body))
		}
		for _, r := range *page.Processes {
			if r.ExecutablePath != p.Processes[0].ExecutablePath || r.Runtime != "unknown" {
				t.Fatal("path altered or runtime guessed")
			}
		}
		if !page.Summary.Coverage.InventoryComplete {
			t.Fatal("page trimming altered full inventory coverage")
		}
	}
}

func TestTargetDiscoveryMalformedCursorHasNoQueryEffects(t *testing.T) {
	s, f, _, _ := discoveryBridgeFixture(t)
	input, _ := json.Marshal(TargetDiscoveryOperationInput{CaptureID: bridgeID, Section: "processes", Cursor: "01:bad"})
	reply, err := s.Call(t.Context(), f, "get_target_discovery", input)
	if err != nil {
		t.Fatal(err)
	}
	defer reply.Close(t.Context())
	if f.admissions+f.starts+f.reads != 0 || !strings.Contains(string(reply.Body), "InvalidCursor") {
		t.Fatal("bad cursor spent a query", string(reply.Body))
	}
}

func TestTargetDiscoveryOversizedRecordRefusalPreservesDownloadRemedy(t *testing.T) {
	p := discoveryTestPage(1)
	p.Processes[0].ExecutablePath = "/" + strings.Repeat("<", 4095)
	_, err := renderTargetDiscoveryPage(bridgeID, "get_query_result", bridgeID, p, queryViewTimes{ObservedAt: p.EndedAt, ExpiresAt: p.EndedAt.Add(time.Second)})
	if !errors.Is(err, value.ErrRecordTooLarge) {
		t.Fatal("oversized escaped record bypassed full wire bound", err)
	}
}
