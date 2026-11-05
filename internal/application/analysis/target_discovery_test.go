package analysis

import (
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"testing"
	"time"
)

type discoveryFixture struct {
	*projectionFixture
	routeCalls int
}

func (f *discoveryFixture) ResolveTargetDiscoveryRoute(context.Context, string, identity.Identity, artifact.RecoveryProof) (value.ContextProjectionCandidate, error) {
	f.routeCalls++
	c := f.a.Scope.Candidate()
	c.Discovery = value.TargetDiscoveryWindow{}
	return c, nil
}
func TestTargetDiscoveryPendingKeepsOriginalSourceAndConfiguredBudget(t *testing.T) {
	f := newProjectionFixture(t)
	f.ready = false
	scope := &f.a.Scope
	scope.NativeType = artifact.ProcessesArtifact
	scope.SourceFormat = artifact.ProcessFormat
	scope.SourceProjectionDigest = artifact.Digest{}
	scope.DisplayVersion = value.TargetDiscoveryDisplayVersion
	scope.Selection = value.LineSelection{}
	scope.Discovery = value.TargetDiscoveryWindow{Section: "processes", Limit: 20}
	f.p.Profile.Worker.MemoryBytes = value.TargetDiscoveryWorkerBytes
	f.p.Profile.Worker.WorkerTransientBytes = value.TargetDiscoveryWorkerBytes
	route := &discoveryFixture{projectionFixture: f}
	f.s.DiscoveryRoutes = route
	reads, enabled := f.s.TargetDiscoveries()
	if !enabled {
		t.Fatal("missing source route")
	}
	request := value.TargetDiscoveryRequest{CaptureID: scope.CaptureID, Section: "processes", Limit: 20}
	inv := f.invocation("get_target_discovery")
	inv.input = ContextQueryInput{Discovery: request}
	d, err := reads.Begin(t.Context(), f, inv, request)
	if err != nil {
		t.Fatal(err)
	}
	inv.outcome = d
	if !d.Pending() || f.q.Scope.BeginTool() != "get_target_discovery" || f.q.Scope.QueryUnits() != 2 || f.q.Scope.ReadBatches() != 1 || f.starts != 1 || f.reads != 0 || f.q.Scope.Discovery != scope.Discovery || f.q.Grant != (value.ContextQueryGrant{}) {
		t.Fatal("configured metadata query contract changed")
	}
	original := f.q.Deadline
	if d.Association().Discovery != scope.Discovery || !d.QueryDeadline().Equal(original) {
		t.Fatal("selection/deadline not retained")
	}
	if err := d.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.polls != 0 || f.batches != 0 || f.reads != 0 {
		t.Fatal("pending response spent a native batch")
	}
	// The existing absolute query deadline remains unchanged after owner closure.
	f.refresh(f.now.Add(time.Second))
	if !f.q.Deadline.Equal(original) {
		t.Fatal("query deadline renewed")
	}
}

type discoveryReader struct {
	*projectionFixture
	wrongSource bool
}
type discoveryRead struct {
	*projectionReadFake
	page value.TargetDiscoveryPage
}

func (r *discoveryRead) Projection(context.Context) (value.ProjectionResult, error) {
	return value.ProjectionResult{TargetDiscovery: &r.page}, nil
}
func (f discoveryReader) ReadProjection(ctx context.Context, start value.ContextReadStart, owner ContextProjectionRequestOwner) (ContextProjectionRead, error) {
	_, err := f.projectionFixture.ReadProjection(ctx, start, owner)
	if err != nil {
		return nil, err
	}
	s := f.q.Scope
	page := value.TargetDiscoveryPage{CaptureID: s.CaptureID, ArtifactID: s.ArtifactID, PodUID: s.PodUID, Section: s.Discovery.Section, StopReason: "completed", CoveredPods: 1, Version: s.Version, StartedAt: f.now.Add(-time.Second), EndedAt: f.now, RetainedBytes: 100, InventoryComplete: true, Start: s.Discovery.Start, Total: 0, Processes: []value.TargetDiscoveryProcess{}, Gaps: []string{"socketOwnersUnsupported"}}
	if f.wrongSource {
		page.Version[0] ^= 1
	}
	return &discoveryRead{projectionReadFake: f.lastRead, page: page}, nil
}
func TestTargetDiscoveryReadyDeliveryOwnsPageAndRejectsWrongSource(t *testing.T) {
	for _, wrong := range []bool{false, true} {
		t.Run(map[bool]string{false: "current", true: "wrong-source"}[wrong], func(t *testing.T) {
			f := newProjectionFixture(t)
			s := &f.a.Scope
			s.NativeType = artifact.ProcessesArtifact
			s.SourceFormat = artifact.ProcessFormat
			s.SourceProjectionDigest = artifact.Digest{}
			s.DisplayVersion = value.TargetDiscoveryDisplayVersion
			s.Selection = value.LineSelection{}
			s.Discovery = value.TargetDiscoveryWindow{Section: "summary", Limit: 20}
			f.p.Profile.Worker.MemoryBytes = value.TargetDiscoveryWorkerBytes
			f.p.Profile.Worker.WorkerTransientBytes = value.TargetDiscoveryWorkerBytes
			f.s.DiscoveryRoutes = &discoveryFixture{projectionFixture: f}
			f.s.Results.Reader = discoveryReader{f, wrong}
			reads, _ := f.s.TargetDiscoveries()
			request := value.TargetDiscoveryRequest{CaptureID: s.CaptureID, Section: "summary", Limit: 20}
			inv := f.invocation("get_target_discovery")
			inv.input = ContextQueryInput{Discovery: request}
			d, err := reads.Begin(t.Context(), f, inv, request)
			if wrong {
				if err == nil && d != nil {
					if _, ok := d.TargetDiscovery(); ok {
						t.Fatal("wrong-source page escaped")
					}
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				inv.outcome = d
				p, ok := d.TargetDiscovery()
				if !ok || !p.InventoryComplete || p.CoveredPods != 1 {
					t.Fatal("saved source coverage lost")
				}
				p.Gaps[0] = "mutated"
				again, _ := d.TargetDiscovery()
				if again.Gaps[0] == "mutated" {
					t.Fatal("consumer changed prepared source")
				}
				if d.Close(context.Background()) != nil {
					t.Fatal("delivery close")
				}
			}
			if f.reads != 1 || f.batches != 1 || f.completions != 1 || f.lastRead == nil || !f.lastRead.closed {
				t.Fatal("paid source was not closed and joined", f.reads, f.batches, f.completions)
			}
		})
	}
}
