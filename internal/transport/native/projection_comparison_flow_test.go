package native_test

import (
	"context"
	"encoding/json"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	native "asservat.local/asservat/internal/transport/native"
)

func pairedProtocolFixture(t *testing.T) projectionProtocolFixture {
	f := newProjectionProtocolFixture(t)
	e := &f.source.Expectation
	e.NativeType, e.DataClass, e.ActionID = artifact.PprofArtifact, "raw", "a0123456789abcdef01234567"
	e.Profile = &artifact.GoProfileAcquisition{SourceRef: "go", EndpointDigest: artifact.Digest{1}, Type: "heap", Mode: "snapshot"}
	e.Registration.NativeLimit = artifact.MaxPprofBytes
	s := &f.scope
	s.NativeType, s.SourceFormat, s.DisplayVersion, s.SourceProjectionDigest = artifact.PprofArtifact, artifact.PprofFormat, query.ProfileComparisonDisplayVersion, artifact.Digest{}
	s.Selection, s.Profile = query.LineSelection{}, query.ProfileSummarySelection{SampleType: "alloc_space", TopN: 20}
	s.Comparison = query.ProfileComparisonWindow{Normalization: query.ProfileComparisonRaw, Baseline: query.ProfileComparisonBaseline{CaseID: s.CaseID, ArtifactID: s.ArtifactID, CaptureID: s.CaptureID, ClusterID: s.ClusterID, NamespaceUID: s.NamespaceUID, WorkloadUID: s.WorkloadUID, PodUID: s.PodUID, Version: s.Version}}
	f.lease.Operation.Processing.CaptureID = s.CaptureID
	f.lease.Operation.Baseline = value.NativeProjectionSource{SourceVersion: s.Version, Path: f.lease.Operation.Path, Processing: f.lease.Operation.Processing}
	if !f.source.Valid(s.Version) || !s.Valid() || !evidence.NativeComparisonSourcesMatch([2]evidence.NativeContextSource{f.source, f.source}, *s, f.lease.Operation) {
		t.Fatal("invalid pair fixture", e.Validate(), s.Valid(), f.source.Valid(s.Version))
	}
	return f
}

type comparisonProtocolReader struct {
	f        projectionProtocolFixture
	calls    atomic.Int32
	complete bool
}

func (r *comparisonProtocolReader) ReadApprovedContext(context.Context, evidence.NativeContextSource, value.NativeOperation, query.ContextProjectionScope, time.Time) (query.ProjectionResult, error) {
	return query.ProjectionResult{}, query.ErrUnavailable
}
func (r *comparisonProtocolReader) ReadApprovedProfileComparison(ctx context.Context, sources [2]evidence.NativeContextSource, o value.NativeOperation, s query.ContextProjectionScope, until time.Time) (query.ProjectionResult, error) {
	r.calls.Add(1)
	if !reflect.DeepEqual(sources, [2]evidence.NativeContextSource{r.f.source, r.f.source}) || !o.Equal(r.f.lease.Operation) || s != r.f.scope || !until.Equal(o.Until) || ctx.Err() != nil {
		return query.ProjectionResult{}, query.ErrUnavailable
	}
	// Typed mismatch is a positive, content-free result; public outcome remains
	// separately audited. Objectstore tests establish the final-auth boundary.
	if r.complete {
		facts := query.ProfileComparisonFacts{ProfileComparisonAcquisition: query.ProfileComparisonAcquisition{ProfileType: "heap", Mode: "snapshot"}, SymbolStatus: "missing"}
		return query.ProjectionResult{Comparison: &query.ProfileComparison{SampleType: s.Profile.SampleType, Unit: "bytes", Normalization: query.ProfileComparisonRaw, Aggregation: "cumulative", Comparable: true, Baseline: facts, Incident: facts, BuildStatus: "unknown", SamplingStatus: "unknown", AcquisitionStatus: "same", Rows: []query.ProfileComparisonRow{}, Limitations: []string{}}}, nil
	}
	return query.ProjectionResult{IncompatibleProfiles: true}, nil
}

func TestNativeComparisonCommandAndTypedRefusalJoinExistingProtocol(t *testing.T) {
	for _, complete := range []bool{false, true} {
		name := "mismatch"
		if complete {
			name = "complete"
		}
		t.Run(name, func(t *testing.T) { runComparisonProtocol(t, complete) })
	}
}

func runComparisonProtocol(t *testing.T, complete bool) {
	f := pairedProtocolFixture(t)
	reader := &comparisonProtocolReader{f: f, complete: complete}
	result, err := evidence.NewRegionalApprovedResult(f.ctx, f.target, reader, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { result.Close(); _ = result.Wait(context.Background()) })
	gate, err := evidence.NewNativeFrameGate(f.ctx, func(context.Context) (value.NativeLease, error) { return f.lease, nil }, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { gate.Close(); _ = gate.Wait(context.Background()) })
	opwire, _ := json.Marshal(f.lease.Operation)
	sourcewire, _ := json.Marshal(f.source)
	scopewire, _ := json.Marshal(f.scope)
	r := f.lease.Operation.Reference
	reference := contracts.NativeReference{InstallationID: r.InstallationID, QueryID: r.QueryID, WorkerID: r.WorkerID, OperationID: r.OperationID, Fence: r.Fence}
	command := contracts.NativeCommand{Format: contracts.NativeExchangeFormat, Reference: reference, Kind: string(value.NativeProjection), Source: sourcewire, BaselineSource: sourcewire, Operation: opwire, Projection: scopewire, ParentID: f.lease.Operation.ParentID, Generation: 1, LeaseSequence: 1, Until: f.lease.Until.Format(time.RFC3339Nano)}
	var completed atomic.Int32
	op, err := native.NewHubOperation(gate, command, f.source, func(_ context.Context, l value.NativeLease) error {
		completed.Add(1)
		if !l.Operation.Equal(f.lease.Operation) {
			return contracts.ErrNativeProtocol
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	client := flowServer(t, contracts.NativeWorkerPath, projectionProtocolAdmission{op, f.hello, reference})
	t.Cleanup(func() { _ = op.Close() })
	stream, err := client.Open(f.ctx, f.hello)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan projectionProtocolOutcome, 1)
	go func() {
		defer stream.Close()
		state, err := native.RunWorkerConversation(f.ctx, stream, f.hello, f.target, f.lease.Operation.WorkerPublicKey, result)
		done <- projectionProtocolOutcome{state, err}
	}()
	got, err := op.Projection(f.ctx)
	if err != nil || !got.Valid(f.scope) || got.IncompatibleProfiles == complete || (got.Comparison != nil) != complete {
		t.Fatal("typed comparison result", got, err)
	}
	if err := op.AcknowledgeProjection(f.ctx); err != nil {
		t.Fatal("acknowledge", err)
	}
	out := projectionProtocolReceive(t, f.ctx, done)
	if out.err != nil || out.state.State != contracts.NativeJoined || reader.calls.Load() != 1 || completed.Load() != 1 {
		t.Fatal("paired protocol failed positive join", out, reader.calls.Load(), completed.Load())
	}
}
