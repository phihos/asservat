package native_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	native "asservat.local/asservat/internal/transport/native"
)

// These tests run the actual hub/worker protocol over the existing real H2/mTLS
// fixture. The source reader, admission lookup and SQL completion are synthetic;
// they do not qualify production query authority, key unwrap or SQL fencing.
type projectionProtocolFixture struct {
	ctx        context.Context
	target     value.WorkerCredentialTarget
	source     evidence.NativeContextSource
	scope      query.ContextProjectionScope
	lease      value.NativeLease
	projection query.PodStatusProjection
	hello      contracts.NativeHello
}

func newProjectionProtocolFixture(t *testing.T) projectionProtocolFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	t.Cleanup(cancel)
	now := time.Now().UTC().Truncate(time.Microsecond)
	source := flowSourceValue(t)
	target := value.WorkerCredentialTarget{InstallationID: nativeID, QueryID: "22222222-2222-4222-8222-222222222222", WorkerID: nativeID, PodUID: nativeID, CreatedAt: now, RunUntil: now.Add(time.Minute)}
	scope := query.ContextProjectionScope{RootID: nativeID, CaseID: nativeID, ArtifactID: nativeID, CaptureID: nativeID, ClusterID: nativeID, NamespaceUID: nativeID, WorkloadUID: nativeID, PodUID: nativeID,
		Version: evidence.ContextCopiesDigest(source.Copies), SourceProjectionDigest: query.ContextSourceProjectionDigest(), SourceFormat: artifact.ContextFormat, DisplayVersion: query.ContextDisplayVersion,
		Selection: query.LineSelection{LineStart: 1, MaxLines: 200}, Principal: identity.Principal{Issuer: "https://id.invalid", Subject: "dev", ClientID: "browser", Kind: identity.Human}}
	op := syntheticProcessingPath(value.NativeOperation{Reference: value.NativeReference{InstallationID: nativeID, QueryID: target.QueryID, WorkerID: nativeID, OperationID: "33333333-3333-4333-8333-333333333333", Fence: 1}, Kind: value.NativeProjection,
		HubPodUID: nativeID, HubProcessEpoch: nativeID, WorkerPodUID: nativeID, WorkerPublicKey: artifact.Digest{1}, SourceVersion: scope.Version, ParentID: "44444444-4444-4444-8444-444444444444", Generation: 1, StartedAt: now, Until: now.Add(4 * time.Second)})
	op.Processing.Location = source.Expectation.Registration.Location
	op.Path.StoreID = source.Expectation.Registration.StoreID
	lease := value.NativeLease{Operation: op, Certificate: artifact.Digest{3}, Sequence: 1, ObservedAt: now, Until: op.Until}
	hello := workerHello()
	hello.Reference.SessionID, hello.Reference.QueryID = "", target.QueryID
	p := query.PodStatusProjection{Format: artifact.ContextFormat, NamespaceUID: nativeID, PodUID: nativeID, ResourceVersion: "17", ObservedAt: now, Phase: "Running", Ready: "True", Initialized: "True", Scheduled: "True", RuntimeInstances: 1, Running: 1}
	if !target.Valid() || !scope.Valid() || !lease.Valid(now) || !op.CurrentValid(now) || !p.Valid() {
		t.Fatal("invalid synthetic projection fixture")
	}
	return projectionProtocolFixture{ctx, target, source, scope, lease, p, hello}
}

type projectionProtocolReader struct {
	calls atomic.Int32
	read  func(context.Context, evidence.NativeContextSource, value.NativeOperation, query.ContextProjectionScope, time.Time) (query.PodStatusProjection, error)
}

func (r *projectionProtocolReader) ReadApprovedContext(ctx context.Context, source evidence.NativeContextSource, operation value.NativeOperation, scope query.ContextProjectionScope, until time.Time) (query.ProjectionResult, error) {
	r.calls.Add(1)
	p, err := r.read(ctx, source, operation, scope, until)
	if err != nil {
		return query.ProjectionResult{}, err
	}
	return query.ProjectionResult{PodStatus: p}, nil
}

func (f projectionProtocolFixture) result(t *testing.T, reader *projectionProtocolReader) *evidence.RegionalContextResult {
	t.Helper()
	r, err := evidence.NewRegionalApprovedResult(f.ctx, f.target, reader, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close(); _ = r.Wait(context.Background()) })
	return r
}

func (f projectionProtocolFixture) reader() *projectionProtocolReader {
	return &projectionProtocolReader{read: func(ctx context.Context, source evidence.NativeContextSource, op value.NativeOperation, scope query.ContextProjectionScope, until time.Time) (query.PodStatusProjection, error) {
		deadline, ok := ctx.Deadline()
		if ctx.Err() != nil || !ok || deadline.After(f.lease.Operation.Until) || !op.Equal(f.lease.Operation) || scope != f.scope || !reflect.DeepEqual(source, f.source) || !until.Equal(f.lease.Operation.Until) {
			return query.PodStatusProjection{}, errors.New("synthetic reader received changed original query")
		}
		return f.projection, nil
	}}
}

type projectionProtocolAdmission struct {
	operation *native.HubOperation
	hello     contracts.NativeHello
	reference contracts.NativeReference
}

func (a projectionProtocolAdmission) OpenNative(ctx context.Context, peer *tls.ConnectionState, h contracts.NativeHello) (native.Conversation, error) {
	if peer == nil || !peer.HandshakeComplete || len(peer.VerifiedChains) == 0 || h.Reference != a.hello.Reference || h.Nonce != a.hello.Nonce {
		return nil, contracts.ErrNativeProtocol
	}
	// This controlled lookup supplies the admitted operation; it is not a test
	// of the production token/SQL/native-owner routing implementation.
	h.Reference = a.reference
	return a.operation.Attach(ctx, h)
}

func (f projectionProtocolFixture) operation(t *testing.T, complete evidence.NativeCompletion) (*native.HubOperation, *mtls.NativeClient) {
	t.Helper()
	return f.operationChecked(t, complete, func(context.Context) (value.NativeLease, error) { return f.lease, nil })
}

func (f projectionProtocolFixture) operationChecked(t *testing.T, complete evidence.NativeCompletion, check evidence.NativeCurrentCheck) (*native.HubOperation, *mtls.NativeClient) {
	t.Helper()
	gate, err := evidence.NewNativeFrameGate(f.ctx, check, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { gate.Close(); _ = gate.Wait(context.Background()) })
	operation, _ := json.Marshal(f.lease.Operation)
	source, _ := json.Marshal(f.source)
	scope, _ := json.Marshal(f.scope)
	r := f.lease.Operation.Reference
	reference := contracts.NativeReference{InstallationID: r.InstallationID, QueryID: r.QueryID, WorkerID: r.WorkerID, OperationID: r.OperationID, Fence: r.Fence}
	command := contracts.NativeCommand{Format: contracts.NativeExchangeFormat, Reference: reference, Kind: string(value.NativeProjection), Source: source, Operation: operation, Projection: scope, ParentID: f.lease.Operation.ParentID, Generation: f.lease.Operation.Generation, LeaseSequence: 1, Until: f.lease.Until.Format(time.RFC3339Nano)}
	op, err := native.NewHubOperation(gate, command, f.source, complete)
	if err != nil {
		t.Fatal(err)
	}
	client := flowServer(t, contracts.NativeWorkerPath, projectionProtocolAdmission{op, f.hello, reference})
	// Close the operation before httptest waits for its HTTP handler.
	t.Cleanup(func() { _ = op.Close() })
	return op, client
}

type projectionProtocolOutcome struct {
	state contracts.NativeConversationResult
	err   error
}

// Inspect only this closed branch's frames. No native data frame, native hash,
// filename or download-session reference can accidentally pass this fixture.
type projectionProtocolStream struct {
	native.Stream
	f                     projectionProtocolFixture
	commands, projections atomic.Int32
}

func (s *projectionProtocolStream) Receive(ctx context.Context) (contracts.NativeFrame, error) {
	f, err := s.Stream.Receive(ctx)
	if err != nil {
		return f, err
	}
	r := s.f.lease.Operation.Reference
	expected := contracts.NativeReference{InstallationID: r.InstallationID, QueryID: r.QueryID, WorkerID: r.WorkerID, OperationID: r.OperationID, Fence: r.Fence}
	valid := false
	if f.Kind == contracts.NativeCommandFrame {
		c, e := contracts.DecodeNativeCommand(f.Payload)
		var scope query.ContextProjectionScope
		valid = e == nil && c.Reference == expected && c.Nonce == s.f.hello.Nonce && c.Kind == string(value.NativeProjection) && c.ParentID == s.f.lease.Operation.ParentID && c.Generation == s.f.lease.Operation.Generation && c.WindowID == "" && c.Offset == 0 && c.Length == 0 && c.Until == s.f.lease.Until.Format(time.RFC3339Nano) && json.Unmarshal(c.Projection, &scope) == nil && scope == s.f.scope
		s.commands.Add(1)
	} else if f.Kind == contracts.NativeAcknowledgeFrame || f.Kind == contracts.NativeDoneFrame {
		a, e := contracts.DecodeNativeAcknowledge(f.Payload)
		phase := "approved"
		if f.Kind == contracts.NativeDoneFrame {
			phase = "joined"
		}
		valid = e == nil && a.Reference == expected && a.Nonce == s.f.hello.Nonce && a.Bytes == 0 && a.Phase == phase
	}
	if !valid {
		clear(f.Payload)
		return contracts.NativeFrame{}, contracts.ErrNativeProtocol
	}
	return f, nil
}

func (s *projectionProtocolStream) Send(ctx context.Context, f contracts.NativeFrame) error {
	r := s.f.lease.Operation.Reference
	expected := contracts.NativeReference{InstallationID: r.InstallationID, QueryID: r.QueryID, WorkerID: r.WorkerID, OperationID: r.OperationID, Fence: r.Fence}
	valid := false
	if f.Kind == contracts.NativeMetadataFrame {
		m, err := contracts.DecodeNativeMetadata(f.Payload)
		encoded, _ := json.Marshal(s.f.projection)
		valid = err == nil && m.Reference == expected && m.Nonce == s.f.hello.Nonce && string(m.Metadata) == string(encoded)
		s.projections.Add(1)
	} else if f.Kind == contracts.NativeDoneFrame {
		a, err := contracts.DecodeNativeAcknowledge(f.Payload)
		valid = err == nil && a.Reference == expected && a.Nonce == s.f.hello.Nonce && a.Bytes == 0 && a.Phase == "closed"
	}
	if !valid {
		return contracts.ErrNativeProtocol
	}
	return s.Stream.Send(ctx, f)
}

func (f projectionProtocolFixture) run(t *testing.T, client *mtls.NativeClient, result *evidence.RegionalContextResult, target value.WorkerCredentialTarget, key artifact.Digest) (<-chan projectionProtocolOutcome, *projectionProtocolStream) {
	t.Helper()
	s, err := client.Open(f.ctx, f.hello)
	if err != nil {
		t.Fatal(err)
	}
	stream := &projectionProtocolStream{Stream: s, f: f}
	done := make(chan projectionProtocolOutcome, 1)
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		defer s.Close()
		state, err := native.RunWorkerConversation(f.ctx, stream, f.hello, target, key, result)
		done <- projectionProtocolOutcome{state, err}
	}()
	t.Cleanup(func() {
		_ = s.Close()
		select {
		case <-joined:
		case <-f.ctx.Done():
			t.Error("projection worker did not join")
		}
	})
	return done, stream
}

func projectionProtocolReceive(t *testing.T, ctx context.Context, done <-chan projectionProtocolOutcome) projectionProtocolOutcome {
	t.Helper()
	select {
	case out := <-done:
		return out
	case <-ctx.Done():
		t.Fatal("projection worker did not return", ctx.Err())
		return projectionProtocolOutcome{}
	}
}

func TestNativeApprovedProjectionJoinsExactQueryWithoutNativeData(t *testing.T) {
	f := newProjectionProtocolFixture(t)
	reader := f.reader()
	result := f.result(t, reader)
	entered, release := make(chan struct{}), make(chan struct{})
	var completed atomic.Int32
	op, client := f.operation(t, func(ctx context.Context, lease value.NativeLease) error {
		completed.Add(1)
		if !lease.Operation.Equal(f.lease.Operation) {
			return contracts.ErrNativeProtocol
		}
		close(entered)
		select {
		case <-release:
			return ctx.Err()
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	done, stream := f.run(t, client, result, f.target, artifact.Digest{1})
	p, err := op.Projection(f.ctx)
	if err != nil || !reflect.DeepEqual(p.PodStatus, f.projection) {
		t.Fatal("approved DTO changed", err)
	}
	ack := make(chan error, 1)
	go func() { ack <- op.AcknowledgeProjection(f.ctx) }()
	select {
	case <-entered:
	case <-f.ctx.Done():
		t.Fatal("worker close did not reach exact completion")
	}
	select {
	case out := <-done:
		t.Fatal("worker joined before completion acknowledgement", out)
	default:
	}
	select {
	case err := <-ack:
		t.Fatal("hub returned before completion acknowledgement", err)
	default:
	}
	close(release)
	if err := <-ack; err != nil {
		t.Fatal(err)
	}
	out := projectionProtocolReceive(t, f.ctx, done)
	if out.err != nil || out.state.State != contracts.NativeJoined || out.state.Reference.QueryID != f.target.QueryID || out.state.Reference.SessionID != "" || out.state.Reference.OperationID != f.lease.Operation.Reference.OperationID || out.state.Reference.Fence != 1 || reader.calls.Load() != 1 || completed.Load() != 1 || stream.commands.Load() != 1 || stream.projections.Load() != 1 {
		t.Fatal("query exchange did not join exactly once", out, reader.calls.Load(), completed.Load())
	}
	if _, err := op.Projection(f.ctx); err == nil {
		t.Fatal("approved DTO handed to a second consumer")
	}
}

func TestNativeApprovedProjectionCancellationJoinsRead(t *testing.T) {
	f := newProjectionProtocolFixture(t)
	entered, joined := make(chan struct{}), make(chan struct{})
	reader := &projectionProtocolReader{read: func(ctx context.Context, _ evidence.NativeContextSource, _ value.NativeOperation, _ query.ContextProjectionScope, _ time.Time) (query.PodStatusProjection, error) {
		close(entered)
		<-ctx.Done()
		close(joined)
		return query.PodStatusProjection{}, ctx.Err()
	}}
	result := f.result(t, reader)
	var completed atomic.Int32
	op, client := f.operation(t, func(context.Context, value.NativeLease) error { completed.Add(1); return nil })
	done, stream := f.run(t, client, result, f.target, artifact.Digest{1})
	select {
	case <-entered:
	case <-f.ctx.Done():
		t.Fatal("approved reader never entered")
	}
	if err := op.Close(); err != nil {
		t.Fatal(err)
	}
	out := projectionProtocolReceive(t, f.ctx, done)
	select {
	case <-joined:
	default:
		t.Fatal("worker returned before cancelled reader joined")
	}
	if out.err == nil || out.state.State != contracts.NativeUncertain || reader.calls.Load() != 1 || completed.Load() != 0 || stream.projections.Load() != 0 {
		t.Fatal("cancelled query disclosed or claimed joined completion", out)
	}
}

func TestNativeApprovedProjectionRejectsWrongWorkerIdentity(t *testing.T) {
	for _, mode := range []string{"query", "mixed-parent", "pod", "key"} {
		t.Run(mode, func(t *testing.T) {
			f := newProjectionProtocolFixture(t)
			reader := f.reader()
			result := f.result(t, reader)
			var completed atomic.Int32
			op, client := f.operation(t, func(context.Context, value.NativeLease) error { completed.Add(1); return nil })
			target, key := f.target, artifact.Digest{1}
			switch mode {
			case "query":
				target.QueryID = "55555555-5555-4555-8555-555555555555"
			case "mixed-parent":
				target.SessionID = nativeID
			case "pod":
				target.PodUID = "55555555-5555-4555-8555-555555555555"
			case "key":
				key = artifact.Digest{9}
			}
			done, stream := f.run(t, client, result, target, key)
			out := projectionProtocolReceive(t, f.ctx, done)
			if out.err == nil || out.state.State != contracts.NativeUncertain || reader.calls.Load() != 0 || completed.Load() != 0 || stream.projections.Load() != 0 {
				t.Fatal("foreign worker reached approved source", out)
			}
			_ = op.Close()
		})
	}
}

func TestNativeApprovedProjectionBatchCannotBeReadAgain(t *testing.T) {
	for _, firstFails := range []bool{false, true} {
		name := "completed"
		if firstFails {
			name = "uncertain"
		}
		t.Run(name, func(t *testing.T) {
			f := newProjectionProtocolFixture(t)
			reader := f.reader()
			if firstFails {
				reader.read = func(context.Context, evidence.NativeContextSource, value.NativeOperation, query.ContextProjectionScope, time.Time) (query.PodStatusProjection, error) {
					return query.PodStatusProjection{}, errors.New("synthetic unavailable after read began")
				}
			}
			result := f.result(t, reader)
			for attempt := 0; attempt < 2; attempt++ {
				// A new exact exchange/fence does not replenish the same batch.
				f.lease.Operation.Reference.Fence = int64(attempt + 1)
				op, client := f.operation(t, syntheticNativeCompletion)
				done, stream := f.run(t, client, result, f.target, artifact.Digest{1})
				if attempt == 0 && !firstFails {
					if _, err := op.Projection(f.ctx); err != nil {
						t.Fatal(err)
					}
					if err := op.AcknowledgeProjection(f.ctx); err != nil {
						t.Fatal(err)
					}
					out := projectionProtocolReceive(t, f.ctx, done)
					if out.err != nil || out.state.State != contracts.NativeJoined {
						t.Fatal("first batch failed", out)
					}
				} else {
					out := projectionProtocolReceive(t, f.ctx, done)
					if out.err == nil || out.state.State != contracts.NativeUncertain || stream.projections.Load() != 0 {
						t.Fatal("spent batch returned another projection", out)
					}
				}
				_ = op.Close()
			}
			if reader.calls.Load() != 1 {
				t.Fatal("reconnected batch repeated source/key work", reader.calls.Load())
			}
		})
	}
}

// Installed native85: each complete hub check (owner serving, worker
// enrollment, operation) costs a few hundred milliseconds, and the hub ran two
// around every frame, so the projection read took more than three seconds
// before its first acknowledgement. Frame checks of one approved projection
// conversation now share a complete check for NativeRecheckInterval.
func TestNativeApprovedProjectionSharesFrameChecksWithinInterval(t *testing.T) {
	f := newProjectionProtocolFixture(t)
	result := f.result(t, f.reader())
	var checks atomic.Int32
	op, client := f.operationChecked(t, func(ctx context.Context, _ value.NativeLease) error { return ctx.Err() }, func(ctx context.Context) (value.NativeLease, error) {
		checks.Add(1)
		select {
		case <-time.After(250 * time.Millisecond): // one installed complete check
		case <-ctx.Done():
			return value.NativeLease{}, ctx.Err()
		}
		return f.lease, nil
	})
	started := time.Now()
	done, _ := f.run(t, client, result, f.target, artifact.Digest{1})
	if _, err := op.Projection(f.ctx); err != nil {
		t.Fatal(err)
	}
	if err := op.AcknowledgeProjection(f.ctx); err != nil {
		t.Fatal(err)
	}
	out := projectionProtocolReceive(t, f.ctx, done)
	t.Logf("complete checks=%d elapsed=%s", checks.Load(), time.Since(started))
	// Gate creation, both admissions, the handler's attachment check, the
	// consumption, acknowledgement and completion checks stay complete (7);
	// all frame checks share one. Without sharing this run made 15.
	if out.err != nil || out.state.State != contracts.NativeJoined || checks.Load() > 8 {
		t.Fatal("frame checks were not shared within the recheck interval", out.err, checks.Load())
	}
}

// Installed native87: the worker's request started 16.41; admission, the
// handler's attachment check and the command's frame check took about five
// seconds, and the hub's first result read then failed: the five-second
// Hello read deadline set at request start still applied to the attached
// conversation. The attached projection conversation reads under its lease.
func TestNativeApprovedProjectionResultReadOutlivesHelloDeadline(t *testing.T) {
	f := newProjectionProtocolFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	f.ctx = ctx
	now := time.Now().UTC().Truncate(time.Microsecond)
	f.lease.Operation.StartedAt, f.lease.Operation.Until = now, now.Add(20*time.Second)
	f.lease.Operation.Processing.ObservedAt, f.lease.Operation.Processing.ValidUntil = now, f.lease.Operation.Until
	f.lease.ObservedAt, f.lease.Until = now, f.lease.Operation.Until
	result := f.result(t, f.reader())
	var slow atomic.Bool
	op, client := f.operationChecked(t, func(ctx context.Context, _ value.NativeLease) error { return ctx.Err() }, func(ctx context.Context) (value.NativeLease, error) {
		if slow.Load() {
			select {
			case <-time.After(1800 * time.Millisecond): // installed complete check cost
			case <-ctx.Done():
				return value.NativeLease{}, ctx.Err()
			}
		}
		return f.lease, nil
	})
	slow.Store(true)
	done, _ := f.run(t, client, result, f.target, artifact.Digest{1})
	p, err := op.Projection(f.ctx)
	if err != nil || !reflect.DeepEqual(p.PodStatus, f.projection) {
		t.Fatal("result read failed after the Hello deadline", err)
	}
	if err = op.AcknowledgeProjection(f.ctx); err != nil {
		t.Fatal(err)
	}
	if out := projectionProtocolReceive(t, f.ctx, done); out.err != nil || out.state.State != contracts.NativeJoined {
		t.Fatal("conversation did not join", out.err)
	}
}

type fixedReadStep struct{ step string }

func (e fixedReadStep) Error() string     { return "refused" }
func (e fixedReadStep) FixedStep() string { return e.step }

// Installed native87 stopped the worker at "read" with no inner step. The
// worker's stop now names the approved reader's own closed step.
func TestNativeApprovedProjectionWorkerNamesReadStep(t *testing.T) {
	f := newProjectionProtocolFixture(t)
	reader := &projectionProtocolReader{read: func(context.Context, evidence.NativeContextSource, value.NativeOperation, query.ContextProjectionScope, time.Time) (query.PodStatusProjection, error) {
		return query.PodStatusProjection{}, fixedReadStep{"commit-get/cancelled"}
	}}
	result := f.result(t, reader)
	_, client := f.operation(t, func(ctx context.Context, _ value.NativeLease) error { return ctx.Err() })
	done, _ := f.run(t, client, result, f.target, artifact.Digest{1})
	out := projectionProtocolReceive(t, f.ctx, done)
	var s interface{ FixedStep() string }
	if !errors.As(out.err, &s) || s.FixedStep() != "read/approved/commit-get/cancelled" {
		t.Fatal("worker read stop lost its inner step", out.err)
	}
}

type exhaustionProjectionReader struct {
	projection query.ProjectionResult
	calls      atomic.Int32
}

func (r *exhaustionProjectionReader) ReadApprovedContext(context.Context, evidence.NativeContextSource, value.NativeOperation, query.ContextProjectionScope, time.Time) (query.ProjectionResult, error) {
	r.calls.Add(1)
	return r.projection, nil
}

type exhaustionProjectionStream struct {
	native.Stream
	mode string
}

func (s exhaustionProjectionStream) Receive(ctx context.Context) (contracts.NativeFrame, error) {
	f, e := s.Stream.Receive(ctx)
	if e == nil && f.Kind == contracts.NativeDoneFrame && s.mode == "lost-final" {
		clear(f.Payload)
		return contracts.NativeFrame{}, io.ErrUnexpectedEOF
	}
	return f, e
}
func (s exhaustionProjectionStream) Close() error {
	e := s.Stream.Close()
	if s.mode == "close-failed" {
		return io.ErrClosedPipe
	}
	return e
}

// Real H2/mTLS and exact protocol joins, with synthetic admitted scope, reader
// and SQL-completion ports. No worker-lifetime or authority interval is changed.
func TestNativeExhaustionRequiresExactSingleBatchJoinedACK(t *testing.T) {
	for _, mode := range []string{"single-batch", "two-batch-raw", "lost-final", "close-failed", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			f := newProjectionProtocolFixture(t)
			e, s := &f.source.Expectation, &f.scope
			e.NativeType, e.DataClass, e.ActionID = artifact.PprofArtifact, "raw", "a0123456789abcdef01234567"
			e.Profile = &artifact.GoProfileAcquisition{SourceRef: "go", EndpointDigest: artifact.Digest{1}, Type: "heap", Mode: "snapshot"}
			e.Registration.NativeLimit = artifact.MaxPprofBytes
			s.NativeType, s.SourceFormat, s.DisplayVersion, s.SourceProjectionDigest = artifact.PprofArtifact, artifact.PprofFormat, query.ProfileSummaryDisplayVersion, artifact.Digest{}
			s.Selection = query.LineSelection{}
			s.Profile = query.ProfileSummarySelection{SampleType: "alloc_space", TopN: 20}
			projection := query.ProjectionResult{Summary: &query.ProfileSummary{SampleType: "alloc_space", Unit: "bytes", SymbolStatus: "missing", Top: []query.ProfileHotspot{}}}
			if mode == "two-batch-raw" {
				e.NativeType, e.DataClass, e.Profile = artifact.SyscallArgumentsArtifact, "raw", nil
				e.Registration.NativeLimit = artifact.RecordingNativeLimit
				e.Recording = &artifact.Recording{Kind: "syscallTrace", Profile: "arguments", Composition: []byte("{}"), DurationMillis: 1000, MaxBytes: artifact.RecordingNativeLimit, Syscalls: &artifact.RecordingSyscalls{Names: []string{"write"}, MaxEvents: 100, MaxEventsPerSecond: 100, MaxTrackedThreads: 16}, Arguments: &artifact.RecordingArguments{ProgramDigest: artifact.Digest{1}, DefinitionDigest: artifact.Digest{2}, AccountingRule: artifact.Digest{3}, MaxProbeBytes: 256, MaxBytesPerEvent: 128, MaxBytesPerSecond: 1024}}
				s.NativeType, s.SourceFormat, s.DisplayVersion = artifact.SyscallArgumentsArtifact, artifact.SyscallArgumentsFormat, query.SyscallQueryDisplayVersion
				s.Profile = query.ProfileSummarySelection{}
				selection, err := query.NormalizeSyscallSelection(s.CaseID, s.ArtifactID, query.SyscallQueryView, "", 20, nil, false)
				if err != nil {
					t.Fatal(err)
				}
				s.Syscalls, s.RawGrantID = selection.Window(), nativeID
				projection = query.ProjectionResult{SyscallQuery: &query.SyscallArgumentPage{Version: s.Version, Events: []artifact.RawArgumentEvent{}}}
			}
			if !s.Valid() || !f.source.Valid(s.Version) || !projection.Valid(*s) {
				t.Fatal("invalid exhaustion fixture", e.Validate(), s.Valid(), projection.Valid(*s))
			}
			reader := &exhaustionProjectionReader{projection: projection}
			result, err := evidence.NewRegionalApprovedResult(f.ctx, f.target, reader, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { result.Close(); _ = result.Wait(context.Background()) })
			entered, release := make(chan struct{}), make(chan struct{})
			var completed atomic.Int32
			op, client := f.operation(t, func(ctx context.Context, _ value.NativeLease) error {
				completed.Add(1)
				close(entered)
				select {
				case <-release:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			})
			stream, err := client.Open(f.ctx, f.hello)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			done := make(chan projectionProtocolOutcome, 1)
			go func() {
				out, err := native.RunWorkerConversation(ctx, exhaustionProjectionStream{stream, mode}, f.hello, f.target, artifact.Digest{1}, result)
				done <- projectionProtocolOutcome{out, err}
			}()
			if _, err := op.Projection(f.ctx); err != nil {
				t.Fatal(err)
			}
			acked := make(chan error, 1)
			go func() { acked <- op.AcknowledgeProjection(f.ctx) }()
			<-entered
			select {
			case out := <-done:
				t.Fatal("worker published exhaustion before joined ACK", out)
			default:
			}
			if mode == "cancelled" {
				cancel()
			}
			close(release)
			ackErr := <-acked
			out := projectionProtocolReceive(t, f.ctx, done)
			if mode == "lost-final" || mode == "close-failed" || mode == "cancelled" {
				if out.err == nil || out.state.State != contracts.NativeUncertain || out.state.ExhaustedProjection {
					t.Fatal("unjoined projection marked exhausted", out)
				}
			} else if ackErr != nil || out.err != nil || out.state.State != contracts.NativeJoined || out.state.ExhaustedProjection != (s.ReadBatches() == 1) {
				t.Fatal("joined exhaustion does not match immutable scope", out, ackErr, s.ReadBatches())
			}
			if reader.calls.Load() != 1 || completed.Load() != 1 {
				t.Fatal("projection effect or completion repeated", reader.calls.Load(), completed.Load())
			}
		})
	}
}
