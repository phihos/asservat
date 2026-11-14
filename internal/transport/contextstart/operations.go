package contextstart

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	executionapp "asservat.local/asservat/internal/application/execution"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/collector"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

// ADR-171: the hub runs the API context runner. The region answers only these
// cluster-local operations for the exact verified work. Plaintext evidence and
// data keys never cross the exchange: acquisition captures, encrypts and
// uploads in the region and returns copy receipts only.
const (
	opResolvePod             = "resolve-pod"
	opResolvePacketSource    = "resolve-packet-source"
	opResolveArgumentSource  = "resolve-argument-source"
	opStartArgumentRecording = "start-argument-recording"
	opStartPolicyRecording   = "start-policy-recording"
	opReadProcess            = "read-process"
	opPrepareOutput          = "prepare-output"
	opAcquire                = "acquire-context"
	opComplete               = "complete-stored"
	opFinish                 = "finish"
	// ADR-248: a recording is started within the committed start and
	// collected by a later exchange for the same verified capture.
	opStartProfile   = "start-profile"
	opStartLogs      = "start-logs"
	opStartRecording = "start-recording"
	opCollect        = "collect-recording"
)

// Closed failure labels; raw errors never cross the exchange.
var operationFailures = []struct {
	label string
	err   error
}{
	{"preparation-uncertain", value.ErrPreparationUncertain},
	{"store-unconfirmed", evidence.ErrContextStoreUnconfirmed},
	{"target-changed", targets.ErrChanged},
	{"target-denied", targets.ErrDenied},
	{"peers-changed", targets.ErrPeersChanged},
	{"peers-stale", targets.ErrPeersStale},
	{"peer-busy", targets.ErrPeerVerifierBusy},
	{"denied", value.ErrDenied},
	{"invalid", value.ErrInvalid},
	{"expired", value.ErrExpired},
	{"conflict", value.ErrConflict},
	{"unavailable", value.ErrUnavailable},
}

func operationFailureLabel(err error) string {
	for _, f := range operationFailures {
		if errors.Is(err, f.err) {
			return f.label
		}
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "expired"
	}
	return "unavailable"
}

func operationFailureError(label string) error {
	for _, f := range operationFailures {
		if f.label == label {
			return f.err
		}
	}
	return value.ErrUnavailable
}

type acquireRequest struct {
	Pin            artifact.PinnedPod
	Started, Until time.Time
}
type policyRecordingRequest struct {
	Pin            artifact.PinnedPod
	Started, Until time.Time
	Source         targets.PacketSourceObservation
	Permit         collector.ObservationPermit
}

type argumentRecordingRequest struct {
	Pin            artifact.PinnedPod
	Started, Until time.Time
	Source         targets.PacketSourceObservation
	Permit         collector.ArgumentObservationPermit
}

type profileRequest struct {
	Pin            artifact.PinnedPod
	Started, Until time.Time
	Endpoint       targets.ProfileEndpointRequest
}

type acquireReply struct {
	Acquired time.Time
	Copies   artifact.Copies
}
type recordingReply struct {
	Queued time.Time
}

// HubOperations implements the runner's cluster-local ports by sending one
// operation at a time over the exchange. It never carries native bytes.
type HubOperations struct {
	stream Stream
	ctx    context.Context
	mu     sync.Mutex
	seq    int
	broken bool
	// Timing, when set, receives each operation's fixed method name and
	// duration (diagnostic only).
	Timing func(method string, d time.Duration)
}

var (
	_ executionapp.APIProcessReader = (*HubOperations)(nil)
	_ executionapp.ContextCollector = (*HubOperations)(nil)
	_ evidence.ContextProducer      = (*HubOperations)(nil)
)

// call sends one operation and decodes its reply. A failure may still carry
// partial facts (an acquisition instant); they are decoded before the failure
// is returned. Any transport or framing defect breaks the exchange.
func (h *HubOperations) call(ctx context.Context, method string, in, out any) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.Timing != nil {
		defer func(start time.Time) { h.Timing(method, time.Since(start)) }(time.Now())
	}
	if h.broken || ctx == nil || h.seq >= contracts.APIContextMaximumOperations {
		return value.ErrUnavailable
	}
	// ADR-333: nothing is sent for an operation the connector did not
	// announce; the exchange stays intact for the run's own failure handling.
	if e := requireCapability(h.stream, operationCapability(method), errOperationClass); e != nil {
		return e
	}
	h.seq++
	body, err := json.Marshal(in)
	if err != nil {
		return value.ErrInvalid
	}
	encoded, err := contracts.EncodeAPIContextOperation(contracts.APIContextOperation{Format: contracts.APIContextExchangeFormat, Sequence: h.seq, Method: method, Body: body})
	if err != nil {
		return value.ErrInvalid
	}
	err = h.stream.Send(ctx, contracts.APIContextFrame{Kind: contracts.APIContextOperationRequestFrame, Payload: encoded})
	clear(encoded)
	if err != nil {
		h.broken = true
		return err
	}
	f, err := h.stream.Receive(ctx)
	defer clear(f.Payload)
	if err != nil || f.Kind != contracts.APIContextOperationResponseFrame {
		h.broken = true
		if err != nil {
			return err
		}
		return contracts.ErrAPIContextProtocol
	}
	reply, err := contracts.DecodeAPIContextOperationReply(f.Payload)
	if err != nil || reply.Sequence != h.seq || reply.Method != method {
		h.broken = true
		return contracts.ErrAPIContextProtocol
	}
	if out == nil || len(reply.Body) == 0 {
		if reply.Failure != "" {
			return operationFailureError(reply.Failure)
		}
		if out == nil {
			return nil
		}
		h.broken = true
		return contracts.ErrAPIContextProtocol
	}
	if decodeOperationBody(reply.Body, out) != nil {
		h.broken = true
		return contracts.ErrAPIContextProtocol
	}
	if reply.Failure != "" {
		return operationFailureError(reply.Failure)
	}
	return nil
}

func (h *HubOperations) ResolvePod(ctx context.Context, r targets.Request) (targets.PodResolution, error) {
	var out targets.PodResolution
	err := h.call(ctx, opResolvePod, r, &out)
	return out, err
}
func (h *HubOperations) ResolvePacketSource(ctx context.Context, r targets.Request) (targets.RecorderResolution, error) {
	var out targets.RecorderResolution
	err := h.call(ctx, opResolvePacketSource, r, &out)
	return out, err
}

func (h *HubOperations) ResolveArgumentSource(ctx context.Context, r targets.Request) (targets.RecorderResolution, error) {
	var out targets.RecorderResolution
	err := h.call(ctx, opResolveArgumentSource, r, &out)
	return out, err
}

func (h *HubOperations) ReadAPIProcess(ctx context.Context) (value.APIProcessObservation, error) {
	var out value.APIProcessObservation
	err := h.call(ctx, opReadProcess, struct{}{}, &out)
	return out, err
}

// Capture never runs on the hub; acquisition belongs to the regional output.
func (h *HubOperations) Capture(context.Context, artifact.PinnedPod) ([]byte, error) {
	return nil, value.ErrUnavailable
}

func (h *HubOperations) PrepareContext(ctx context.Context, e artifact.ContextExpectation) (evidence.PreparedContext, error) {
	if err := h.call(ctx, opPrepareOutput, e, nil); err != nil {
		return nil, err
	}
	return &remoteOutput{h: h}, nil
}

// remoteOutput is the hub's handle on the regional prepared output.
type remoteOutput struct{ h *HubOperations }

var (
	_ evidence.StoredContextCloser     = (*remoteOutput)(nil)
	_ evidence.ContextAcquirer         = (*remoteOutput)(nil)
	_ evidence.ContextRecorder         = (*remoteOutput)(nil)
	_ evidence.ArgumentContextRecorder = (*remoteOutput)(nil)
	_ evidence.RecordingCollector      = (*HubOperations)(nil)
)

func (o *remoteOutput) StartProfile(ctx context.Context, pin artifact.PinnedPod, started, until time.Time, endpoint targets.ProfileEndpointRequest) (time.Time, error) {
	var out recordingReply
	err := o.h.call(ctx, opStartProfile, profileRequest{pin, started, until, endpoint}, &out)
	return out.Queued, err
}

func (o *remoteOutput) StartLogs(ctx context.Context, pin artifact.PinnedPod, started, until time.Time) (time.Time, error) {
	var out recordingReply
	err := o.h.call(ctx, opStartLogs, acquireRequest{pin, started, until}, &out)
	return out.Queued, err
}

// StartRecording asks the region to queue the recording on the pinned Pod's
// node within the committed start (ADR-248).
func (o *remoteOutput) StartRecording(ctx context.Context, pin artifact.PinnedPod, started, until time.Time) (time.Time, error) {
	var out recordingReply
	err := o.h.call(ctx, opStartRecording, acquireRequest{pin, started, until}, &out)
	return out.Queued, err
}

func (o *remoteOutput) StartPolicyRecording(ctx context.Context, pin artifact.PinnedPod, started, until time.Time, source targets.PacketSourceObservation, permit collector.ObservationPermit) (time.Time, error) {
	var out recordingReply
	err := o.h.call(ctx, opStartPolicyRecording, policyRecordingRequest{pin, started, until, source, permit}, &out)
	return out.Queued, err
}

func (o *remoteOutput) StartArgumentRecording(ctx context.Context, pin artifact.PinnedPod, started, until time.Time, source targets.PacketSourceObservation, permit collector.ArgumentObservationPermit) (time.Time, error) {
	var out recordingReply
	err := o.h.call(ctx, opStartArgumentRecording, argumentRecordingRequest{pin, started, until, source, permit}, &out)
	return out.Queued, err
}

// CollectRecording asks the region for the held outcome of this exchange's
// verified capture (ADR-248). No evidence byte crosses: only the state and
// the writer completion.
func (h *HubOperations) CollectRecording(ctx context.Context) (evidence.RecordingCollection, error) {
	var out evidence.RecordingCollection
	err := h.call(ctx, opCollect, struct{}{}, &out)
	return out, err
}

func (o *remoteOutput) StoreContext(context.Context, []byte, time.Time, time.Time) (artifact.Copies, error) {
	return artifact.Copies{}, value.ErrUnavailable // native bytes never reach the hub
}

// Close is a no-op: the region closes its handle when the work finishes.
func (o *remoteOutput) Close() {}
func (o *remoteOutput) AcquireContext(ctx context.Context, pin artifact.PinnedPod, started, until time.Time) (time.Time, artifact.Copies, error) {
	var out acquireReply
	err := o.h.call(ctx, opAcquire, acquireRequest{pin, started, until}, &out)
	return out.Acquired, out.Copies, err
}
func (o *remoteOutput) CompleteStored() (artifact.ContextWriterCompletion, error) {
	var out artifact.ContextWriterCompletion
	err := o.h.call(o.h.ctx, opComplete, struct{}{}, &out)
	return out, err
}

// ServeHubOperations sends the signed work, runs run with this exchange's
// operations and ends the conversation with run's state: a finish operation,
// the regional result echo and the receipt.
func ServeHubOperations(ctx context.Context, stream Stream, w fleet.APIContextWork, signed []byte, run func(context.Context, *HubOperations) (string, error), now func() time.Time) (state string, err error) {
	stage := streamHubSetup
	defer func() { recordStreamDiagnostic(ctx, stream, err, stage) }()
	if ctx == nil || ctx.Err() != nil || stream == nil || run == nil || now == nil || !w.Valid(now()) || len(signed) == 0 || len(signed) > contracts.APIContextSignedWorkBytes {
		return "", fleet.ErrInvalid
	}
	call, cancel := context.WithDeadline(ctx, w.NotAfter)
	ended := make(chan struct{})
	stopStream := context.AfterFunc(stream.Context(), func() { cancel(); close(ended) })
	defer func() {
		if !stopStream() {
			<-ended
		}
		cancel()
	}()
	stage = streamHubSend
	if err = stream.Send(call, contracts.APIContextFrame{Kind: contracts.APIContextWorkFrame, Payload: signed}); err != nil {
		return "", err
	}
	ops := &HubOperations{stream: stream, ctx: call}
	stage = streamHubOperations
	state, runErr := run(call, ops)
	if !knownResult(state) {
		state = "Unavailable"
	}
	// A run failure is reported at the operations stage once the conversation
	// has otherwise completed, never replaced by a later transport stage.
	defer func() {
		if runErr != nil && err == runErr {
			stage = streamHubOperations
		}
	}()
	stage = streamHubResult
	if err = ops.call(call, opFinish, state, nil); err != nil {
		return "", err
	}
	f, err := stream.Receive(call)
	defer clear(f.Payload)
	if err != nil || f.Kind != contracts.APIContextResultFrame {
		return "", contracts.ErrAPIContextProtocol
	}
	result, err := contracts.DecodeAPIContextResult(f.Payload)
	if err != nil || result.Format != contracts.APIContextExchangeFormat || result.ExchangeID != w.Channel.ExchangeID || result.CaptureID != w.CaptureID || result.State != state {
		return "", contracts.ErrAPIContextProtocol
	}
	stage = streamHubReceipt
	receipt, err := contracts.EncodeAPIContextReceipt(contracts.APIContextReceipt{Format: contracts.APIContextExchangeFormat, ExchangeID: w.Channel.ExchangeID, CaptureID: w.CaptureID, State: "received"})
	if err != nil {
		return "", err
	}
	err = stream.Send(call, contracts.APIContextFrame{Kind: contracts.APIContextReceiptFrame, Payload: receipt})
	clear(receipt)
	if err != nil {
		return "", err
	}
	return state, runErr
}

// RegionalLocal is the regional process's cluster-local port set. It holds no
// SQL, identity or unwrap authority.
type RegionalLocal struct {
	Process executionapp.APIProcessReader
	// Targets also answers the hub's pre-work queries (ADR-179).
	Targets   QueryTargets
	Output    evidence.ContextProducer
	Collector executionapp.ContextCollector
	// Source is this region's own connector source reader (ADR-178).
	Source fleetapp.ConnectorIdentitySourceReader
	// Recordings answers collects of held recordings (ADR-248); optional.
	Recordings RegionalRecordings
	History    *HistoryLocal
	Sources    *SourceLocal
	Now        func() time.Time
}

// RegionalRecordings is the connector's holder of started recordings.
type RegionalRecordings interface {
	// Collect returns the held outcome of the work's capture, bound to its
	// attempt and expectation digest.
	Collect(w fleet.APIContextWork) (evidence.RecordingCollection, error)
}

func (l RegionalLocal) valid() bool {
	return l.Process != nil && l.Targets != nil && l.Output != nil && l.Collector != nil && l.Now != nil
}

// regionalSession answers operations for exactly one verified work. Every
// operation is bound to that work's capture, attempt, target and digests;
// acquisition requires the committed start and the exact resolved pin.
type regionalSession struct {
	snapshotTarget *targets.SourceSnapshotResolution
	local          RegionalLocal
	work           fleet.APIContextWork
	// process is this work's one complete process observation (ADR-173). Later
	// operations reuse it until its original deadline; it is never renewed.
	process        *value.APIProcessObservation
	resolved       *targets.PodResolution
	packetSource   *targets.PacketSourceObservation
	argumentSource *targets.PacketSourceObservation
	expectation    *artifact.ContextExpectation
	prepared       evidence.PreparedContext
	acquired       bool
}

func (s *regionalSession) close() {
	if s.prepared != nil {
		s.prepared.Close()
		s.prepared = nil
	}
}

// readProcess answers from the work's observation while it is within its
// original interval; afterwards it reads a new complete one.
func (s *regionalSession) readProcess(ctx context.Context) (value.APIProcessObservation, error) {
	if s.process != nil && s.process.Valid(s.local.Now()) {
		return *s.process, nil
	}
	s.process = nil
	out, err := s.local.Process.ReadAPIProcess(ctx)
	if err == nil && out.Valid(s.local.Now()) {
		s.process = &out
	}
	return out, err
}

func decodeOperationBody(body []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(body))
	// Unknown fields of a newer peer are ignored (ADR-333).
	if d.Decode(out) != nil || d.More() {
		return value.ErrInvalid
	}
	return nil
}

func (s *regionalSession) handle(ctx context.Context, q contracts.APIContextOperation) (any, error) {
	l := s.local
	switch q.Method {
	case opResolveSourceSnapshot:
		return s.resolveSourceSnapshot(ctx, q.Body)
	case opResolvePod:
		if s.packetSource != nil || s.argumentSource != nil || s.snapshotTarget != nil {
			return nil, value.ErrDenied
		}
		var r targets.Request
		if err := decodeOperationBody(q.Body, &r); err != nil {
			return nil, err
		}
		out, err := l.Targets.ResolvePod(ctx, r)
		if err != nil {
			return nil, err
		}
		if out.Target() != s.work.Target {
			return nil, value.ErrDenied
		}
		s.resolved = &out
		return out, nil
	case opResolvePacketSource:
		var r targets.Request
		if err := decodeOperationBody(q.Body, &r); err != nil {
			return nil, err
		}
		// A source observation grants nothing: a policy raw predicate (ADR-261)
		// or a manual rawPackets/httpHeaders recording (ADR-279/282) asks for
		// it, and only a
		// verified metered expectation can start with it (policyRecordingMatches).
		resolver, ok := l.Targets.(interface {
			ResolvePacketSource(context.Context, targets.Request) (targets.RecorderResolution, error)
		})
		if !ok || s.resolved != nil {
			return nil, value.ErrDenied
		}
		out, err := resolver.ResolvePacketSource(ctx, r)
		if err != nil {
			return nil, err
		}
		if !out.ValidSource(l.Now()) || out.Target.Target() != s.work.Target {
			return nil, value.ErrDenied
		}
		target, source := out.Target, *out.Recorder.Source
		s.resolved, s.packetSource = &target, &source
		return out, nil
	case opResolveArgumentSource:
		var r targets.Request
		if err := decodeOperationBody(q.Body, &r); err != nil {
			return nil, err
		}
		resolver, ok := l.Targets.(interface {
			ResolveArgumentSource(context.Context, targets.Request) (targets.RecorderResolution, error)
		})
		if !ok || s.resolved != nil {
			return nil, value.ErrDenied
		}
		out, err := resolver.ResolveArgumentSource(ctx, r)
		if err != nil {
			return nil, err
		}
		if !out.ValidSource(l.Now()) || out.Target.Target() != s.work.Target {
			return nil, value.ErrDenied
		}
		target, source := out.Target, *out.Recorder.Source
		s.resolved, s.argumentSource = &target, &source
		return out, nil
	case opReadProcess:
		return s.readProcess(ctx)
	case opPrepareOutput:
		var e artifact.ContextExpectation
		if err := decodeOperationBody(q.Body, &e); err != nil {
			return nil, err
		}
		if s.prepared != nil || evidence.ContextExpectationDigest(e) != s.work.ExpectationDigest {
			return nil, value.ErrDenied
		}
		prepared, err := l.Output.PrepareContext(ctx, e)
		if err != nil {
			return nil, err
		}
		s.prepared = prepared
		s.expectation = &e
		return struct{}{}, nil
	case opAcquire:
		var r acquireRequest
		if err := decodeOperationBody(q.Body, &r); err != nil {
			return nil, err
		}
		if s.acquired || s.prepared == nil || s.resolved == nil || r.Until.After(s.work.NotAfter) || r.Pin != s.resolved.Pin {
			return nil, value.ErrDenied
		}
		s.acquired = true
		return s.acquire(ctx, r)
	case opComplete:
		closer, ok := s.prepared.(evidence.StoredContextCloser)
		if !s.acquired || !ok {
			return nil, value.ErrDenied
		}
		return closer.CompleteStored()
	case opStartLogs:
		var r acquireRequest
		if err := decodeOperationBody(q.Body, &r); err != nil {
			return nil, err
		}
		recorder, ok := s.prepared.(evidence.LogsRecorder)
		if s.acquired || !ok || s.resolved == nil || s.expectation == nil || s.expectation.Logs == nil || r.Until.After(s.work.NotAfter) || r.Pin != s.resolved.Pin || !l.Now().Before(r.Until) {
			return nil, value.ErrDenied
		}
		s.acquired = true
		queued, err := recorder.StartLogs(ctx, r.Pin, r.Started, r.Until)
		if err != nil {
			return nil, err
		}
		return recordingReply{Queued: queued}, nil
	case opStartProfile:
		var r profileRequest
		if err := decodeOperationBody(q.Body, &r); err != nil {
			return nil, err
		}
		recorder, ok := s.prepared.(evidence.ProfileRecorder)
		if s.acquired || !ok || s.resolved == nil || s.expectation == nil || s.expectation.Profile == nil || r.Until.After(s.work.NotAfter) || r.Pin != s.resolved.Pin || !l.Now().Before(r.Until) {
			return nil, value.ErrDenied
		}
		s.acquired = true
		queued, err := recorder.StartProfile(ctx, r.Pin, r.Started, r.Until, r.Endpoint)
		if err != nil {
			return nil, err
		}
		return recordingReply{Queued: queued}, nil
	case opStartRecording:
		if s.expectation != nil && s.expectation.Recording != nil && s.expectation.Recording.Arguments != nil {
			return nil, value.ErrDenied
		}
		var r acquireRequest
		if err := decodeOperationBody(q.Body, &r); err != nil {
			return nil, err
		}
		recorder, ok := s.prepared.(evidence.ContextRecorder)
		if s.acquired || !ok || s.resolved == nil || r.Until.After(s.work.NotAfter) || r.Pin != s.resolved.Pin {
			return nil, value.ErrDenied
		}
		s.acquired = true
		queued, err := recorder.StartRecording(ctx, r.Pin, r.Started, r.Until)
		if err != nil {
			return nil, err
		}
		return recordingReply{Queued: queued}, nil
	case opStartSourceSnapshot:
		return s.startSourceSnapshot(ctx, q.Body)
	case opStartPolicyRecording:
		var r policyRecordingRequest
		if err := decodeOperationBody(q.Body, &r); err != nil {
			return nil, err
		}
		recorder, ok := s.prepared.(evidence.PolicyContextRecorder)
		// A policy raw predicate (ADR-261) or a human's approved rawPackets
		// (ADR-279) or httpHeaders (ADR-282) recording, judged on the
		// verified expectation.
		_, _, policy := authorization.PolicyExecutor(s.work.Actor)
		metered := policy || s.expectation != nil && s.expectation.Recording != nil && (s.expectation.Recording.Profile == "rawPackets" || s.expectation.Recording.Profile == "httpHeaders")
		if s.acquired || !metered || !ok || s.resolved == nil || s.packetSource == nil || s.expectation == nil || r.Until.After(s.work.NotAfter) || r.Pin != s.resolved.Pin || !samePacketSource(r.Source, *s.packetSource) || !r.Source.Valid(l.Now()) || !r.Permit.ValidFinite(l.Now()) || r.Permit.Binding.ExpectationDigest != [32]byte(s.work.ExpectationDigest) || r.Permit.Binding.CaptureID != s.work.CaptureID || r.Permit.Binding.ActionID != s.expectation.ActionID || !policyRecordingMatches(*s.expectation, r.Source, r.Permit) || !l.Now().Before(r.Until) {
			return nil, value.ErrDenied
		}
		s.acquired = true
		queued, err := recorder.StartPolicyRecording(ctx, r.Pin, r.Started, r.Until, r.Source, r.Permit)
		if err != nil {
			return nil, err
		}
		return recordingReply{Queued: queued}, nil
	case opStartArgumentRecording:
		var r argumentRecordingRequest
		if err := decodeOperationBody(q.Body, &r); err != nil {
			return nil, err
		}
		recorder, ok := s.prepared.(evidence.ArgumentContextRecorder)
		now := l.Now()
		if s.acquired || !ok || s.resolved == nil || s.argumentSource == nil || s.expectation == nil ||
			r.Until.After(s.work.NotAfter) || r.Pin != s.resolved.Pin || !samePacketSource(r.Source, *s.argumentSource) || !r.Source.Valid(now) || !r.Permit.ValidFinite(now) ||
			r.Permit.Binding.ExpectationDigest != [32]byte(s.work.ExpectationDigest) || r.Permit.Binding.CaptureID != s.work.CaptureID || r.Permit.Binding.ActionID != s.expectation.ActionID || !argumentRecordingMatches(*s.expectation, r.Source, r.Permit) || !now.Before(r.Until) {
			return nil, value.ErrDenied
		}
		s.acquired = true // an uncertain reply cannot repeat the start effect
		queued, err := recorder.StartArgumentRecording(ctx, r.Pin, r.Started, r.Until, r.Source, r.Permit)
		if err != nil {
			return nil, err
		}
		return recordingReply{Queued: queued}, nil
	case opCollect:
		// Collecting needs no start: the verified work names the capture
		// whose held outcome is returned. Nothing is acquired or spent.
		if l.Recordings == nil || s.prepared != nil || s.acquired {
			return nil, value.ErrUnavailable
		}
		return l.Recordings.Collect(s.work)
	}
	return nil, value.ErrInvalid
}

// acquire captures within the committed start's deadline, then encrypts and
// uploads in place. Only the instant and copy receipts leave this process.
func (s *regionalSession) acquire(ctx context.Context, r acquireRequest) (acquireReply, error) {
	captureCtx, end := context.WithDeadline(ctx, r.Until)
	native, err := s.local.Collector.Capture(captureCtx, r.Pin)
	acquired := s.local.Now().UTC().Truncate(time.Microsecond)
	captureErr := captureCtx.Err()
	end()
	defer clear(native)
	if err != nil || captureErr != nil || !acquired.Before(r.Until) || len(native) == 0 || len(native) > artifact.MaxContextBytes {
		return acquireReply{}, value.ErrExpired // capture failed: no copies exist
	}
	copies, err := s.prepared.StoreContext(ctx, native, r.Started, acquired)
	if err != nil {
		return acquireReply{Acquired: acquired}, errors.Join(evidence.ErrContextStoreUnconfirmed, err)
	}
	return acquireReply{Acquired: acquired, Copies: copies}, nil
}

// ServeRegionalOperations accepts exactly one signed work, then answers the
// hub's operations for it until finish, echoes the hub's final state and
// waits for the receipt.
func ServeRegionalOperations(ctx context.Context, stream Stream, receiver fleet.APIContextReceiver, verifier fleetapp.APIContextWorkVerifier, local RegionalLocal, now func() time.Time) (err error) {
	stage := streamRegionalSetup
	defer func() { recordStreamDiagnostic(ctx, stream, err, stage) }()
	if ctx == nil || ctx.Err() != nil || stream == nil || verifier == nil || !local.valid() || now == nil || !receiver.Valid(now()) {
		return fleet.ErrInvalid
	}
	stage = streamRegionalWork
	f, current, err := stream.AwaitWork(ctx)
	if err != nil || f.Kind != contracts.APIContextWorkFrame && f.Kind != contracts.HistoryWorkFrame {
		clear(f.Payload)
		return contracts.ErrAPIContextProtocol
	}
	if current.Channel != receiver.Channel || !current.Valid(now()) {
		clear(f.Payload)
		return fleet.ErrDenied
	}
	if f.Kind == contracts.HistoryWorkFrame {
		defer clear(f.Payload)
		return serveRegionalHistory(ctx, stream, current, f.Payload, local.History, now)
	}
	stage = streamRegionalVerify
	authenticated, err := verifier.VerifyAPIContextWork(ctx, f.Payload, current)
	clear(f.Payload)
	if err != nil || !authenticated.Valid(now()) {
		return fleet.ErrDenied
	}
	call, cancel := context.WithDeadline(ctx, authenticated.ValidUntil)
	ended := make(chan struct{})
	stopStream := context.AfterFunc(stream.Context(), func() { cancel(); close(ended) })
	defer func() {
		if !stopStream() {
			<-ended
		}
		cancel()
	}()
	s := &regionalSession{local: local, work: authenticated.Work}
	defer s.close()
	stage = streamRegionalOperations
	for sequence := 1; sequence <= contracts.APIContextMaximumOperations; sequence++ {
		f, err := stream.Receive(call)
		if err != nil || f.Kind != contracts.APIContextOperationRequestFrame {
			clear(f.Payload)
			return contracts.ErrAPIContextProtocol
		}
		q, err := contracts.DecodeAPIContextOperation(f.Payload)
		clear(f.Payload)
		if err != nil || q.Sequence != sequence {
			return contracts.ErrAPIContextProtocol
		}
		if q.Method == opFinish {
			var state string
			if decodeOperationBody(q.Body, &state) != nil || !knownResult(state) {
				return contracts.ErrAPIContextProtocol
			}
			stage = streamRegionalResult
			return s.finish(call, stream, q, state)
		}
		reply := contracts.APIContextOperationReply{Format: contracts.APIContextExchangeFormat, Sequence: q.Sequence, Method: q.Method}
		out, err := s.handle(call, q)
		if err != nil {
			reply.Failure = operationFailureLabel(err)
			if a, ok := out.(acquireReply); ok && !a.Acquired.IsZero() {
				reply.Body, _ = json.Marshal(a) // a failed store still reports its instant
			}
		} else if reply.Body, err = json.Marshal(out); err != nil {
			reply.Body, reply.Failure = nil, "unavailable"
		}
		encoded, err := contracts.EncodeAPIContextOperationReply(reply)
		if err != nil {
			return err
		}
		err = stream.Send(call, contracts.APIContextFrame{Kind: contracts.APIContextOperationResponseFrame, Payload: encoded})
		clear(encoded)
		if err != nil {
			return err
		}
	}
	return contracts.ErrAPIContextProtocol
}

// finish acknowledges the hub's final state as an ordinary operation reply,
// then sends the result echo and waits for the receipt.
func (s *regionalSession) finish(ctx context.Context, stream Stream, q contracts.APIContextOperation, state string) error {
	s.close()
	ack, err := contracts.EncodeAPIContextOperationReply(contracts.APIContextOperationReply{Format: contracts.APIContextExchangeFormat, Sequence: q.Sequence, Method: q.Method})
	if err != nil {
		return err
	}
	err = stream.Send(ctx, contracts.APIContextFrame{Kind: contracts.APIContextOperationResponseFrame, Payload: ack})
	clear(ack)
	if err != nil {
		return err
	}
	// ADR-178: a fresh regional source precedes the result for the hub's final check.
	if pusher, ok := stream.(interface{ pushSource(context.Context) error }); ok {
		if err = pusher.pushSource(ctx); err != nil {
			return err
		}
	}
	encoded, err := contracts.EncodeAPIContextResult(contracts.APIContextResult{Format: contracts.APIContextExchangeFormat, ExchangeID: s.work.Channel.ExchangeID, CaptureID: s.work.CaptureID, State: state})
	if err != nil {
		return err
	}
	err = stream.Send(ctx, contracts.APIContextFrame{Kind: contracts.APIContextResultFrame, Payload: encoded})
	clear(encoded)
	if err != nil {
		return err
	}
	f, err := stream.Receive(ctx)
	defer clear(f.Payload)
	if err != nil || f.Kind != contracts.APIContextReceiptFrame {
		return contracts.ErrAPIContextProtocol
	}
	receipt, err := contracts.DecodeAPIContextReceipt(f.Payload)
	if err != nil || receipt.Format != contracts.APIContextExchangeFormat || receipt.ExchangeID != s.work.Channel.ExchangeID || receipt.CaptureID != s.work.CaptureID || receipt.State != "received" {
		return contracts.ErrAPIContextProtocol
	}
	return nil
}

// Compare instants rather than Go time representations: SQL receipts may have
// passed through a driver-local zone without changing their original bounds.
func samePacketSource(a, b targets.PacketSourceObservation) bool {
	return a.PodUID == b.PodUID && a.NodeUID == b.NodeUID && a.BootID == b.BootID && a.CollectorPodUID == b.CollectorPodUID && a.CollectorEpoch == b.CollectorEpoch && a.ObservedAt.Equal(b.ObservedAt) && a.FreshUntil.Equal(b.FreshUntil)
}

// The expectation was checked against independently verified signed work at
// prepare-output; the source was resolved locally in this exchange. Neither is
// recovered from the permit's caller-supplied copies.
func policyRecordingMatches(e artifact.ContextExpectation, source targets.PacketSourceObservation, permit collector.ObservationPermit) bool {
	r, b := e.Recording, permit.Binding
	if !r.Valid() || r.Arguments != nil || !compiler.MeteredRecording(r) || permit.Duration != time.Duration(r.DurationMillis)*time.Millisecond || b.PodUID != e.PodUID || source.PodUID != e.PodUID || b.NodeUID != source.NodeUID || b.BootID != source.BootID || b.CollectorPodUID != source.CollectorPodUID || b.CollectorEpoch != source.CollectorEpoch {
		return false
	}
	program := make([]planning.BPFInstruction, len(r.Filter.Program))
	for i, ins := range r.Filter.Program {
		program[i] = planning.BPFInstruction{Code: ins.Code, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}
	}
	return b.ProgramDigest == [32]byte(compiler.FilterProgramDigest(program))
}

// The local source and signed expectation are independent of the permit fields.
func argumentRecordingMatches(e artifact.ContextExpectation, source targets.PacketSourceObservation, permit collector.ArgumentObservationPermit) bool {
	r, b := e.Recording, permit.Binding
	if !r.Valid() || r.Arguments == nil || e.NativeType != artifact.SyscallArgumentsArtifact || e.DataClass != "raw" || permit.Duration != time.Duration(r.DurationMillis)*time.Millisecond || permit.SessionUntil.After(e.Registration.WriteUntil) ||
		b.PodUID != e.PodUID || source.PodUID != e.PodUID || b.NodeUID != source.NodeUID || b.BootID != source.BootID || b.CollectorPodUID != source.CollectorPodUID || b.CollectorEpoch != source.CollectorEpoch ||
		(e.NodeUID != "" && e.NodeUID != source.NodeUID) || (e.NodeBootID != "" && e.NodeBootID != source.BootID) {
		return false
	}
	a, s := r.Arguments, r.Syscalls
	return b.ProgramDigest == [32]byte(a.ProgramDigest) && b.DefinitionDigest == [32]byte(a.DefinitionDigest) && b.AccountingRule == [32]byte(a.AccountingRule) &&
		permit.MaxProbeBytes == a.MaxProbeBytes && permit.MaxBytesPerEvent == a.MaxBytesPerEvent && permit.BytesPerSecond == a.MaxBytesPerSecond && permit.CaptureBuffers == a.CaptureBuffers && permit.EventsPerSecond == s.MaxEventsPerSecond && permit.MaxTrackedThreads == s.MaxTrackedThreads
}
