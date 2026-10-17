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
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/targets"
)

// ADR-171: the hub runs the API context runner. The region answers only these
// cluster-local operations for the exact verified work. Plaintext evidence and
// data keys never cross the exchange: acquisition captures, encrypts and
// uploads in the region and returns copy receipts only.
const (
	opResolvePod    = "resolve-pod"
	opReadProcess   = "read-process"
	opPrepareStart  = "prepare-start"
	opReadyStart    = "ready-start"
	opConsumeStart  = "consume-start"
	opPrepareOutput = "prepare-output"
	opAcquire       = "acquire-context"
	opComplete      = "complete-stored"
	opFinish        = "finish"
)

// Closed failure labels; raw errors never cross the exchange.
var operationFailures = []struct {
	label string
	err   error
}{
	{"preparation-uncertain", value.ErrPreparationUncertain},
	{"store-unconfirmed", evidence.ErrContextStoreUnconfirmed},
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
type acquireReply struct {
	Acquired time.Time
	Copies   artifact.Copies
}

// HubOperations implements the runner's cluster-local ports by sending one
// operation at a time over the exchange. It never carries native bytes.
type HubOperations struct {
	stream Stream
	ctx    context.Context
	mu     sync.Mutex
	seq    int
	broken bool
}

var (
	_ executionapp.APIProcessReader    = (*HubOperations)(nil)
	_ executionapp.APIStartPreparation = (*HubOperations)(nil)
	_ executionapp.StartJournal        = (*HubOperations)(nil)
	_ executionapp.ContextCollector    = (*HubOperations)(nil)
	_ evidence.ContextProducer         = (*HubOperations)(nil)
)

// call sends one operation and decodes its reply. A failure may still carry
// partial facts (an acquisition instant); they are decoded before the failure
// is returned. Any transport or framing defect breaks the exchange.
func (h *HubOperations) call(ctx context.Context, method string, in, out any) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.broken || ctx == nil || h.seq >= contracts.APIContextMaximumOperations {
		return value.ErrUnavailable
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
func (h *HubOperations) ReadAPIProcess(ctx context.Context) (value.APIProcessObservation, error) {
	var out value.APIProcessObservation
	err := h.call(ctx, opReadProcess, struct{}{}, &out)
	return out, err
}
func (h *HubOperations) PrepareStart(ctx context.Context, c value.PreparationCheck) (value.PreparedStart, error) {
	var out value.PreparedStart
	err := h.call(ctx, opPrepareStart, c, &out)
	return out, err
}
func (h *HubOperations) ReadyStart(ctx context.Context, r value.Request) (value.Disposition, error) {
	var out value.Disposition
	err := h.call(ctx, opReadyStart, r, &out)
	return out, err
}
func (h *HubOperations) ConsumeStart(ctx context.Context, r value.Request) (value.Disposition, error) {
	var out value.Disposition
	err := h.call(ctx, opConsumeStart, r, &out)
	return out, err
}

// LookupStart is not part of the runner's fresh execution path.
func (h *HubOperations) LookupStart(context.Context, value.Request) (value.Disposition, error) {
	return value.Disposition{}, value.ErrUnavailable
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
	_ evidence.StoredContextCloser = (*remoteOutput)(nil)
	_ evidence.ContextAcquirer     = (*remoteOutput)(nil)
)

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
	Local     executionapp.APIStartPreparation
	Starts    executionapp.StartJournal
	Output    evidence.ContextProducer
	Collector executionapp.ContextCollector
	// Source is this region's own connector source reader (ADR-178).
	Source fleetapp.ConnectorIdentitySourceReader
	Now    func() time.Time
}

func (l RegionalLocal) valid() bool {
	return l.Process != nil && l.Targets != nil && l.Local != nil && l.Starts != nil && l.Output != nil && l.Collector != nil && l.Now != nil
}

// regionalSession answers operations for exactly one verified work. Every
// operation is bound to that work's capture, attempt, target and digests;
// acquisition requires the committed start and the exact resolved pin.
type regionalSession struct {
	local RegionalLocal
	work  fleet.APIContextWork
	// process is this work's one complete process observation (ADR-173). Later
	// operations reuse it until its original deadline; it is never renewed.
	process  *value.APIProcessObservation
	resolved *targets.PodResolution
	prepared evidence.PreparedContext
	consumed *value.Disposition
	acquired bool
}

func (s *regionalSession) close() {
	if s.prepared != nil {
		s.prepared.Close()
		s.prepared = nil
	}
}

// binding ties a start to the verified work. The work's BudgetDigest is the
// capture budget, a different value from an execution binding's, so it is not
// compared; capture, attempt, cluster, Pod and plan scope are exact.
func (s *regionalSession) binding(b value.Binding) bool {
	w := s.work
	return b.CaptureID == w.CaptureID && b.AttemptID == w.AttemptID && b.ClusterID == w.Target.ClusterID && b.PodUID == w.Target.PodUID && b.ScopeDigest == w.ScopeDigest
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

// observed reports whether the work's observation still covers this start.
func (s *regionalSession) observed(b value.Binding) bool {
	return s.process != nil && s.process.Valid(s.local.Now()) && s.process.Matches(b)
}

func decodeOperationBody(body []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.More() {
		return value.ErrInvalid
	}
	return nil
}

func (s *regionalSession) handle(ctx context.Context, q contracts.APIContextOperation) (any, error) {
	l := s.local
	switch q.Method {
	case opResolvePod:
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
	case opReadProcess:
		return s.readProcess(ctx)
	case opPrepareStart:
		var c value.PreparationCheck
		if err := decodeOperationBody(q.Body, &c); err != nil {
			return nil, err
		}
		if !s.binding(c.Binding) {
			return nil, value.ErrDenied
		}
		if observed, ok := l.Local.(executionapp.ObservedAPIStartPreparation); ok && s.observed(c.Binding) {
			return observed.PrepareObservedStart(ctx, c, *s.process)
		}
		return l.Local.PrepareStart(ctx, c)
	case opReadyStart, opConsumeStart:
		var r value.Request
		if err := decodeOperationBody(q.Body, &r); err != nil {
			return nil, err
		}
		if !s.binding(r.Binding) {
			return nil, value.ErrDenied
		}
		if q.Method == opReadyStart {
			if observed, ok := l.Local.(executionapp.ObservedAPIStartPreparation); ok && s.observed(r.Binding) {
				return observed.ReadyObservedStart(ctx, r, *s.process)
			}
			return l.Local.ReadyStart(ctx, r)
		}
		if s.consumed != nil {
			return nil, value.ErrConflict
		}
		d, err := l.Starts.ConsumeStart(ctx, r)
		if err == nil {
			s.consumed = &d
		}
		return d, err
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
		return struct{}{}, nil
	case opAcquire:
		var r acquireRequest
		if err := decodeOperationBody(q.Body, &r); err != nil {
			return nil, err
		}
		d := s.consumed
		if s.acquired || s.prepared == nil || s.resolved == nil || d == nil || !d.MayStart || d.Phase != value.StartCommitted || r.Until.After(d.ValidUntil) || r.Pin != s.resolved.Pin {
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
	if err != nil || f.Kind != contracts.APIContextWorkFrame {
		clear(f.Payload)
		return contracts.ErrAPIContextProtocol
	}
	if current.Channel != receiver.Channel || !current.Valid(now()) {
		clear(f.Payload)
		return fleet.ErrDenied
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
