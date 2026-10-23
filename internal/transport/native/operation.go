package native

import (
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"context"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"
)

type nativeAction struct {
	phase string
	n     int64
	done  chan error
}

// HubOperation belongs to one actual hub request/response, installed in the
// process router before its SQL locator is published. It holds no unwrap key or
// payload queue. A content buffer is handed to exactly one response consumer.
type HubOperation struct {
	gate                             *evidence.NativeFrameGate
	complete                         evidence.NativeCompletion
	command                          contracts.NativeCommand
	expected                         evidence.NativeContextSource
	delivery                         artifact.DownloadDeliveryLease
	ctx                              context.Context
	cancel                           context.CancelFunc
	mu                               sync.Mutex
	reserved, attached, closed, used bool
	stream                           Stream
	metadata                         chan artifact.NativeDownloadMetadata
	projection                       chan query.PodStatusProjection
	projectionScope                  query.ContextProjectionScope
	body                             chan []byte
	action                           chan nativeAction
	done                             chan struct{}
	doneOnce                         sync.Once
}

func NewHubOperation(gate *evidence.NativeFrameGate, c contracts.NativeCommand, expected evidence.NativeContextSource, complete evidence.NativeCompletion) (*HubOperation, error) {
	if c.Kind == string(value.NativeResponse) {
		return nil, artifact.ErrInvalid
	}
	return newHubOperation(gate, c, expected, artifact.DownloadDeliveryLease{}, complete)
}

// NewHubResponseOperation pins the complete original delivery lease locally.
// Neither the worker command nor a matching range can substitute another owner,
// scope or current authority observation when acknowledging a final sink write.
func NewHubResponseOperation(gate *evidence.NativeFrameGate, c contracts.NativeCommand, expected evidence.NativeContextSource, delivery artifact.DownloadDeliveryLease, complete evidence.NativeCompletion) (*HubOperation, error) {
	if c.Kind != string(value.NativeResponse) || !delivery.Valid(time.Now()) {
		return nil, artifact.ErrInvalid
	}
	return newHubOperation(gate, c, expected, delivery, complete)
}
func newHubOperation(gate *evidence.NativeFrameGate, c contracts.NativeCommand, expected evidence.NativeContextSource, delivery artifact.DownloadDeliveryLease, complete evidence.NativeCompletion) (*HubOperation, error) {
	if gate == nil || complete == nil {
		return nil, artifact.ErrInvalid
	}
	checked, e := checkNativeAdmission(gate.Context(), gate)
	if e != nil {
		return nil, e
	}
	return newHubOperationChecked(gate, checked, c, expected, delivery, complete)
}

// Only synchronous native-package callers may transfer an already performed
// check. Public constructors above always perform their own full current check.
func newHubOperationChecked(gate *evidence.NativeFrameGate, checked *checkedNativeAdmission, c contracts.NativeCommand, expected evidence.NativeContextSource, delivery artifact.DownloadDeliveryLease, complete evidence.NativeCompletion) (*HubOperation, error) {
	if gate == nil || complete == nil {
		return nil, artifact.ErrInvalid
	}
	l, e := checked.take(gate)
	if e != nil {
		return nil, e
	}
	var o value.NativeOperation
	until, err := time.Parse(time.RFC3339Nano, c.Until)
	if err != nil || nativeDecode(c.Operation, &o) != nil || !o.Equal(l.Operation) || c.Reference != nativeReference(o) || c.Kind != string(o.Kind) || c.Format != contracts.NativeExchangeFormat || c.Nonce != "" || c.ParentID != o.ParentID || c.Generation != o.Generation || c.LeaseSequence != l.Sequence || until.After(l.Until) || !time.Now().Before(until) || !expected.Valid(o.SourceVersion) {
		return nil, artifact.ErrInvalid
	}
	if o.Kind == value.NativeResponse {
		if !value.UUID(c.WindowID) || c.Offset < 0 || c.Length < 1 || c.Offset > artifact.MaxContextBytes || c.Length > artifact.MaxContextBytes-c.Offset {
			return nil, artifact.ErrInvalid
		}
	} else if c.WindowID != "" || c.Offset != 0 || c.Length != 0 {
		return nil, artifact.ErrInvalid
	}
	// Snapshot mutable wire/source slices before registration; callers cannot
	// replace a source after reviewing/admitting the operation.
	c.Operation = append(json.RawMessage(nil), c.Operation...)
	c.Source = append(json.RawMessage(nil), c.Source...)
	c.Projection = append(json.RawMessage(nil), c.Projection...)
	var projectionScope query.ContextProjectionScope
	if o.Kind == value.NativeProjection {
		if nativeDecode(c.Projection, &projectionScope) != nil || !projectionScope.Valid() || projectionScope.Version != o.SourceVersion {
			return nil, artifact.ErrInvalid
		}
	} else if len(c.Projection) != 0 {
		return nil, artifact.ErrInvalid
	}
	encoded, e := json.Marshal(expected)
	if e != nil {
		return nil, e
	}
	if o.Kind == value.NativeObserve {
		if string(c.Source) != "null" {
			return nil, artifact.ErrInvalid
		}
	} else if string(c.Source) != string(encoded) {
		return nil, artifact.ErrInvalid
	}
	var cloned evidence.NativeContextSource
	if json.Unmarshal(encoded, &cloned) != nil {
		return nil, artifact.ErrInvalid
	}
	if l, e = checked.restrict(gate); e != nil || until.After(l.Until) {
		return nil, artifact.ErrDownloadUnavailable
	}
	ctx, cancel := context.WithDeadline(gate.Context(), until)
	result := &HubOperation{gate: gate, complete: complete, command: c, expected: cloned, delivery: delivery, ctx: ctx, cancel: cancel, metadata: make(chan artifact.NativeDownloadMetadata, 1), projection: make(chan query.PodStatusProjection, 1), projectionScope: projectionScope, body: make(chan []byte), action: make(chan nativeAction), done: make(chan struct{})}
	if o.Kind == value.NativeResponse && !result.matchChunk(delivery, c.Offset, c.Length) {
		cancel()
		return nil, artifact.ErrInvalid
	}
	return result, nil
}
func (o *HubOperation) Gate() *evidence.NativeFrameGate { return o.gate }
func (o *HubOperation) Context() context.Context        { return o.ctx }
func (o *HubOperation) Close() error {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	o.closed = true
	o.cancel()
	s := o.stream
	attached := o.attached
	o.mu.Unlock()
	if s != nil {
		_ = s.Close()
	}
	o.gate.Close()
	if !attached {
		o.doneOnce.Do(func() { close(o.done) })
	}
	<-o.done
	return o.gate.Wait(context.Background())
}
func (o *HubOperation) claim() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || o.used || o.gate.Context().Err() != nil {
		return false
	}
	o.used = true
	return true
}
func (o *HubOperation) Prepared(ctx context.Context) (artifact.NativeDownloadMetadata, error) {
	if ctx == nil || o == nil || !o.claim() {
		return artifact.NativeDownloadMetadata{}, artifact.ErrDownloadUnavailable
	}
	select {
	case m := <-o.metadata:
		if _, e := o.gate.Check(ctx); e != nil {
			return artifact.NativeDownloadMetadata{}, e
		}
		if o.command.Kind == "observe-prepared-context" {
			if e := o.submit(ctx, "observed", 0); e != nil {
				return artifact.NativeDownloadMetadata{}, e
			}
		}
		return m, nil
	case <-ctx.Done():
		o.cancel()
		return artifact.NativeDownloadMetadata{}, ctx.Err()
	case <-o.ctx.Done():
		select {
		case m := <-o.metadata:
			if _, e := o.gate.Check(ctx); e != nil {
				return artifact.NativeDownloadMetadata{}, e
			}
			if o.command.Kind == "observe-prepared-context" {
				if e := o.submit(ctx, "observed", 0); e != nil {
					return artifact.NativeDownloadMetadata{}, e
				}
			}
			return m, nil
		default:
			return artifact.NativeDownloadMetadata{}, artifact.ErrDownloadUnavailable
		}
	}
}
func (o *HubOperation) submit(ctx context.Context, phase string, n int64) error {
	if ctx == nil || o == nil {
		return artifact.ErrInvalid
	}
	if _, e := o.gate.Check(ctx); e != nil {
		return e
	}
	a := nativeAction{phase, n, make(chan error, 1)}
	select {
	case o.action <- a:
	case <-ctx.Done():
		o.cancel()
		return ctx.Err()
	case <-o.ctx.Done():
		return artifact.ErrDownloadUnavailable
	}
	select {
	case e := <-a.done:
		return e
	case <-ctx.Done():
		o.cancel()
		return ctx.Err()
	case <-o.ctx.Done():
		select {
		case e := <-a.done:
			return e
		default:
			return artifact.ErrDownloadUnavailable
		}
	}
}
func (o *HubOperation) Commit(ctx context.Context) error {
	if o == nil || o.command.Kind != "prepare-context" {
		return artifact.ErrInvalid
	}
	return o.submit(ctx, "prepared", 0)
}
func (o *HubOperation) ReadChunk(ctx context.Context, l artifact.DownloadDeliveryLease, offset, length int64) (evidence.NativeResponseChunk, error) {
	if o == nil || ctx == nil || !o.matchChunk(l, offset, length) || !o.claim() {
		return evidence.NativeResponseChunk{}, artifact.ErrDownloadUnavailable
	}
	select {
	case b := <-o.body:
		if _, e := o.gate.Check(ctx); e != nil {
			clear(b)
			return evidence.NativeResponseChunk{}, e
		}
		return evidence.NativeResponseChunk{Bytes: b, ReadWork: evidence.ContextDownloadReadWork, FinalVerified: true}, nil
	case <-ctx.Done():
		o.cancel()
		return evidence.NativeResponseChunk{}, ctx.Err()
	case <-o.ctx.Done():
		return evidence.NativeResponseChunk{}, artifact.ErrDownloadUnavailable
	}
}
func (o *HubOperation) matchChunk(l artifact.DownloadDeliveryLease, offset, length int64) bool {
	return o.command.Kind == "read-context-response" && l == o.delivery && l.Valid(time.Now()) && l.ResponseID == o.command.ParentID && l.WindowID == o.command.WindowID && l.Generation == o.command.Generation && l.Sequence == o.command.LeaseSequence && offset == o.command.Offset && length == o.command.Length && l.Authority.Scope.Version == o.expectedVersion() && l.Allows(offset, length, time.Now())
}
func (o *HubOperation) expectedVersion() artifact.Digest {
	return evidence.ContextCopiesDigest(o.expected.Copies)
}
func (o *HubOperation) AcknowledgeNativeChunk(ctx context.Context, l artifact.DownloadDeliveryLease, offset, length int64) error {
	if o == nil || !o.matchChunk(l, offset, length) {
		return artifact.ErrDownloadUnavailable
	}
	return o.submit(ctx, "delivered", length)
}
func (o *HubOperation) readMetadata(ctx context.Context, s Stream) (artifact.NativeDownloadMetadata, error) {
	var zero artifact.NativeDownloadMetadata
	f, e := s.Receive(ctx)
	if e != nil {
		return zero, e
	}
	defer clear(f.Payload)
	m, e := contracts.DecodeNativeMetadata(f.Payload)
	if e != nil || f.Kind != contracts.NativeMetadataFrame || m.Format != o.command.Format || m.Reference != o.command.Reference || m.Nonce != o.command.Nonce {
		return zero, contracts.ErrNativeProtocol
	}
	var native artifact.NativeDownloadMetadata
	if nativeDecode(m.Metadata, &native) != nil {
		return zero, contracts.ErrNativeProtocol
	}
	version := o.expectedVersion()
	expected := o.expected.Expectation.Registration
	if native.Filename != "artifact-"+expected.Location.ArtifactID+".json" || native.Format != artifact.ContextFormat || native.ETag != `"v1-`+hex.EncodeToString(version[:])+`"` || native.Size < 1 || native.Size > artifact.MaxContextBytes || native.SHA256 == (artifact.Digest{}) || !native.ReadUntil.Equal(expected.ExpiresAt) || !native.DeleteBy.Equal(expected.DeleteBy) || native.Coverage != "Selected pod-status fields only; no logs, messages or workload configuration." {
		return zero, contracts.ErrNativeProtocol
	}
	return native, nil
}

// nativeCompletionProof never crosses the wire or application boundary. Only
// this successful exact close can enable the hub's zero-byte terminal send.
type nativeCompletionProof struct {
	gate         *evidence.NativeFrameGate
	lease        value.NativeLease
	nonce, phase string
}

func (o *HubOperation) finish(ctx context.Context, s Stream, phase string) error {
	lease, err := o.gate.Check(ctx)
	if err != nil {
		return step("gate", err)
	}
	call, stop := context.WithDeadline(ctx, lease.Until)
	defer stop()
	if err = o.complete(call, lease); err != nil {
		return step("complete", err)
	}
	if call.Err() != nil || o.ctx.Err() != nil || !lease.Valid(time.Now()) {
		return step("expired", artifact.ErrDownloadExpired)
	}
	terminal, ok := s.(interface {
		sendCompleted(context.Context, contracts.NativeFrame, nativeCompletionProof) error
	})
	if !ok {
		return step("terminal-stream", contracts.ErrNativeProtocol)
	}
	payload, err := json.Marshal(ack(o.command, phase, 0))
	if err != nil {
		return err
	}
	defer clear(payload)
	return step("send-done", terminal.sendCompleted(call, contracts.NativeFrame{Kind: contracts.NativeDoneFrame, Payload: payload}, nativeCompletionProof{o.gate, lease, o.command.Nonce, phase}))
}

func (o *HubOperation) Serve(ctx context.Context, s Stream) (err error) {
	// The closed stage of a failed conversation, for the operator report only.
	stage := "attach"
	defer func() { err = step(stage, err) }()
	o.mu.Lock()
	if !o.reserved || o.attached || o.closed || s == nil {
		o.mu.Unlock()
		return contracts.ErrNativeProtocol
	}
	o.attached = true
	o.stream = s
	o.mu.Unlock()
	defer func() { o.cancel(); _ = s.Close(); o.doneOnce.Do(func() { close(o.done) }) }()
	work, cancel := context.WithCancel(o.ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, cancel)
	defer stop()
	stage = "command"
	if e := sendControl(work, s, contracts.NativeCommandFrame, o.command); e != nil {
		return e
	}
	stage = "result"
	if o.command.Kind == "read-context-response" {
		f, e := s.Receive(work)
		if e != nil {
			return e
		}
		if f.Kind != contracts.NativeDataFrame || int64(len(f.Payload)) != o.command.Length {
			clear(f.Payload)
			return contracts.ErrNativeProtocol
		}
		// Ownership transfers to the final sink's caller. It clears only after its
		// own write has joined; cancellation here must not race with that write.
		select {
		case o.body <- f.Payload:
			f.Payload = nil
		case <-work.Done():
			clear(f.Payload)
			return work.Err()
		}
	} else if o.command.Kind == string(value.NativeProjection) {
		p, e := o.readProjection(work, s)
		if e != nil {
			return e
		}
		select {
		case o.projection <- p:
		case <-work.Done():
			return work.Err()
		}
	} else {
		m, e := o.readMetadata(work, s)
		if e != nil {
			return e
		}
		select {
		case o.metadata <- m:
		case <-work.Done():
			return work.Err()
		}
	}
	stage = "consumer"
	var action nativeAction
	select {
	case action = <-o.action:
	case <-work.Done():
		return work.Err()
	}
	defer func() { action.done <- err }()
	stage = "close"
	// Do not close a successful observation before the original hub caller has
	// consumed it under the still-current gate. No extra wire authority is
	// introduced: this local acknowledgement only permits normal stream close.
	if o.command.Kind == "observe-prepared-context" {
		if action.phase != "observed" || action.n != 0 {
			return contracts.ErrNativeProtocol
		}
		return o.finish(work, s, "closed")
	}
	if o.command.Kind == "prepare-context" {
		if action.phase != "prepared" || action.n != 0 {
			return contracts.ErrNativeProtocol
		}
		if err = sendControl(work, s, contracts.NativeCommitFrame, ack(o.command, "prepared", 0)); err != nil {
			return err
		}
		f, e := s.Receive(work)
		if e != nil {
			return e
		}
		if err = exactAck(f, contracts.NativeAcknowledgeFrame, o.command, "prepared", 0); err != nil {
			return err
		}
		return o.finish(work, s, "closed")
	}
	if o.command.Kind == string(value.NativeProjection) {
		if action.phase != "approved" || action.n != 0 {
			return step("action", contracts.ErrNativeProtocol)
		}
		if err = sendControl(work, s, contracts.NativeAcknowledgeFrame, ack(o.command, "approved", 0)); err != nil {
			return step("ack", err)
		}
		f, e := s.Receive(work)
		if e != nil {
			return step("worker-closed", e)
		}
		if err = exactAck(f, contracts.NativeDoneFrame, o.command, "closed", 0); err != nil {
			return step("worker-closed-frame", err)
		}
		return step("finish", o.finish(work, s, "joined"))
	}
	if action.phase != "delivered" || action.n != o.command.Length {
		return contracts.ErrNativeProtocol
	}
	if err = sendControl(work, s, contracts.NativeAcknowledgeFrame, ack(o.command, "delivered", action.n)); err != nil {
		return err
	}
	f, e := s.Receive(work)
	if e != nil {
		return e
	}
	if err = exactAck(f, contracts.NativeDoneFrame, o.command, "closed", 0); err != nil {
		return err
	}
	return o.finish(work, s, "joined")
}

// Attach binds the worker's fresh nonce only after the ingress independently
// authenticates actual connector, origin and this exact stored operation. It
// cannot create work; duplicate attachment cannot replace a live stream.
func (o *HubOperation) Attach(ctx context.Context, h contracts.NativeHello) (Conversation, error) {
	if o == nil || ctx == nil || h.Format != contracts.NativeExchangeFormat || !contracts.ValidWorkerNonce(h.Nonce) || h.Reference != o.command.Reference {
		return nil, contracts.ErrNativeProtocol
	}
	checked, err := checkNativeAdmission(ctx, o.gate)
	if err != nil {
		return nil, err
	}
	return o.attachChecked(checked, h)
}

func (o *HubOperation) attachChecked(checked *checkedNativeAdmission, h contracts.NativeHello) (Conversation, error) {
	if o == nil || h.Format != contracts.NativeExchangeFormat || !contracts.ValidWorkerNonce(h.Nonce) || h.Reference != o.command.Reference {
		return nil, contracts.ErrNativeProtocol
	}
	if _, err := checked.take(o.gate); err != nil {
		return nil, err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.reserved || o.attached || o.closed || o.ctx.Err() != nil {
		return nil, contracts.ErrNativeProtocol
	}
	if _, err := checked.restrict(o.gate); err != nil {
		return nil, err
	}
	o.reserved = true
	o.command.Nonce = h.Nonce
	return o, nil
}
