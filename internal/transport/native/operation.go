package native

import (
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"context"
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
	// A response window is served chunk by chunk (ADR-248): next is the next
	// native offset, pending the length of a chunk handed to the consumer
	// whose final-sink acknowledgement has not yet been submitted.
	next, pending   int64
	stream          Stream
	metadata        chan artifact.NativeDownloadMetadata
	projection      chan query.PodStatusProjection
	projectionScope query.ContextProjectionScope
	body            chan []byte
	action          chan nativeAction
	done            chan struct{}
	doneOnce        sync.Once
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
	if err != nil || nativeDecode(c.Operation, &o) != nil || !o.Equal(l.Operation) || c.Reference != nativeReference(o) || c.Kind != string(o.Kind) || c.Format != contracts.NativeExchangeFormat || c.Nonce != "" || c.ParentID != o.ParentID || c.Generation != o.Generation || c.LeaseSequence != l.Sequence || until.After(attachBound(l)) || !time.Now().Before(until) || !expected.Valid(o.SourceVersion) {
		return nil, artifact.ErrInvalid
	}
	if o.Kind == value.NativeResponse {
		limit := expected.Expectation.Type().DownloadLimit()
		if !value.UUID(c.WindowID) || c.Offset < 0 || c.Length < 1 || c.Offset > limit || c.Length > limit-c.Offset {
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
	if l, e = checked.restrict(gate); e != nil || until.After(attachBound(l)) {
		return nil, artifact.ErrDownloadUnavailable
	}
	ctx, cancel := context.WithDeadline(gate.Context(), until)
	result := &HubOperation{gate: gate, complete: complete, command: c, expected: cloned, delivery: delivery, ctx: ctx, cancel: cancel, metadata: make(chan artifact.NativeDownloadMetadata, 1), projection: make(chan query.PodStatusProjection, 1), projectionScope: projectionScope, body: make(chan []byte), action: make(chan nativeAction), done: make(chan struct{}), next: c.Offset}
	if o.Kind == value.NativeResponse && !result.matchChunk(delivery, c.Offset, min(nativeChunkBytes, c.Length)) {
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

// nativeChunkBytes is the response chunk of the private exchange: one data
// frame carries one delivery chunk (artifact.DeliveryBytes, equal to
// contracts.NativeDataBytes), so a window of at most RemoteNativeLimit is at
// most eight data frames and eight acknowledgements, within the per-stream
// frame cap. The worker and the transfer split a window identically.
const nativeChunkBytes = artifact.DeliveryBytes

// claimChunk admits the window's next chunk only: in order, exactly the
// expected length, and after the previous chunk's acknowledgement.
func (o *HubOperation) claimChunk(offset, length int64) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	end := o.command.Offset + o.command.Length
	if o.closed || o.pending != 0 || o.gate.Context().Err() != nil || offset != o.next || o.next >= end || length != min(nativeChunkBytes, end-o.next) {
		return false
	}
	o.used = true
	o.pending = length
	return true
}
func (o *HubOperation) ReadChunk(ctx context.Context, l artifact.DownloadDeliveryLease, offset, length int64) (evidence.NativeResponseChunk, error) {
	if o == nil || ctx == nil || !o.matchChunk(l, offset, length) || !o.claimChunk(offset, length) {
		return evidence.NativeResponseChunk{}, artifact.ErrDownloadUnavailable
	}
	select {
	case b := <-o.body:
		native, e := o.gate.Check(ctx)
		if e != nil || native.Sequence != l.Sequence {
			clear(b)
			o.cancel()
			if e != nil {
				return evidence.NativeResponseChunk{}, e
			}
			return evidence.NativeResponseChunk{}, step("chunk-sequence", artifact.ErrDownloadUnavailable)
		}
		o.mu.Lock()
		if o.closed || o.ctx.Err() != nil || ctx.Err() != nil {
			o.mu.Unlock()
			clear(b)
			o.cancel()
			return evidence.NativeResponseChunk{}, artifact.ErrDownloadUnavailable
		}
		o.delivery = l
		o.mu.Unlock()
		// The window's read work is reported once, with its first chunk.
		var work int64
		if offset == o.command.Offset {
			work = evidence.NativeWindowReadWork(o.expected.Expectation.Type())
		}
		return evidence.NativeResponseChunk{Bytes: b, ReadWork: work, FinalVerified: true, NativeUntil: native.Until}, nil
	case <-ctx.Done():
		o.cancel()
		return evidence.NativeResponseChunk{}, ctx.Err()
	case <-o.ctx.Done():
		return evidence.NativeResponseChunk{}, artifact.ErrDownloadUnavailable
	}
}

// matchChunk binds a chunk to the operation's exact original delivery lease
// and window; the chunk lies inside the window.
func (o *HubOperation) matchChunk(l artifact.DownloadDeliveryLease, offset, length int64) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	c := o.command
	return c.Kind == "read-context-response" && evidence.SameNativeWindow(l, o.delivery) && l.Sequence >= o.delivery.Sequence && l.Valid(time.Now()) && l.ResponseID == c.ParentID && l.WindowID == c.WindowID && l.Generation == c.Generation && l.Sequence >= c.LeaseSequence && l.Offset == c.Offset && l.Length == c.Length && length >= 1 && offset >= c.Offset && length <= c.Offset+c.Length-offset && l.Authority.Scope.Version == o.expectedVersion() && l.Allows(offset, length, time.Now())
}
func (o *HubOperation) expectedVersion() artifact.Digest {
	return evidence.ContextCopiesDigest(o.expected.Copies)
}
func (o *HubOperation) AcknowledgeNativeChunk(ctx context.Context, l artifact.DownloadDeliveryLease, offset, length int64) error {
	if o == nil || ctx == nil || ctx.Err() != nil || !o.matchChunk(l, offset, length) {
		return artifact.ErrDownloadUnavailable
	}
	o.mu.Lock()
	ok := !o.closed && o.ctx.Err() == nil && ctx.Err() == nil && l.Sequence == o.delivery.Sequence && o.pending == length && offset == o.next
	if ok {
		o.pending = 0
		o.next += length
	}
	o.mu.Unlock()
	if !ok {
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
	// The facts follow the hub's own expectation: type filename, format,
	// coverage and size bound, the copies ETag and the registered dates.
	if !evidence.ValidNativeSourceMetadata(o.expected, native) {
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
		return o.serveResponse(work, s, &stage)
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
	return contracts.ErrNativeProtocol
}

// serveResponse relays one window: per chunk one data frame of exactly the
// chunk length, handed to the consumer, then its final-sink acknowledgement.
// After the last chunk the worker closes and the operation finishes; a single
// chunk (pod status) is exactly the historical frame sequence.
func (o *HubOperation) serveResponse(work context.Context, s Stream, stage *string) (err error) {
	end := o.command.Offset + o.command.Length
	for at := o.command.Offset; at < end; {
		n := min(nativeChunkBytes, end-at)
		f, e := s.Receive(work)
		if e != nil {
			return e
		}
		if f.Kind != contracts.NativeDataFrame || int64(len(f.Payload)) != n {
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
		*stage = "consumer"
		var action nativeAction
		select {
		case action = <-o.action:
		case <-work.Done():
			return work.Err()
		}
		*stage = "close"
		if action.phase != "delivered" || action.n != n {
			action.done <- contracts.ErrNativeProtocol
			return contracts.ErrNativeProtocol
		}
		e = sendControl(work, s, contracts.NativeAcknowledgeFrame, ack(o.command, "delivered", n))
		if at += n; at < end {
			action.done <- e
			if e != nil {
				return e
			}
			*stage = "result"
			continue
		}
		defer func() { action.done <- err }()
		if e != nil {
			return e
		}
		f, e = s.Receive(work)
		if e != nil {
			return e
		}
		if err = exactAck(f, contracts.NativeDoneFrame, o.command, "closed", 0); err != nil {
			return err
		}
		return o.finish(work, s, "joined")
	}
	return contracts.ErrNativeProtocol
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
