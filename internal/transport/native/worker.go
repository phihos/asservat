package native

import (
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"time"
)

func nativeDecode(b []byte, v any) error {
	return nativeDecodeBounded(b, v, contracts.NativeControlBytes)
}
func nativeDecodeBounded(b []byte, v any, limit int) error {
	if len(b) < 1 || len(b) > limit {
		return contracts.ErrNativeProtocol
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		return contracts.ErrNativeProtocol
	}
	canonical, e := json.Marshal(v)
	defer clear(canonical)
	if e != nil || !bytes.Equal(canonical, b) {
		return contracts.ErrNativeProtocol
	}
	return nil
}
func nativeReference(o value.NativeOperation) contracts.NativeReference {
	r := o.Reference
	return contracts.NativeReference{InstallationID: r.InstallationID, SessionID: r.SessionID, QueryID: r.QueryID, WorkerID: r.WorkerID, OperationID: r.OperationID, Fence: r.Fence}
}
func nativeControl(kind contracts.NativeFrameKind, v any) (contracts.NativeFrame, error) {
	limit := contracts.NativeControlBytes
	if kind == contracts.NativeCommandFrame {
		limit = contracts.NativeCommandBytes
	}
	b, e := json.Marshal(v)
	if e != nil || len(b) > limit {
		clear(b)
		return contracts.NativeFrame{}, contracts.ErrNativeProtocol
	}
	return contracts.NativeFrame{Kind: kind, Payload: b}, nil
}
func sendControl(ctx context.Context, s Stream, kind contracts.NativeFrameKind, v any) error {
	f, e := nativeControl(kind, v)
	if e != nil {
		return e
	}
	defer clear(f.Payload)
	return s.Send(ctx, f)
}
func commandValues(c contracts.NativeCommand, h contracts.NativeHello, target value.WorkerCredentialTarget, key artifact.Digest, now time.Time) (value.NativeOperation, evidence.NativeContextSource, time.Time, error) {
	var o value.NativeOperation
	var source evidence.NativeContextSource
	until, e := time.Parse(time.RFC3339Nano, c.Until)
	if e != nil || nativeDecode(c.Operation, &o) != nil || !o.Valid() || c.Format != contracts.NativeExchangeFormat || c.Nonce != h.Nonce || c.Reference != nativeReference(o) || o.Reference.InstallationID != target.InstallationID || o.Reference.Parent() != target.Parent() || o.Reference.WorkerID != target.WorkerID || o.WorkerPodUID != target.PodUID || o.WorkerPublicKey != key || o.Until.After(target.RunUntil) || c.Kind != string(o.Kind) || c.ParentID != o.ParentID || c.Generation != o.Generation || !now.Before(until) || until.After(now.Add(value.NativeConversationWindow(o.Kind))) || until.After(o.Until) {
		return o, source, until, contracts.ErrNativeProtocol
	}
	if o.Kind != value.NativeProjection && len(c.Projection) != 0 {
		return o, source, until, contracts.ErrNativeProtocol
	}
	switch o.Kind {
	case value.NativeProjection:
		var scope query.ContextProjectionScope
		if c.WindowID != "" || c.LeaseSequence != 1 || c.Offset != 0 || c.Length != 0 || nativeDecode(c.Projection, &scope) != nil || !scope.Valid() || scope.Version != o.SourceVersion || nativeDecodeBounded(c.Source, &source, contracts.NativeCommandBytes) != nil || !source.Valid(o.SourceVersion) {
			return o, source, until, contracts.ErrNativeProtocol
		}
	case value.NativePrepare:
		if c.WindowID != "" || c.LeaseSequence != 1 || c.Offset != 0 || c.Length != 0 || nativeDecodeBounded(c.Source, &source, contracts.NativeCommandBytes) != nil || !source.Valid(o.SourceVersion) {
			return o, source, until, contracts.ErrNativeProtocol
		}
	case value.NativeObserve:
		if c.WindowID != "" || c.LeaseSequence != 1 || c.Offset != 0 || c.Length != 0 || !bytes.Equal(c.Source, []byte("null")) {
			return o, source, until, contracts.ErrNativeProtocol
		}
	case value.NativeResponse:
		if !value.UUID(c.WindowID) || c.LeaseSequence < 1 || c.Offset < 0 || c.Length < 1 || nativeDecodeBounded(c.Source, &source, contracts.NativeCommandBytes) != nil || !source.Valid(o.SourceVersion) {
			return o, source, until, contracts.ErrNativeProtocol
		}
		if limit := source.Expectation.Type().DownloadLimit(); c.Offset > limit || c.Length > limit-c.Offset {
			return o, source, until, contracts.ErrNativeProtocol
		}
	}
	return o, source, until, nil
}
func exactAck(f contracts.NativeFrame, kind contracts.NativeFrameKind, c contracts.NativeCommand, phase string, n int64) error {
	defer clear(f.Payload)
	a, e := contracts.DecodeNativeAcknowledge(f.Payload)
	if e != nil || f.Kind != kind || a.Format != c.Format || a.Reference != c.Reference || a.Nonce != c.Nonce || a.Phase != phase || a.Bytes != n {
		return contracts.ErrNativeProtocol
	}
	return nil
}
func ack(c contracts.NativeCommand, phase string, n int64) contracts.NativeAcknowledge {
	return contracts.NativeAcknowledge{Format: c.Format, Reference: c.Reference, Nonce: c.Nonce, Phase: phase, Bytes: n}
}

// RunWorker owns one already authenticated outbound native stream. It cannot
// acquire work from a certificate alone: only the exact stored operation's
// command can invoke the separately scoped regional reader. The worker keeps
// the process result owner between streams, never a human CurrentIdentity.
func RunWorker(ctx context.Context, s Stream, h contracts.NativeHello, target value.WorkerCredentialTarget, key artifact.Digest, result *evidence.RegionalContextResult) error {
	_, err := RunWorkerConversation(ctx, s, h, target, key, result)
	return err
}

// RunWorkerConversation returns Joined only after the original RunWorker body,
// buffers, receive goroutine and stream Close have joined. Every other result
// remains Uncertain; it must not select newly dispatchable work automatically.
func RunWorkerConversation(ctx context.Context, s Stream, h contracts.NativeHello, target value.WorkerCredentialTarget, key artifact.Digest, result *evidence.RegionalContextResult) (contracts.NativeConversationResult, error) {
	disposition := contracts.NativeConversationResult{State: contracts.NativeUncertain}
	err := runWorker(ctx, s, h, target, key, result, &disposition)
	if err == nil {
		disposition.State = contracts.NativeJoined
	}
	return disposition, err
}
func runWorker(ctx context.Context, s Stream, h contracts.NativeHello, target value.WorkerCredentialTarget, key artifact.Digest, result *evidence.RegionalContextResult, disposition *contracts.NativeConversationResult) (err error) {
	// The closed stage of a failed conversation, for the worker's stop report.
	stage := "command"
	defer func() { err = step(stage, err) }()
	if ctx == nil || s == nil || result == nil || !target.Valid() || key == (artifact.Digest{}) || h.Reference.InstallationID != target.InstallationID || value.AcquisitionParentFor(h.Reference.SessionID, h.Reference.QueryID) != target.Parent() || h.Reference.WorkerID != target.WorkerID || h.Reference.OperationID != "" || h.Reference.Fence != 0 || len(h.WorkerLeaf) != 0 {
		return contracts.ErrNativeProtocol
	}
	defer s.Close()
	first, stop := context.WithTimeout(ctx, 5*time.Second)
	f, e := s.Receive(first)
	stop()
	if e != nil {
		return e
	}
	c, e := contracts.DecodeNativeCommand(f.Payload)
	clear(f.Payload)
	if e != nil || f.Kind != contracts.NativeCommandFrame {
		return contracts.ErrNativeProtocol
	}
	// Record only the decoded exact routing reference; malformed/foreign command
	// failure remains uncertain and never grants reconnection to that reference.
	disposition.Reference = c.Reference
	o, source, until, e := commandValues(c, h, target, key, time.Now())
	var approvedScope query.ContextProjectionScope
	if e == nil && o.Kind == value.NativeProjection {
		e = nativeDecode(c.Projection, &approvedScope)
	}
	clear(c.Projection)
	c.Projection = nil
	clear(c.Source)
	clear(c.Operation)
	c.Source, c.Operation = nil, nil
	if e != nil {
		return e
	}
	work, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	type reply struct {
		frame contracts.NativeFrame
		err   error
	}
	received := make(chan reply, 1)
	// Reading the next frame concurrently makes actual owner EOF/revocation cancel
	// a blocked S3/key read immediately. One bounded control frame may be pending.
	receive := func() {
		go func() {
			f, e := s.Receive(work)
			if e != nil {
				cancel()
			}
			received <- reply{f, e}
		}()
	}
	receive()
	joined := false
	defer func() {
		cancel()
		s.Close()
		if !joined {
			r := <-received
			clear(r.frame.Payload)
		}
	}()
	take := func(kind contracts.NativeFrameKind, phase string, n int64) error {
		stage = "acknowledge"
		r := <-received
		joined = true
		if r.err != nil {
			clear(r.frame.Payload)
			return r.err
		}
		return exactAck(r.frame, kind, c, phase, n)
	}
	stage = "read"
	switch o.Kind {
	case value.NativeProjection:
		projection, e := result.ReadApproved(work, o, source, approvedScope)
		if e != nil {
			return e
		}
		// Result write, acknowledgement and close, for the worker's read report.
		framesStarted := time.Now()
		defer func() { auditapp.MarkStep(ctx, "frames", framesStarted) }()
		b, e := json.Marshal(projection)
		projection = query.PodStatusProjection{}
		if e != nil || len(b) > query.ContextResultBytes {
			clear(b)
			return contracts.ErrNativeProtocol
		}
		stage = "result"
		e = sendControl(work, s, contracts.NativeMetadataFrame, contracts.NativeMetadata{Format: c.Format, Reference: c.Reference, Nonce: c.Nonce, Metadata: b})
		clear(b)
		if e != nil {
			return e
		}
		if e = take(contracts.NativeAcknowledgeFrame, "approved", 0); e != nil {
			return e
		}
		stage = "close"
		if e = sendControl(work, s, contracts.NativeDoneFrame, ack(c, "closed", 0)); e != nil {
			return e
		}
		f, e = s.Receive(work)
		if e != nil {
			return e
		}
		return exactAck(f, contracts.NativeDoneFrame, c, "joined", 0)
	case value.NativePrepare:
		m, e := result.Prepare(work, o, source)
		if e != nil {
			return e
		}
		b, e := json.Marshal(m)
		if e != nil {
			return e
		}
		stage = "result"
		e = sendControl(work, s, contracts.NativeMetadataFrame, contracts.NativeMetadata{Format: c.Format, Reference: c.Reference, Nonce: c.Nonce, Metadata: b})
		clear(b)
		if e != nil {
			return e
		}
		if e = take(contracts.NativeCommitFrame, "prepared", 0); e != nil {
			return e
		}
		stage = "commit"
		if e = result.Commit(work, o); e != nil {
			return e
		}
		stage = "close"
		if e = sendControl(work, s, contracts.NativeAcknowledgeFrame, ack(c, "prepared", 0)); e != nil {
			return e
		}
		f, e = s.Receive(work)
		if e != nil {
			return e
		}
		return exactAck(f, contracts.NativeDoneFrame, c, "closed", 0)
	case value.NativeObserve:
		m, e := result.Observe(work, o)
		if e != nil {
			return e
		}
		b, e := json.Marshal(m)
		if e != nil {
			return e
		}
		stage = "result"
		e = sendControl(work, s, contracts.NativeMetadataFrame, contracts.NativeMetadata{Format: c.Format, Reference: c.Reference, Nonce: c.Nonce, Metadata: b})
		clear(b)
		if e != nil {
			return e
		}
		return take(contracts.NativeDoneFrame, "closed", 0)
	case value.NativeResponse:
		// One data frame per chunk, each acknowledged by the hub's final sink
		// before the next is read (ADR-248); a single chunk is the historical
		// frame sequence. The receiver restarts after each non-final ack.
		end := c.Offset + c.Length
		at := c.Offset
		e := result.ReadWindow(work, o, source, c.WindowID, c.Offset, c.Length, func(call context.Context, chunk []byte) error {
			stage = "result"
			if e := s.Send(call, contracts.NativeFrame{Kind: contracts.NativeDataFrame, Payload: chunk}); e != nil {
				return e
			}
			if e := take(contracts.NativeAcknowledgeFrame, "delivered", int64(len(chunk))); e != nil {
				return e
			}
			if at += int64(len(chunk)); at < end {
				joined = false
				receive()
			}
			stage = "read"
			return nil
		})
		if e == nil && at != end {
			e = contracts.ErrNativeProtocol
		}
		if e != nil {
			return e
		}
		stage = "close"
		if e = sendControl(work, s, contracts.NativeDoneFrame, ack(c, "closed", 0)); e != nil {
			return e
		}
		// The client body is live/non-replayable. Keep it open until the hub has
		// observed our cleared-buffer acknowledgement; cancelling immediately after
		// a pipe write can reset HTTP/2 before the peer consumes that frame.
		f, e := s.Receive(work)
		if e != nil {
			return e
		}
		return exactAck(f, contracts.NativeDoneFrame, c, "joined", 0)
	default:
		return contracts.ErrNativeProtocol
	}
}
