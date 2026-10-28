package contextstart

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"

	"asservat.local/asservat/internal/contracts"
	execution "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"golang.org/x/net/http2"
)

// StreamInterruption contains only closed diagnostic codes. It cannot carry a
// peer, payload, source value, arbitrary error text or authority. The first
// deciding interruption wins before cancellation can recursively close peers.
type StreamInterruption struct {
	stage  streamStage
	reason streamReason
}

type streamStage uint8

const (
	streamNoStage streamStage = iota
	streamOwner
	streamClose
	streamSendAdmission
	streamReceiveAdmission
	streamSendCall
	streamReceiveCall
	streamSendPeer
	streamReceivePeer
	streamSendBound
	streamReceiveBound
	streamSendDeadline
	streamReceiveDeadline
	streamWrite
	streamFlush
	streamRead
	streamSendResult
	streamReceiveResult
	streamPassiveCall
	streamPassiveDeadline
	streamPassiveFrame
	streamPassivePeer
	streamHubSetup
	streamHubSend
	streamHubReceive
	streamHubOperations
	streamHubResult
	streamHubReceipt
	streamRegionalSetup
	streamRegionalWork
	streamRegionalVerify
	streamRegionalOperations
	streamRegionalResult
	streamRegionalReceipt
	streamWorkPeerLease
	streamHubQuery
	streamHubQuerySource
	streamHubQueryCheck
	streamRegionalQueryOwner
	streamRegionalQueryWrite
	streamRegionalQueryLocal
	streamRegionalQueryOwnerAuth
)

func (v StreamInterruption) Stage() string {
	names := [...]string{"none", "owner", "close", "send-admission", "receive-admission", "send-call", "receive-call", "send-peer", "receive-peer", "send-bound", "receive-bound", "send-deadline", "receive-deadline", "write", "flush", "read", "send-result", "receive-result", "passive-call", "passive-deadline", "passive-frame", "passive-peer", "hub-setup", "hub-send", "hub-receive", "hub-operations", "hub-result", "hub-receipt", "regional-setup", "regional-work", "regional-verify", "regional-operations", "regional-result", "regional-receipt", "work-peer-lease", "hub-query", "hub-query-source", "hub-query-check", "regional-query-owner", "regional-query-write", "regional-query-local", "regional-query-owner-auth"}
	if int(v.stage) >= len(names) {
		return "unknown"
	}
	return names[v.stage]
}

type streamReason uint8

const (
	streamNoReason streamReason = iota
	streamOther
	streamCanceled
	streamExpired
	streamEOF
	streamShortRead
	streamClosedIO
	streamTimeout
	streamInvalid
	streamDenied
	streamUnavailable
	streamProtocol
	streamClosed
	streamBusy
	streamBudget
	streamPeerInvalid
	streamPeerChanged
	streamHTTP2Internal
	streamHTTP2Deadline
	streamHTTP2Cancel
	streamHTTP2Protocol
	streamHTTP2Refused
	streamHTTP2Other
)

func (v StreamInterruption) Reason() string {
	names := [...]string{"none", "other", "canceled", "deadline", "eof", "short-read", "closed-io", "io-timeout", "invalid", "denied", "unavailable", "protocol", "closed", "concurrent-call", "frame-or-byte-budget", "peer-invalid", "peer-changed", "http2-internal", "http2-deadline", "http2-cancel", "http2-protocol", "http2-refused", "http2-other"}
	if int(v.reason) >= len(names) {
		return "unknown"
	}
	return names[v.reason]
}
func (v StreamInterruption) Present() bool { return v.stage != streamNoStage }

// StreamDiagnostics is one invocation-owned fixed snapshot. It accepts no
// callback, error, source value or caller-supplied diagnostic. A fixture can
// carry separate instances on its original hub and regional contexts; absence
// of a recorder changes neither work nor error normalization.
type StreamDiagnostics struct {
	first atomic.Pointer[StreamInterruption]
}
type streamDiagnosticKey struct{}

func NewStreamDiagnosticContext(ctx context.Context) (context.Context, *StreamDiagnostics) {
	if ctx == nil {
		return nil, nil
	}
	d := &StreamDiagnostics{}
	return context.WithValue(ctx, streamDiagnosticKey{}, d), d
}
func (d *StreamDiagnostics) Interruption() StreamInterruption {
	if d != nil {
		if v := d.first.Load(); v != nil {
			return *v
		}
	}
	return StreamInterruption{}
}

// Classification uses standard trusted in-process Go error protocols (Is, As,
// Unwrap and Timeout). It never renders Error text or retains provider payloads.
// Network input cannot inject Go implementations of those methods.
func streamErrorReason(err error) streamReason {
	switch {
	case err == nil:
		return streamNoReason
	case errors.Is(err, context.Canceled):
		return streamCanceled
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return streamExpired
	case errors.Is(err, io.EOF):
		return streamEOF
	case errors.Is(err, io.ErrUnexpectedEOF):
		return streamShortRead
	case errors.Is(err, io.ErrClosedPipe), errors.Is(err, net.ErrClosed):
		return streamClosedIO
	case errors.Is(err, fleet.ErrInvalid), errors.Is(err, identity.ErrInvalid), errors.Is(err, execution.ErrInvalid):
		return streamInvalid
	case errors.Is(err, fleet.ErrDenied), errors.Is(err, identity.ErrDenied), errors.Is(err, execution.ErrDenied):
		return streamDenied
	case errors.Is(err, fleet.ErrUnavailable), errors.Is(err, identity.ErrUnavailable), errors.Is(err, execution.ErrUnavailable):
		return streamUnavailable
	case errors.Is(err, contracts.ErrAPIContextProtocol):
		return streamProtocol
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return streamTimeout
	}
	// Go's net/http supports As into x/net/http2.StreamError, including through
	// standard wrappers. Retain no ID or Cause text; INTERNAL alone proves no
	// timeout or origin. Only its exact known deadline Cause gets that label.
	var stream http2.StreamError
	ok := errors.As(err, &stream)
	if ok {
		switch stream.Code {
		case http2.ErrCodeInternal:
			if stream.Cause == os.ErrDeadlineExceeded {
				return streamHTTP2Deadline
			}
			return streamHTTP2Internal
		case http2.ErrCodeCancel:
			return streamHTTP2Cancel
		case http2.ErrCodeProtocol:
			return streamHTTP2Protocol
		case http2.ErrCodeRefusedStream:
			return streamHTTP2Refused
		default:
			return streamHTTP2Other
		}
	}
	return streamOther
}

func (s *frameStream) record(stage streamStage, reason streamReason) {
	if s != nil {
		s.first.CompareAndSwap(nil, &StreamInterruption{stage, reason})
	}
}
func (s *frameStream) interruption() StreamInterruption {
	if s != nil {
		if v := s.first.Load(); v != nil {
			return *v
		}
	}
	return StreamInterruption{}
}
func recordStreamDiagnostic(ctx context.Context, stream Stream, err error, stage streamStage) {
	if err == nil {
		return
	}
	var v StreamInterruption
	if s, ok := stream.(*frameStream); ok {
		s.record(stage, streamErrorReason(err))
		v = s.interruption()
	} else {
		v = StreamInterruption{stage, streamErrorReason(err)}
	}
	if ctx != nil {
		if d, ok := ctx.Value(streamDiagnosticKey{}).(*StreamDiagnostics); ok && d != nil {
			d.first.CompareAndSwap(nil, &v)
		}
	}
}

// The frame decoder deliberately normalizes I/O errors. This original-reader
// delegate retains only the error class for that one decode, without another
// read, changed n/error, clock sample or retained payload. A read with n>0 and
// EOF that satisfies ReadFull must not be mistaken for a failed frame.
type streamReadDiagnostic struct {
	reader io.Reader
	reason streamReason
}

func (r *streamReadDiagnostic) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if err != nil {
		r.reason = streamErrorReason(err)
	}
	return n, err
}

type streamWriteDiagnostic struct {
	writer io.Writer
	reason streamReason
}

func (w *streamWriteDiagnostic) Write(p []byte) (int, error) {
	n, err := w.writer.Write(p)
	if err != nil {
		w.reason = streamErrorReason(err)
	}
	return n, err
}
