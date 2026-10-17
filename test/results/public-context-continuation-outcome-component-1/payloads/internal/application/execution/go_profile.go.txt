package execution

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/execution"
)

// GoProfileGuard checks the original admitted profile attempt, current rights,
// recovery/deny/source/target state and retained conflicting-runtime slot. It
// cannot create a start, renew a permit, change parameters or refund spend.
// There is deliberately no fixture/default implementation in production.
type GoProfileGuard interface {
	ObserveGoProfile(context.Context, value.GoProfileRequest) (value.GoProfileCurrent, error)
}

// GoProfileChannel is one already connected, HTTP/1 channel to the exact named
// endpoint. Host and Authorization are supplied only by a qualified protected
// resolver; never by a user, API DTO or collected evidence. A credential-bearing
// connection must expose a completed, verified TLS ConnectionState.
type GoProfileChannel struct {
	Connection          net.Conn
	Host, Authorization string
	// Original channel/credential deadline; setting a socket deadline must not
	// extend a shorter provider lifetime. This is not observation freshness.
	ValidUntil time.Time
}

// GoProfileDialer resolves the accepted endpoint digest and exact pod/node/boot
// binding, validates current configuration and credential workload audience and
// opens a node-local connection. targetLoopback MUST use the pinned target netns.
// Its context and connection must preserve original cancellation/deadlines. It
// must not return before its own network operations have joined, leak a failed
// connection, redirect, retry an HTTP request or resolve a replacement Pod.
// This interface alone does not qualify a real node/network implementation.
type GoProfileDialer interface {
	DialGoProfile(context.Context, value.GoProfileRequest) (GoProfileChannel, error)
}

// GoProfileSink consumes the complete native stream synchronously into prepared
// encryption. The reader cannot escape this call or cross a hub/controller
// transport. On return all reads/writes must have joined; partial output stays
// under the original reserved copy/cleanup accounting and is never published.
type GoProfileSink interface {
	ConsumeGoProfile(context.Context, value.GoProfileRequest, io.Reader) (artifact.Layout, error)
	// CollectGoProfile takes ownership of this prepared attempt, including on
	// validation/dial failure, and calls Close after all source work has joined.
	Close()
}

type GoProfileCollection struct {
	Outcome value.GoProfileOutcome
	Layout  artifact.Layout
}

type GoProfileCollector interface {
	CollectGoProfile(context.Context, value.GoProfileRequest, GoProfileSink) (GoProfileCollection, error)
}

// GoProfileEncodingSink connects the mechanism to the existing versioned
// evidence encoder. Keys MUST already be wrapped before acquisition starts.
// It owns one use, including failure. Destination writers receive ciphertext
// only; they must honor the acquisition context and custody's original bounds.
// This is not a manifest producer, copy receipt or artifact publication service.
type GoProfileEncodingSink struct {
	mu          sync.Mutex
	request     value.GoProfileRequest
	encoder     evidence.StorageEncoder
	data, index io.Writer
	used        bool
}

func NewGoProfileEncodingSink(r value.GoProfileRequest, encoder evidence.StorageEncoder, data, index io.Writer) (*GoProfileEncodingSink, error) {
	if r.Validate(r.NotBefore) != nil || encoder == nil || data == nil || index == nil {
		return nil, value.ErrInvalid
	}
	return &GoProfileEncodingSink{request: r, encoder: encoder, data: data, index: index}, nil
}

// Close releases prepared primitive references after success, failure or a source
// that could not be opened. It is not a claim of physical Go heap key erasure.
func (s *GoProfileEncodingSink) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.used = true
	s.encoder = nil
	s.data = nil
	s.index = nil
}

func (s *GoProfileEncodingSink) ConsumeGoProfile(ctx context.Context, r value.GoProfileRequest, source io.Reader) (artifact.Layout, error) {
	if s == nil || ctx == nil {
		return artifact.Layout{}, value.ErrProfileOutput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.used || s.encoder == nil || s.data == nil || s.index == nil || r != s.request || source == nil || ctx.Err() != nil {
		return artifact.Layout{}, value.ErrProfileOutput
	}
	s.used = true
	defer func() { s.encoder = nil; s.data = nil; s.index = nil }()
	dataLimit, indexLimit, err := artifact.WorstCase(r.NativeLimit)
	if err != nil {
		return artifact.Layout{}, value.ErrProfileOutput
	}
	data := &profileCipherWriter{ctx: ctx, writer: s.data, remaining: dataLimit}
	index := &profileCipherWriter{ctx: ctx, writer: s.index, remaining: indexLimit}
	l, err := s.encoder.Encode(ctx, source, data, index, r.NativeLimit)
	if err != nil || ctx.Err() != nil || l.Validate() != nil || l.Binding != r.Binding || l.NativeBytes < 1 || l.NativeBytes > r.NativeLimit || l.DataBytes != dataLimit-data.remaining || l.IndexBytes != indexLimit-index.remaining {
		return artifact.Layout{}, value.ErrProfileOutput
	}
	return l, nil
}

type profileCipherWriter struct {
	ctx       context.Context
	writer    io.Writer
	remaining int64
}

func (w *profileCipherWriter) Write(p []byte) (int, error) {
	if w.ctx.Err() != nil || int64(len(p)) > w.remaining {
		return 0, value.ErrProfileOutput
	}
	n, err := w.writer.Write(p)
	if n < 0 || n > len(p) {
		return 0, value.ErrProfileOutput
	}
	w.remaining -= int64(n)
	if err != nil || n != len(p) || w.ctx.Err() != nil {
		return n, value.ErrProfileOutput
	}
	return n, nil
}
