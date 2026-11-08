package native

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	app "asservat.local/asservat/internal/application/live"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/identity"
	v "asservat.local/asservat/internal/domain/live"
)

// LiveOwnerAdmission uses actual current owner TLS/registry/route observations.
// Hello.Actor only binds callbacks and must never be accepted as authority.
type LiveOwnerAdmission interface {
	CheckLiveOwner(context.Context, *tls.ConnectionState, contracts.LiveOwnerHello) (time.Time, error)
}
type LiveOwnerHandler struct {
	authority, rootID, ownerID string
	service                    *app.Service
	admission                  LiveOwnerAdmission
	slots                      chan struct{}
}

func NewLiveOwnerHandler(authority, rootID, ownerID string, s *app.Service, a LiveOwnerAdmission, slots int) (*LiveOwnerHandler, error) {
	if authority == "" || rootID == "" || ownerID == "" || s == nil || a == nil || slots < 1 || slots > 16 {
		return nil, contracts.ErrNativeProtocol
	}
	return &LiveOwnerHandler{authority, rootID, ownerID, s, a, make(chan struct{}, slots)}, nil
}
func (h *LiveOwnerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil || r == nil || r.URL == nil || r.TLS == nil || r.TLS.DidResume || r.TLS.Version != tls.VersionTLS13 || r.TLS.NegotiatedProtocol != "h2" || r.ProtoMajor != 2 || r.Method != http.MethodPost || r.Host != h.authority || r.RequestURI != contracts.LiveOwnerPath || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.Scheme != "" || r.URL.Host != "" || r.URL.User != nil || r.ContentLength != -1 || len(r.TransferEncoding) != 0 || !oneHeader(r, "Content-Type", contracts.LiveOwnerMedia) || !oneHeader(r, "Accept", contracts.LiveOwnerMedia) {
		unavailable(w)
		return
	}
	for _, name := range []string{"Authorization", "Cookie", "Origin", "Referer", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Content-Encoding", "Idempotency-Key", "X-Idempotency-Key"} {
		if len(r.Header.Values(name)) != 0 {
			unavailable(w)
			return
		}
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		unavailable(w)
		return
	}
	controller := http.NewResponseController(w)
	if controller.SetReadDeadline(time.Now().Add(2*time.Second)) != nil {
		unavailable(w)
		return
	}
	first, err := contracts.ReadNativeFrame(r.Body)
	if err != nil || first.Kind != contracts.NativeHelloFrame {
		clear(first.Payload)
		unavailable(w)
		return
	}
	hello, err := contracts.DecodeLiveOwnerHello(bytes.NewReader(first.Payload))
	clear(first.Payload)
	if err != nil || hello.RootID != h.rootID || hello.OwnerID != h.ownerID || !time.Now().Before(hello.Until) || hello.Until.After(time.Now().Add(5*time.Second)) {
		unavailable(w)
		return
	}
	call, cancel := context.WithDeadline(r.Context(), hello.Until)
	defer cancel()
	until, err := h.admission.CheckLiveOwner(call, r.TLS, hello)
	if err != nil || !time.Now().Before(until) || until.After(hello.Until) {
		unavailable(w)
		return
	}
	bounded, end := context.WithDeadline(call, until)
	defer end()
	// Hello's prelude bound must not expire an admitted healthy command. Both
	// I/O directions now use its already-shortened original absolute deadline.
	if controller.SetReadDeadline(until) != nil || controller.SetWriteDeadline(until) != nil {
		unavailable(w)
		return
	}
	var command app.Command
	dec := json.NewDecoder(bytes.NewReader(hello.Command))
	dec.DisallowUnknownFields()
	if dec.Decode(&command) != nil || dec.Decode(new(any)) != io.EOF || !command.Valid() {
		unavailable(w)
		return
	}
	stream := newLiveOwnerStream(bounded, r, w)
	defer stream.Close()
	w.Header().Set("Content-Type", contracts.LiveOwnerMedia)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	if controller.Flush() != nil {
		return
	}
	current := &liveOwnerIdentity{stream: stream, hello: hello, until: until}
	// The first identity observation is the service's own existing check. Route
	// binding fields cannot supply it. Exact actor/client is checked on each reply.
	keys := app.RouteKeys{Actor: identity.Principal{Issuer: hello.Actor.Issuer, Subject: hello.Actor.Subject, ClientID: hello.Actor.ClientID, Kind: identity.Kind(hello.Actor.Kind)}, Until: until}
	keys.Policy = identity.Revision{UID: hello.Policy.UID, Generation: hello.Policy.Generation, Digest: hello.Policy.Digest}
	var delivery app.CommandDelivery
	if err == nil {
		delivery, err = h.service.BeginOwnedLocalCommand(bounded, current, command, keys)
	}
	if err != nil {
		_ = current.sendResult(bounded, app.CommandResult{}, until, err)
		return
	}
	defer delivery.Close(context.Background())
	result := delivery.Result()
	if result.Batch != nil {
		until = earlierLive(until, result.Batch.DisclosureUntil)
	}
	final, err := h.admission.CheckLiveOwner(bounded, r.TLS, hello)
	until = earlierLive(until, final)
	if err != nil || delivery.CheckDisclosure(bounded) != nil || !time.Now().Before(until) {
		return
	}
	if current.sendResult(bounded, result, until, nil) != nil {
		return
	}
	// Retain actual operation/peer ownership through the ingress outcome audit
	// and final write. Missing acknowledgement is not successful delivery.
	f, err := stream.Receive(bounded)
	if err != nil {
		return
	}
	defer clear(f.Payload)
	ack, err := contracts.DecodeLiveOwnerFrame(bytes.NewReader(f.Payload))
	if err != nil || f.Kind != contracts.NativeDoneFrame || ack.Kind != "done" || ack.Nonce != hello.Nonce || ack.Sequence != current.sequence+1 || ack.Until.After(until) {
		return
	}
	if delivery.Close(context.Background()) != nil {
		return
	}
	confirmation, _ := json.Marshal(ack)
	_ = stream.Send(bounded, contracts.NativeFrame{Kind: contracts.NativeDoneFrame, Payload: confirmation})
	clear(confirmation)
}
func earlierLive(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

type liveOwnerIdentity struct {
	stream   *liveOwnerStream
	hello    contracts.LiveOwnerHello
	sequence uint64
	until    time.Time
	policy   *identity.Revision
}

func (p *liveOwnerIdentity) ResolveIdentity(ctx context.Context) (identity.Identity, error) {
	var zero identity.Identity
	p.sequence++
	until := p.until
	if d, ok := ctx.Deadline(); ok {
		until = earlierLive(until, d)
	}
	if !time.Now().Before(until) {
		return zero, identity.ErrDenied
	}
	request := contracts.LiveOwnerFrame{Kind: "current", Nonce: p.hello.Nonce, Sequence: p.sequence, Until: until}
	b, err := json.Marshal(request)
	if err != nil {
		return zero, err
	}
	err = p.stream.Send(ctx, contracts.NativeFrame{Kind: contracts.NativeMetadataFrame, Payload: b})
	clear(b)
	if err != nil {
		return zero, err
	}
	reply, err := p.stream.Receive(ctx)
	if err != nil {
		return zero, err
	}
	defer clear(reply.Payload)
	f, err := contracts.DecodeLiveOwnerFrame(bytes.NewReader(reply.Payload))
	if err != nil || reply.Kind != contracts.NativeCommandFrame || f.Kind != "identity" || f.Nonce != p.hello.Nonce || f.Sequence != p.sequence || f.Until.After(until) {
		return zero, identity.ErrDenied
	}
	dec := json.NewDecoder(bytes.NewReader(f.Identity))
	dec.DisallowUnknownFields()
	var i identity.Identity
	if dec.Decode(&i) != nil || dec.Decode(new(any)) != io.EOF || !i.Valid(time.Now()) || i.Principal != (identity.Principal{Issuer: p.hello.Actor.Issuer, Subject: p.hello.Actor.Subject, ClientID: p.hello.Actor.ClientID, Kind: identity.Kind(p.hello.Actor.Kind)}) || p.policy != nil && i.Policy != *p.policy || !time.Now().Before(f.Until) {
		return zero, identity.ErrDenied
	}
	if p.policy == nil {
		policy := i.Policy
		p.policy = &policy
	}
	p.until = earlierLive(p.until, earlierLive(f.Until, i.ValidUntil))
	i.ValidUntil = p.until
	return i, nil
}
func (p *liveOwnerIdentity) sendResult(ctx context.Context, result app.CommandResult, until time.Time, err error) error {
	p.sequence++
	f := contracts.LiveOwnerFrame{Kind: "result", Nonce: p.hello.Nonce, Sequence: p.sequence, Until: earlierLive(p.until, until)}
	if err != nil {
		f.Kind = "error"
		switch {
		case errors.Is(err, v.ErrDenied):
			f.Failure = "denied"
		case errors.Is(err, v.ErrConflict):
			f.Failure = "conflict"
		case errors.Is(err, v.ErrCapacity):
			f.Failure = "capacity"
		case errors.Is(err, v.ErrInvalid):
			f.Failure = "invalid"
		default:
			f.Failure = "unavailable"
		}
	} else {
		f.Result, err = app.EncodeOwnerResult(result)
		if err != nil {
			return err
		}
	}
	b, e := json.Marshal(f)
	if e != nil || len(b) > contracts.NativeControlBytes {
		return contracts.ErrNativeProtocol
	}
	defer clear(b)
	return p.stream.Send(ctx, contracts.NativeFrame{Kind: contracts.NativeMetadataFrame, Payload: b})
}

// The live stream uses the existing bounded native frame codec and HTTP/2 I/O
// cancellation pattern without fabricating a worker/evidence NativeLease.
type liveOwnerStream struct {
	ctx             context.Context
	cancel          context.CancelFunc
	r               *http.Request
	w               http.ResponseWriter
	controller      *http.ResponseController
	mu              sync.Mutex
	active          sync.WaitGroup
	closed          bool
	reads, writes   int
	stopInterrupt   func() bool
	interruptJoined chan struct{}
	closeOnce       sync.Once
}

func newLiveOwnerStream(ctx context.Context, r *http.Request, w http.ResponseWriter) *liveOwnerStream {
	owned, cancel := context.WithCancel(ctx)
	s := &liveOwnerStream{ctx: owned, cancel: cancel, r: r, w: w, controller: http.NewResponseController(w)}
	s.interruptJoined = make(chan struct{})
	s.stopInterrupt = context.AfterFunc(owned, func() { defer close(s.interruptJoined); s.interrupt() })
	return s
}
func (s *liveOwnerStream) Context() context.Context { return s.ctx }
func (s *liveOwnerStream) interrupt() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.cancel()
	s.mu.Unlock()
	_ = s.controller.SetReadDeadline(time.Now())
	_ = s.controller.SetWriteDeadline(time.Now())
	_ = s.r.Body.Close()
}
func (s *liveOwnerStream) Close() error {
	s.closeOnce.Do(func() {
		stopped := s.stopInterrupt()
		s.interrupt()
		if !stopped {
			<-s.interruptJoined
		}
		s.active.Wait()
	})
	return nil
}
func (s *liveOwnerStream) begin(ctx context.Context, read bool) (func(), error) {
	s.mu.Lock()
	if s.closed || ctx == nil || ctx.Err() != nil || s.ctx.Err() != nil || read && s.reads >= contracts.NativeMaximumFrames || !read && s.writes >= contracts.NativeMaximumFrames {
		s.mu.Unlock()
		return nil, contracts.ErrNativeProtocol
	}
	if read {
		s.reads++
	} else {
		s.writes++
	}
	s.active.Add(1)
	s.mu.Unlock()
	joined := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { s.interrupt(); close(joined) })
	return func() {
		if !stop() {
			<-joined
		}
		s.active.Done()
	}, nil
}
func (s *liveOwnerStream) Receive(ctx context.Context) (contracts.NativeFrame, error) {
	end, e := s.begin(ctx, true)
	if e != nil {
		return contracts.NativeFrame{}, e
	}
	defer end()
	f, e := contracts.ReadNativeFrame(s.r.Body)
	if e != nil || ctx.Err() != nil || s.ctx.Err() != nil {
		clear(f.Payload)
		s.interrupt()
		return contracts.NativeFrame{}, contracts.ErrNativeProtocol
	}
	return f, nil
}
func (s *liveOwnerStream) Send(ctx context.Context, f contracts.NativeFrame) error {
	end, e := s.begin(ctx, false)
	if e != nil {
		return e
	}
	defer end()
	if e = contracts.WriteNativeFrame(s.w, f); e == nil {
		e = s.controller.Flush()
	}
	if e != nil || ctx.Err() != nil || s.ctx.Err() != nil {
		s.interrupt()
		return contracts.ErrNativeProtocol
	}
	return nil
}
