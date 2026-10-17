package clusterobservation

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

type ownerObservationIngress interface {
	ObserveOwnerPeer(context.Context, *tls.ConnectionState, contracts.OwnerObservationRequest) (contracts.OwnerObservationReply, error)
}

// OwnerHandler serves the one closed own-peer proof purpose. It has no worker,
// context-start, public or workload-metadata backend, and no dynamic route map.
type OwnerHandler struct {
	host, serverName string
	ingress          ownerObservationIngress
	root             context.Context
	cancel           context.CancelFunc
	now              func() time.Time
	mu               sync.Mutex
	closed           bool
	maximum, active  int
	joined           sync.WaitGroup
}

func NewOwnerHandler(ctx context.Context, host string, ingress ownerObservationIngress, maximum int, now func() time.Time) (*OwnerHandler, error) {
	name, port, e := net.SplitHostPort(host)
	p, pe := strconv.Atoi(port)
	if ctx == nil || ctx.Err() != nil || e != nil || pe != nil || p < 1024 || p > 65535 || name == "" || net.ParseIP(name) != nil || strings.ContainsAny(name, "/\\ \t\r\n%") || name != strings.ToLower(name) || ingress == nil || maximum < 1 || maximum > 16 || now == nil {
		return nil, fleet.ErrInvalid
	}
	root, cancel := context.WithCancel(ctx)
	return &OwnerHandler{host: host, serverName: name, ingress: ingress, root: root, cancel: cancel, now: now, maximum: maximum}, nil
}
func (h *OwnerHandler) Authority() string {
	if h == nil {
		return ""
	}
	return h.host
}
func (h *OwnerHandler) enter() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.root.Err() != nil || h.active >= h.maximum {
		return false
	}
	h.active++
	h.joined.Add(1)
	return true
}
func (h *OwnerHandler) leave() { h.mu.Lock(); h.active--; h.mu.Unlock(); h.joined.Done() }
func (h *OwnerHandler) Close() {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.closed = true
	h.cancel()
	h.mu.Unlock()
	h.joined.Wait()
}

func (h *OwnerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil || r == nil || r.URL == nil || r.Body == nil || r.TLS == nil || !r.TLS.HandshakeComplete || r.TLS.DidResume || r.TLS.Version != tls.VersionTLS13 || r.TLS.NegotiatedProtocol != "h2" || len(r.TLS.VerifiedChains) == 0 || r.TLS.ServerName != h.serverName || r.ProtoMajor != 2 || r.Method != http.MethodPost || r.Host != h.host || r.RequestURI != contracts.OwnerObservationPath || r.URL.Path != contracts.OwnerObservationPath || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.Host != "" || r.URL.Scheme != "" || r.URL.User != nil || r.ContentLength < 1 || r.ContentLength > contracts.OwnerObservationBytes || len(r.TransferEncoding) != 0 || !oneHeader(r, "Content-Type", contracts.OwnerObservationMedia) || !oneHeader(r, "Accept", contracts.OwnerObservationMedia) {
		localUnavailable(w)
		return
	}
	for _, k := range []string{"Authorization", "Cookie", "Origin", "Referer", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Content-Encoding", "Idempotency-Key", "X-Idempotency-Key"} {
		if len(r.Header.Values(k)) != 0 {
			localUnavailable(w)
			return
		}
	}
	if !h.enter() {
		localUnavailable(w)
		return
	}
	defer h.leave()
	until := h.now().Add(5 * time.Second)
	if d, ok := r.Context().Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	call, cancel := context.WithDeadline(r.Context(), until)
	defer cancel()
	done := make(chan struct{})
	stopRoot := context.AfterFunc(h.root, func() { cancel(); close(done) })
	defer func() {
		if !stopRoot() {
			<-done
		}
	}()
	control := http.NewResponseController(w)
	if control.SetReadDeadline(until) != nil || control.SetWriteDeadline(until) != nil {
		localUnavailable(w)
		return
	}
	interrupted := make(chan struct{})
	stopIO := context.AfterFunc(call, func() {
		_ = control.SetReadDeadline(time.Now())
		_ = control.SetWriteDeadline(time.Now())
		_ = r.Body.Close()
		close(interrupted)
	})
	defer func() {
		if !stopIO() {
			<-interrupted
		}
	}()
	body, e := io.ReadAll(io.LimitReader(r.Body, contracts.OwnerObservationBytes+1))
	if e != nil || len(body) != int(r.ContentLength) || len(body) > contracts.OwnerObservationBytes || call.Err() != nil {
		localUnavailable(w)
		return
	}
	input, e := contracts.DecodeOwnerObservationRequest(body)
	end, ee := time.Parse(time.RFC3339Nano, input.NotAfter)
	start, se := time.Parse(time.RFC3339Nano, input.RequestedAt)
	if e != nil || ee != nil || se != nil || input.Format != contracts.OwnerObservationFormat || !identity.Fresh(start, end, h.now(), 5*time.Second) {
		localUnavailable(w)
		return
	}
	until = identity.Earlier(until, end)
	bounded, narrow := context.WithDeadline(call, until)
	defer narrow()
	// The original shorter wire bound interrupts blocked adapter I/O too, not
	// only the eventual response write. Cancellation is joined before return.
	boundedDone := make(chan struct{})
	stopBounded := context.AfterFunc(bounded, func() {
		_ = control.SetReadDeadline(time.Now())
		_ = control.SetWriteDeadline(time.Now())
		_ = r.Body.Close()
		close(boundedDone)
	})
	defer func() {
		if !stopBounded() {
			<-boundedDone
		}
	}()
	out, e := h.ingress.ObserveOwnerPeer(bounded, r.TLS, input)
	observed, oe := time.Parse(time.RFC3339Nano, out.ObservedAt)
	fresh, fe := time.Parse(time.RFC3339Nano, out.FreshUntil)
	if e != nil || oe != nil || fe != nil || out.Format != contracts.OwnerObservationFormat || out.Request != input || !identity.Fresh(observed, fresh, h.now(), 5*time.Second) || observed.Before(start) || fresh.After(until) || bounded.Err() != nil {
		localUnavailable(w)
		return
	}
	b, e := contracts.EncodeOwnerObservationReply(out)
	if e != nil || len(b) > contracts.OwnerObservationBytes || control.SetWriteDeadline(fresh) != nil || bounded.Err() != nil || !h.now().Before(fresh) {
		localUnavailable(w)
		return
	}
	w.Header().Set("Content-Type", contracts.OwnerObservationMedia)
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if n, e := w.Write(b); e != nil || n != len(b) {
		return
	}
	_ = control.Flush()
}
