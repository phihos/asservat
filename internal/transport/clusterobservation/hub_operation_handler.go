package clusterobservation

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// HubObservationOperationHandler receives only the fixed regional standby purpose.
// The owning private listener must supply each request's ORIGINAL finite socket
// deadline, one request per TLS connection and a socket slot retained through
// joined close. This handler cannot select or enable a listener/runtime route.
type HubObservationOperationHandler struct {
	host, serverName string
	holder           *HubObservationOperationHolder
	factory          HubObservationOperationFactory
	now              func() time.Time
	mu               sync.Mutex
	closed           bool
	joined           sync.WaitGroup
}

func NewHubObservationOperationHandler(host string, holder *HubObservationOperationHolder, factory HubObservationOperationFactory, now func() time.Time) (*HubObservationOperationHandler, error) {
	name, port, err := net.SplitHostPort(host)
	p, pe := strconv.Atoi(port)
	if err != nil || pe != nil || p < 1024 || p > 65535 || name == "" || name != strings.ToLower(name) || net.ParseIP(name) != nil || strings.ContainsAny(name, "/\\ \t\r\n%") || holder == nil || factory == nil || now == nil {
		return nil, fleet.ErrInvalid
	}
	return &HubObservationOperationHandler{host: host, serverName: name, holder: holder, factory: factory, now: now}, nil
}

func (h *HubObservationOperationHandler) Authority() string {
	if h == nil {
		return ""
	}
	return h.host
}

func (h *HubObservationOperationHandler) Close() {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.closed = true
	h.mu.Unlock()
	h.holder.Close()
	h.joined.Wait()
}

func (h *HubObservationOperationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil || r == nil || r.URL == nil || r.Body == nil || r.TLS == nil || !r.TLS.HandshakeComplete || r.TLS.DidResume || r.TLS.Version != tls.VersionTLS13 || r.TLS.NegotiatedProtocol != "h2" || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 || r.TLS.ServerName != h.serverName || r.ProtoMajor != 2 || r.Method != http.MethodPost || r.Host != h.host || r.RequestURI != contracts.ClusterObservationOperationExchangePath || r.URL.Path != contracts.ClusterObservationOperationExchangePath || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.Host != "" || r.URL.Scheme != "" || r.URL.User != nil || r.ContentLength != -1 || len(r.TransferEncoding) != 0 || !oneHeader(r, "Content-Type", contracts.ClusterObservationOperationExchangeMedia) || !oneHeader(r, "Accept", contracts.ClusterObservationOperationExchangeMedia) {
		localUnavailable(w)
		return
	}
	for _, key := range []string{"Authorization", "Cookie", "Origin", "Referer", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Content-Encoding", "Idempotency-Key", "X-Idempotency-Key"} {
		if len(r.Header.Values(key)) != 0 {
			localUnavailable(w)
			return
		}
	}
	// A handler-local timer cannot manufacture the accepted socket's original
	// residency. Missing/overlong listener context is a composition error.
	end, finite := r.Context().Deadline()
	if !finite || !h.now().Before(end) || end.After(h.now().Add(30*time.Second)) {
		localUnavailable(w)
		return
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		localUnavailable(w)
		return
	}
	h.joined.Add(1)
	h.mu.Unlock()
	defer h.joined.Done()
	entry, err := h.holder.reserve(r.Context())
	if err != nil {
		localUnavailable(w)
		return
	}
	defer entry.close()
	setup, cancel := context.WithDeadline(entry.ctx, identity.Earlier(end, h.now().Add(5*time.Second)))
	control := http.NewResponseController(w)
	setupEnd, _ := setup.Deadline()
	if control.SetReadDeadline(setupEnd) != nil || control.SetWriteDeadline(setupEnd) != nil {
		cancel()
		localUnavailable(w)
		return
	}
	interrupted := make(chan struct{})
	stop := context.AfterFunc(setup, func() {
		_ = control.SetReadDeadline(time.Now())
		_ = control.SetWriteDeadline(time.Now())
		_ = r.Body.Close()
		close(interrupted)
	})
	setupJoined := false
	defer func() {
		if !setupJoined {
			if !stop() {
				<-interrupted
			}
			cancel()
		}
	}()
	frame, err := contracts.ReadClusterObservationFrame(r.Body)
	if err != nil || setup.Err() != nil || frame.Kind != contracts.ClusterObservationHelloFrame {
		clear(frame.Payload)
		localUnavailable(w)
		return
	}
	hello, err := contracts.DecodeClusterObservationHello(frame.Payload)
	size := len(frame.Payload)
	clear(frame.Payload)
	if err != nil || hello.Format != contracts.ClusterObservationOperationExchangeFormat || !authorization.UUID(hello.ExchangeID) || !authorization.UUID(hello.RootID) || !authorization.UUID(hello.ClusterID) {
		localUnavailable(w)
		return
	}
	stream, err := newHubObservationOperationStream(entry.ctx, w, r.Body, hello, size, h.now)
	if err != nil {
		localUnavailable(w)
		return
	}
	// Factory performs only the fixed actual TLS/profile admission. It must not
	// use setup's five-second observation as a new process or source lifetime.
	conversation, err := h.factory(entry.ctx, setup, r.TLS, hello, stream)
	if err != nil || conversation == nil || setup.Err() != nil || entry.ctx.Err() != nil {
		_ = stream.Close()
		if conversation != nil {
			conversation.Close()
		}
		localUnavailable(w)
		return
	}
	if entry.bind(hello, stream, conversation) != nil {
		_ = stream.Close()
		conversation.Close()
		localUnavailable(w)
		return
	}
	w.Header().Set("Content-Type", contracts.ClusterObservationOperationExchangeMedia)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	if control.Flush() != nil || setup.Err() != nil {
		return
	}
	// Join/detach the setup callback before handing cancellation ownership to
	// the retained stream. An already firing callback cannot be defeated by a
	// later successful header write or a longer standby socket deadline.
	if !stop() {
		<-interrupted
		return
	}
	setupJoined = true
	if setup.Err() != nil {
		cancel()
		return
	}
	cancel()
	if entry.ctx.Err() != nil || control.SetReadDeadline(end) != nil || control.SetWriteDeadline(end) != nil || entry.publish() != nil {
		return
	}
	select {
	case <-entry.resultDone:
	case <-entry.ctx.Done():
	case <-h.holder.root.Done():
	}
	// entry.close joins every admitted call before this handler returns. A
	// positive complete request body must return normally so net/http can emit
	// response END_STREAM; the listener retains and joins its socket separately.
}
