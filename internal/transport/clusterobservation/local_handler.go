package clusterobservation

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// LocalHandler is installed only on the fixed internal hub HTTPS route. Its
// concrete caller reader is the local Kubernetes admission, and its exchange is
// the exact admitted regional router. Browser/MCP identity cannot enter here.
type LocalHandler struct {
	host, serverName string
	pin              fleet.ClusterObservationCallerPin
	callers          app.ClusterObservationCallerReader
	exchange         app.ClusterObservationExchange
	now              func() time.Time
	root             context.Context
	cancel           context.CancelFunc
	mu               sync.Mutex
	closed           bool
	maximum, active  int
	joined           sync.WaitGroup
}

func NewLocalHandler(ctx context.Context, host string, pin fleet.ClusterObservationCallerPin, callers app.ClusterObservationCallerReader, exchange app.ClusterObservationExchange, maximum int, now func() time.Time) (*LocalHandler, error) {
	origin, parseErr := url.Parse("https://" + host)
	if parseErr != nil || origin.Host != host || origin.Hostname() == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" || strings.Contains(origin.Hostname(), "%") {
		return nil, fleet.ErrInvalid
	}
	serverName := origin.Hostname()
	// TLS deliberately omits SNI for a literal IP destination; DNS authorities
	// require their exact original name. Empty SNI is never a generic fallback.
	if net.ParseIP(serverName) != nil {
		serverName = ""
	}
	if ctx == nil || ctx.Err() != nil || host == "" || strings.ContainsAny(host, "/\\ \t\r\n") || !pin.Valid() || callers == nil || exchange == nil || maximum < 1 || maximum > 16 || now == nil {
		return nil, fleet.ErrInvalid
	}
	root, cancel := context.WithCancel(ctx)
	return &LocalHandler{host: host, serverName: serverName, pin: pin, callers: callers, exchange: exchange, now: now, root: root, cancel: cancel, maximum: maximum}, nil
}
func (h *LocalHandler) enter() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.root.Err() != nil || h.active >= h.maximum {
		return false
	}
	h.active++
	h.joined.Add(1)
	return true
}
func (h *LocalHandler) leave() { h.mu.Lock(); h.active--; h.mu.Unlock(); h.joined.Done() }
func (h *LocalHandler) Close() {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.closed = true
	h.cancel()
	h.mu.Unlock()
	h.joined.Wait()
}
func localUnavailable(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.Error(w, "Unavailable", http.StatusNotFound)
}
func oneHeader(r *http.Request, k, want string) bool {
	v := r.Header.Values(k)
	return len(v) == 1 && v[0] == want
}

func (h *LocalHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil || r == nil || r.URL == nil || r.Body == nil || r.TLS == nil || !r.TLS.HandshakeComplete || r.TLS.Version != tls.VersionTLS13 || r.TLS.NegotiatedProtocol != "h2" || r.TLS.ServerName != h.serverName || r.ProtoMajor != 2 || r.Method != http.MethodPost || r.Host != h.host || r.RequestURI != contracts.ClusterObservationLocalPath || r.URL.Path != contracts.ClusterObservationLocalPath || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.Host != "" || r.URL.Scheme != "" || r.URL.User != nil || r.ContentLength < 1 || r.ContentLength > contracts.ClusterObservationBytes || len(r.TransferEncoding) != 0 || !oneHeader(r, "Content-Type", contracts.ClusterObservationLocalMedia) || !oneHeader(r, "Accept", contracts.ClusterObservationLocalMedia) {
		localUnavailable(w)
		return
	}
	for _, k := range []string{"Cookie", "Origin", "Referer", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Content-Encoding", "Idempotency-Key", "X-Idempotency-Key"} {
		if len(r.Header.Values(k)) != 0 {
			localUnavailable(w)
			return
		}
	}
	auth := r.Header.Values("Authorization")
	if len(auth) != 1 || !strings.HasPrefix(auth[0], "Bearer ") || len(auth[0]) < 8 || len(auth[0]) > 7+(16<<10) {
		localUnavailable(w)
		return
	}
	token := []byte(strings.TrimPrefix(auth[0], "Bearer "))
	defer clear(token)
	if !bytes.Equal(bytes.TrimSpace(token), token) || !h.enter() {
		localUnavailable(w)
		return
	}
	defer h.leave()
	start := h.now()
	until := start.Add(5 * time.Second)
	if d, ok := r.Context().Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	ctx, cancel := context.WithDeadline(r.Context(), until)
	defer cancel()
	rootDone := make(chan struct{})
	stopRoot := context.AfterFunc(h.root, func() { cancel(); close(rootDone) })
	defer func() {
		if !stopRoot() {
			<-rootDone
		}
	}()
	control := http.NewResponseController(w)
	if control.SetReadDeadline(until) != nil || control.SetWriteDeadline(until) != nil {
		localUnavailable(w)
		return
	}
	ioDone := make(chan struct{})
	stopIO := context.AfterFunc(ctx, func() {
		_ = control.SetReadDeadline(time.Now())
		_ = control.SetWriteDeadline(time.Now())
		_ = r.Body.Close()
		close(ioDone)
	})
	defer func() {
		if !stopIO() {
			<-ioDone
		}
	}()
	b, e := io.ReadAll(io.LimitReader(r.Body, contracts.ClusterObservationBytes+1))
	if e != nil || len(b) != int(r.ContentLength) || len(b) > contracts.ClusterObservationBytes || ctx.Err() != nil {
		localUnavailable(w)
		return
	}
	input, e := contracts.DecodeClusterObservationLocalRequest(b)
	if e != nil || input.Format != contracts.ClusterObservationLocalFormat || !authorization.UUID(input.PodUID) {
		localUnavailable(w)
		return
	}
	request, digest, e := ParseRequest(input.Observation, h.now())
	if e != nil || request.RootID != h.pin.RootID {
		localUnavailable(w)
		return
	}
	until = identity.Earlier(until, request.NotAfter)
	call, stop := context.WithDeadline(ctx, until)
	defer stop()
	if control.SetWriteDeadline(until) != nil {
		localUnavailable(w)
		return
	}
	before, e := h.callers.ObserveClusterObservationCaller(call, token, input.PodUID, request)
	if e != nil || !before.Matches(request, h.now()) || before.Pin != h.pin || before.PodUID != input.PodUID || call.Err() != nil {
		localUnavailable(w)
		return
	}
	until = identity.Earlier(until, before.FreshUntil)
	call, stopProof := context.WithDeadline(call, until)
	defer stopProof()
	result, e := h.exchange.ObserveCluster(call, request.Clone())
	if e != nil || !result.Matches(request, digest, h.now()) || call.Err() != nil {
		localUnavailable(w)
		return
	}
	// Retain the first caller's deadline while independently checking current
	// local identity after the remote read. A fresh proof cannot revive it.
	after, e := h.callers.ObserveClusterObservationCaller(call, token, input.PodUID, request)
	if e != nil || !after.Matches(request, h.now()) || !before.SameWorkload(after) || call.Err() != nil {
		localUnavailable(w)
		return
	}
	until = identity.Earlier(until, after.FreshUntil)
	result = result.Restrict(start, until)
	if !result.Matches(request, digest, h.now()) {
		localUnavailable(w)
		return
	}
	out, e := contracts.EncodeClusterObservationResult(ResultWire(result))
	if e != nil || call.Err() != nil || !h.now().Before(result.Interval.FreshUntil) || control.SetWriteDeadline(result.Interval.FreshUntil) != nil {
		localUnavailable(w)
		return
	}
	w.Header().Set("Content-Type", contracts.ClusterObservationLocalMedia)
	w.Header().Set("Content-Length", strconv.Itoa(len(out)))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	if n, e := w.Write(out); e != nil || n != len(out) {
		return
	}
	_ = control.Flush()
}
