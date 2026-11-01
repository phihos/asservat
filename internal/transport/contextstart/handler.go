package contextstart

import (
	"context"
	"crypto/tls"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/fleet"
)

// Ingress authenticates actual TLS and returns a check retaining that exact
// connection. Hello strings are matching inputs, never caller-selected peers.
// The source reader is this exchange's ADR-178 feed of the region's own
// current connector source; the hub never reads the regional API.
type Ingress interface {
	AuthenticateContextStart(context.Context, *tls.ConnectionState, contracts.APIContextHello, app.ConnectorIdentitySourceReader) (fleet.APIContextReceiver, ReceiverCheck, error)
}
type Handler struct {
	host      string
	router    *Router
	ingress   Ingress
	preflight chan struct{}
	// Refused, when set, receives a fixed stage name for each refusal. It carries
	// no request data and changes no response.
	Refused func(string)
}

func NewHandler(host string, router *Router, ingress Ingress, preflight int) (*Handler, error) {
	if host == "" || strings.ContainsAny(host, "/\\ \r\n\t") || router == nil || ingress == nil || preflight < 1 || preflight > 64 {
		return nil, fleet.ErrInvalid
	}
	return &Handler{host: host, router: router, ingress: ingress, preflight: make(chan struct{}, preflight)}, nil
}
func privateUnavailable(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.Error(w, "Unavailable", http.StatusNotFound)
}
func (h *Handler) refuse(w http.ResponseWriter, stage string) {
	if h != nil && h.Refused != nil {
		h.Refused(stage)
	}
	privateUnavailable(w)
}
func exactHeader(r *http.Request, k, v string) bool {
	values := r.Header.Values(k)
	return len(values) == 1 && values[0] == v
}
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil || r == nil || r.URL == nil || r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || r.TLS.NegotiatedProtocol != "h2" || r.ProtoMajor != 2 || r.Method != http.MethodPost || r.Host != h.host || r.URL.Path != contracts.APIContextStartPath || r.RequestURI != contracts.APIContextStartPath || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.Scheme != "" || r.URL.Host != "" || r.URL.User != nil || r.ContentLength != -1 || len(r.TransferEncoding) != 0 || !exactHeader(r, "Content-Type", contracts.APIContextStartMedia) || !exactHeader(r, "Accept", contracts.APIContextStartMedia) {
		h.refuse(w, "request")
		return
	}
	for _, k := range []string{"Authorization", "Cookie", "Origin", "Referer", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Content-Encoding", "Idempotency-Key", "X-Idempotency-Key"} {
		if len(r.Header.Values(k)) != 0 {
			h.refuse(w, "header")
			return
		}
	}
	select {
	case h.preflight <- struct{}{}:
	default:
		h.refuse(w, "preflight")
		return
	}
	// The preflight slot covers unauthenticated framing and actual peer reads.
	// Authenticated standby/capture quotas below are independent per-cluster.
	release := func() { <-h.preflight }
	ctx, stop := context.WithTimeout(r.Context(), 5*time.Second)
	controller := http.NewResponseController(w)
	if controller.SetReadDeadline(time.Now().Add(5*time.Second)) != nil {
		stop()
		release()
		h.refuse(w, "deadline")
		return
	}
	frame, e := contracts.ReadAPIContextFrame(r.Body)
	if e != nil || frame.Kind != contracts.APIContextHelloFrame {
		clear(frame.Payload)
		stop()
		release()
		h.refuse(w, "hello-frame")
		return
	}
	hello, e := contracts.DecodeAPIContextHello(frame.Payload)
	clear(frame.Payload)
	if e != nil || hello.Format != contracts.APIContextExchangeFormat || !time.Now().Before(hello.StandbyUntil) || hello.StandbyUntil.After(time.Now().Add(30*time.Second)) {
		stop()
		release()
		h.refuse(w, "hello")
		return
	}
	// The connector started its finite conversation before dialing. Retain its
	// original declared end as a passive availability bound, intersected with
	// this request's independently owned native socket/caller lifetime. It is
	// never a receiver proof or work authority.
	residence, endResidence := context.WithDeadline(r.Context(), hello.StandbyUntil)
	defer endResidence()
	if setupUntil, _ := ctx.Deadline(); hello.StandbyUntil.Before(setupUntil) {
		shorter, endShorter := context.WithDeadline(ctx, hello.StandbyUntil)
		defer endShorter()
		ctx = shorter
		if controller.SetReadDeadline(hello.StandbyUntil) != nil {
			stop()
			release()
			h.refuse(w, "deadline")
			return
		}
	}
	sources, e := ReadSourceAfterHello(r.Body, hello.Channel.ExchangeID, time.Now)
	if e != nil {
		stop()
		release()
		h.refuse(w, "source")
		return
	}
	receiver, check, e := h.ingress.AuthenticateContextStart(ctx, r.TLS, hello, sources)
	if e != nil || ctx.Err() != nil || !receiver.Valid(time.Now()) || check == nil {
		stop()
		release()
		h.refuse(w, "authenticate")
		return
	}
	// The attach check pulls a fresh regional source over this exchange first.
	var current atomic.Pointer[frameStream]
	attach := func(c context.Context) (fleet.APIContextReceiver, error) {
		s := current.Load()
		if s == nil {
			return fleet.APIContextReceiver{}, fleet.ErrUnavailable
		}
		if e := s.pullSource(c); e != nil {
			return fleet.APIContextReceiver{}, fleet.ErrUnavailable
		}
		return check(c)
	}
	standby, e := h.router.RegisterStandby(residence, receiver, attach)
	stop()
	release()
	if e != nil {
		h.refuse(w, "standby")
		return
	}
	defer standby.Finish()
	stream, e := newFrameStream(standby.Context(), receiver.Channel, check, r.Body, w, controller.SetReadDeadline, controller.SetWriteDeadline, controller.Flush, func() {
		_ = controller.SetReadDeadline(time.Now())
		_ = controller.SetWriteDeadline(time.Now())
		_ = r.Body.Close()
	})
	if e != nil {
		h.refuse(w, "stream")
		return
	}
	defer stream.Close()
	stream.sources = sources
	// Hello and the first source were read before the stream was constructed.
	stream.frames = 2
	stream.bytes = contracts.APIContextWorkBytes + 5 + contracts.APIContextSourceBytes + 5 // Same ceilings as the connector.
	current.Store(stream)
	if controller.SetWriteDeadline(receiver.ValidUntil) != nil || !time.Now().Before(receiver.ValidUntil) {
		return
	}
	w.Header().Set("Content-Type", contracts.APIContextStartMedia)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	if controller.Flush() != nil {
		return
	}
	// After the authenticated empty response header, only passive waiting remains.
	// No work/identity frame can use this residency bound: frameStream requires a
	// new exact work peer observation. Identity frames retain its original bound;
	// final results recheck the exact peer without extending that work lease.
	idleUntil, _ := standby.Context().Deadline()
	if controller.SetReadDeadline(idleUntil) != nil || controller.SetWriteDeadline(idleUntil) != nil {
		return
	}
	_ = standby.Serve(stream, time.Now)
}
