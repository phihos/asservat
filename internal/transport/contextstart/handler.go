package contextstart

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/fleet"
)

// Ingress binds a hello to the cluster its connector's ServiceAccount token
// was attributed to and returns a check that never outlives the token.
// Hello strings are matching inputs, never caller-selected peers.
type Ingress interface {
	AuthenticateContextStart(context.Context, contracts.APIContextHello, fleet.ConnectorCluster, time.Time) (fleet.APIContextReceiver, ReceiverCheck, error)
}

// TokenVerifier attributes a connector's projected ServiceAccount token to
// its registered cluster (ADR-334) and returns the token's expiry.
type TokenVerifier interface {
	VerifyConnectorUntil(context.Context, string) (fleet.ConnectorCluster, time.Time, error)
}
type Handler struct {
	host      string
	router    *Router
	ingress   Ingress
	tokens    TokenVerifier
	preflight chan struct{}
	// Refused, when set, receives a fixed stage name for each refusal. It carries
	// no request data and changes no response.
	Refused func(string)
}

func NewHandler(host string, router *Router, ingress Ingress, tokens TokenVerifier, preflight int) (*Handler, error) {
	if host == "" || strings.ContainsAny(host, "/\\ \r\n\t") || router == nil || ingress == nil || tokens == nil || preflight < 1 {
		return nil, fleet.ErrInvalid
	}
	return &Handler{host: host, router: router, ingress: ingress, tokens: tokens, preflight: make(chan struct{}, preflight)}, nil
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
	token, bearer := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !bearer || token == "" || len(r.Header.Values("Authorization")) != 1 {
		h.refuse(w, "token")
		return
	}
	for _, k := range []string{"Cookie", "Origin", "Referer", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Content-Encoding", "Idempotency-Key", "X-Idempotency-Key"} {
		if len(r.Header.Values(k)) != 0 {
			h.refuse(w, "header")
			return
		}
	}
	// The token is verified before any slot or hello read: an unauthenticated
	// caller holds no slot and learns nothing about the hub.
	verify, endVerify := context.WithTimeout(r.Context(), 5*time.Second)
	presented, tokenUntil, e := h.tokens.VerifyConnectorUntil(verify, token)
	endVerify()
	if e != nil {
		h.refuse(w, "token")
		return
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
	capabilities := contracts.NewConnectorCapabilities(hello.Capabilities)
	if e != nil || capabilities == nil || hello.Format != contracts.APIContextExchangeFormat || !time.Now().Before(hello.StandbyUntil) || hello.StandbyUntil.After(time.Now().Add(30*time.Second)) {
		stop()
		release()
		h.refuse(w, "hello")
		return
	}
	// ADR-334: one protocol major; within it the announced capabilities decide
	// which operations this connector receives.
	if hello.Protocol != contracts.ConnectorProtocolMajor {
		stop()
		release()
		if h.Refused != nil {
			h.Refused("connector-protocol")
		}
		// A clear refusal the connector logs. HTTP/2 forbids the Upgrade
		// header that HTTP/1.1 pairs with 426.
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusUpgradeRequired)
		_, _ = fmt.Fprintf(w, "Hub requires connector protocol major %d. Connector announced major %d (0 means unspecified). Use releases that speak the same protocol major.", contracts.ConnectorProtocolMajor, hello.Protocol)
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
	receiver, check, e := h.ingress.AuthenticateContextStart(ctx, hello, presented, tokenUntil)
	if e != nil || ctx.Err() != nil || !receiver.Valid(time.Now()) || check == nil {
		stop()
		release()
		h.refuse(w, "authenticate")
		return
	}
	var current atomic.Pointer[frameStream]
	attach := func(c context.Context) (fleet.APIContextReceiver, error) {
		s := current.Load()
		if s == nil {
			return fleet.APIContextReceiver{}, fleet.ErrUnavailable
		}
		// Failures are recorded for a caller's diagnostic context only, as
		// for queries; they change neither the result nor the stream.
		receiver, e := check(c)
		if e != nil {
			recordStreamDiagnostic(c, s, e, streamHubQueryCheck)
		}
		return receiver, e
	}
	standby, e := h.router.RegisterStandby(residence, receiver, attach)
	stop()
	release()
	if e != nil {
		h.refuse(w, "standby")
		return
	}
	defer standby.Finish()
	var served atomic.Bool
	stream, e := newFrameStream(standby.Context(), receiver.Channel, check, r.Body, w, controller.SetReadDeadline, controller.SetWriteDeadline, controller.Flush, func() {
		_ = controller.SetReadDeadline(time.Now())
		if !served.Load() {
			_ = controller.SetWriteDeadline(time.Now())
		}
		_ = r.Body.Close()
	})
	if e != nil {
		h.refuse(w, "stream")
		return
	}
	defer stream.Close()
	stream.capabilities = capabilities
	// Hello was read before the stream was constructed.
	stream.frames = 1
	stream.bytes = contracts.APIContextWorkBytes + 5 // Same ceiling as the connector.
	current.Store(stream)
	if controller.SetWriteDeadline(receiver.Window.Until()) != nil || !time.Now().Before(receiver.Window.Until()) {
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
	if stream.sentTerminalReceipt() {
		served.Store(true)
		stream.awaitPeerClose(standby.Context())
	}
}
