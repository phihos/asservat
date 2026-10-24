package keyservice

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	app "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
)

type PeerVerifier interface {
	Verify(*tls.ConnectionState) (value.KeyPeer, error)
}

// ContextPeerVerifier resolves peers with request-scoped reads (ADR-198);
// the handler then passes its request context.
type ContextPeerVerifier interface {
	VerifyContext(context.Context, *tls.ConnectionState) (value.KeyPeer, error)
}

type Handler struct {
	services  map[value.KeyScope]app.KeyService
	peers     PeerVerifier
	now       func() time.Time
	semaphore chan struct{}
	// Report, when set before serving, receives the closed stage of a refused
	// request; never request content, keys or identities.
	Report func(stage string)
}

func NewHandler(services []app.KeyService, peers PeerVerifier, now func() time.Time, concurrency int) (*Handler, error) {
	if len(services) < 1 || len(services) > 32 || peers == nil || now == nil || concurrency < 1 || concurrency > 64 {
		return nil, app.ErrKeyUnavailable
	}
	h := &Handler{services: make(map[value.KeyScope]app.KeyService), peers: peers, now: now, semaphore: make(chan struct{}, concurrency)}
	installation := services[0].Scope.InstallationID
	for _, service := range services {
		if _, ok := service.Backend.(app.KeyConfigurationGuard); !ok {
			return nil, app.ErrKeyUnavailable
		}
		if !service.Scope.Valid() || service.Scope.InstallationID != installation || service.Now == nil || service.Authority == nil || service.Backend == nil {
			return nil, app.ErrKeyUnavailable
		}
		if _, exists := h.services[service.Scope]; exists {
			return nil, app.ErrKeyUnavailable
		}
		h.services[service.Scope] = service
	}
	return h, nil
}

// ServeHTTP requires direct TLS state. Bootstrap must also set TLS 1.3,
// RequireAndVerifyClientCert, pinned client roots, finite server header/idle
// limits and private routing. No forwarded client identity is accepted.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	deny := func(stage string, code int) {
		if h != nil && h.Report != nil {
			h.Report(stage)
		}
		w.WriteHeader(code)
	}
	if h == nil || h.peers == nil || h.now == nil || h.semaphore == nil {
		deny("configuration", 503)
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != contracts.KeyServicePath || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.IsAbs() || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Content-Encoding") != "" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.ContentLength > contracts.KeyServiceMaxBody {
		deny("request-shape", 400)
		return
	}
	select {
	case h.semaphore <- struct{}{}:
		defer func() { <-h.semaphore }()
	default:
		deny("busy", 429)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	control := http.NewResponseController(w)
	deadline, _ := ctx.Deadline()
	if control.SetReadDeadline(deadline) != nil || control.SetWriteDeadline(deadline) != nil {
		deny("deadline", 503)
		return
	}
	// Expired request deadlines must not poison a reusable keep-alive socket.
	defer control.SetReadDeadline(time.Time{})
	defer control.SetWriteDeadline(time.Time{})
	var peer value.KeyPeer
	var err error
	if c, ok := h.peers.(ContextPeerVerifier); ok {
		peer, err = c.VerifyContext(ctx, r.TLS)
	} else {
		peer, err = h.peers.Verify(r.TLS)
	}
	if err != nil || !peer.Valid(h.now()) {
		deny("peer", 403)
		return
	}
	wire, err := contracts.DecodeKeyRequest(http.MaxBytesReader(w, r.Body, contracts.KeyServiceMaxBody))
	defer clear(wire.Input)
	defer clear(wire.Binding)
	if err != nil || wire.Format != contracts.KeyServiceFormat {
		r.Close = true
		w.Header().Set("Connection", "close")
		deny("decode", 400)
		return
	}
	request := value.KeyRequest{Scope: value.KeyScope{InstallationID: wire.Scope.InstallationID, Purpose: wire.Scope.Purpose, KeyID: wire.Scope.KeyID}, AuthorityID: wire.AuthorityID, Operation: wire.Operation, Binding: wire.Binding, Input: wire.Input, Version: wire.Version}
	if wire.Sealed != nil {
		request.Sealed = artifact.SealedKey{Reference: wire.Sealed.Reference, Ciphertext: wire.Sealed.Ciphertext}
	}
	if !request.Valid() || (wire.Operation == "unwrap") != (wire.Sealed != nil) {
		deny("request", 400)
		return
	}
	service, ok := h.services[request.Scope]
	if !ok {
		deny("scope", 403)
		return
	}
	result, err := service.Execute(ctx, peer, request)
	defer clear(result.Output)
	if err != nil {
		stage := "unavailable"
		code := 503
		if errors.Is(err, app.ErrKeyDenied) {
			stage, code = "denied", 403
		}
		var fixed interface{ FixedStep() string }
		if errors.As(err, &fixed) {
			stage += "/" + fixed.FixedStep()
		}
		deny(stage, code)
		return
	}
	out := contracts.KeyServiceResponse{Format: contracts.KeyServiceFormat, Operation: request.Operation, RequestSHA256: hex.EncodeToString(result.RequestDigest[:]), ValidUntil: result.ValidUntil.UTC().Format(time.RFC3339Nano), Output: result.Output}
	if request.Operation == "wrap" {
		out.Sealed = &contracts.SealedLocalKey{Reference: result.Sealed.Reference, Ciphertext: result.Sealed.Ciphertext}
	}
	b, err := json.Marshal(out)
	defer clear(b)
	if err != nil || len(b) > contracts.KeyServiceMaxBody || ctx.Err() != nil || !h.now().Before(result.ValidUntil) || !peer.Valid(h.now()) {
		deny("response", 503)
		return
	}
	if result.ValidUntil.Before(deadline) {
		deadline = result.ValidUntil
	}
	if control.SetWriteDeadline(deadline) != nil {
		deny("write", 503)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
	// net/http may buffer a short response until after ServeHTTP returns. Flush
	// secret output while its original write deadline is still in force.
	_ = control.Flush()
}
