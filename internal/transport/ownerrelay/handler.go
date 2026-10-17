// Package ownerrelay receives finite worker-enrollment exchanges between
// authenticated hub processes. It never accepts evidence or human credentials.
package ownerrelay

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"net/http"
	"strings"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	fleet "asservat.local/asservat/internal/domain/fleet"
)

type RequestPeers interface {
	AuthenticateOwnerRequest(context.Context, *tls.ConnectionState) (fleet.AuthenticatedOwner, error)
	CheckOwnerServing(context.Context) (time.Time, error)
}
type Handler struct {
	binding fleet.OwnerBinding
	peers   RequestPeers
	owners  evidence.WorkerOwnerEnrollment
	now     func() time.Time
	slots   chan struct{}
}

func NewHandler(binding fleet.OwnerBinding, peers RequestPeers, owners evidence.WorkerOwnerEnrollment, now func() time.Time, concurrency int) (*Handler, error) {
	if !binding.Valid() || peers == nil || owners == nil || now == nil || concurrency < 1 || concurrency > 16 {
		return nil, artifact.ErrInvalid
	}
	return &Handler{binding, peers, owners, now, make(chan struct{}, concurrency)}, nil
}
func earlier(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

func (h *Handler) authenticate(ctx context.Context, state *tls.ConnectionState) (fleet.AuthenticatedOwner, time.Time, error) {
	var zero fleet.AuthenticatedOwner
	if state == nil || !state.HandshakeComplete || state.Version != tls.VersionTLS13 || state.DidResume || len(state.VerifiedChains) == 0 {
		return zero, time.Time{}, fleet.ErrDenied
	}
	start := h.now()
	ctx, cancel := context.WithDeadline(ctx, start.Add(5*time.Second))
	defer cancel()
	local, err := h.peers.CheckOwnerServing(ctx)
	if err != nil || !h.now().Before(local) || local.After(h.now().Add(5*time.Second)) {
		return zero, time.Time{}, fleet.ErrDenied
	}
	peer, err := h.peers.AuthenticateOwnerRequest(ctx, state)
	b := peer.Certificate.Binding
	if err != nil || ctx.Err() != nil || !peer.Valid(h.now()) || peer.Certificate.Usage != "client" || b.InstallationID != h.binding.InstallationID || b.ClusterID != h.binding.ClusterID || b.IssuerEpoch != h.binding.IssuerEpoch || !h.now().Before(local) {
		return zero, time.Time{}, fleet.ErrDenied
	}
	return peer, earlier(start.Add(5*time.Second), earlier(local, peer.ValidUntil)), nil
}
func samePeer(a, b fleet.AuthenticatedOwner) bool {
	return a.Certificate == b.Certificate && a.EnrollmentID == b.EnrollmentID && a.Pool == b.Pool && a.Pod == b.Pod && a.ReplicaSetUID == b.ReplicaSetUID && a.ConfigurationRevision == b.ConfigurationRevision && a.ProtectionDigest == b.ProtectionDigest
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	fail := func(code int) { r.Close = true; w.Header().Set("Connection", "close"); w.WriteHeader(code) }
	if h == nil || h.peers == nil || h.owners == nil {
		fail(503)
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != contracts.OwnerRelayPath || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.IsAbs() || len(r.Header.Values("Content-Type")) != 1 || r.Header.Get("Content-Type") != "application/json" || len(r.Header.Values("Authorization")) != 1 || len(r.Header.Values("Cookie")) != 0 || len(r.Header.Values("Content-Encoding")) != 0 || len(r.Header.Values("Expect")) != 0 || len(r.TransferEncoding) != 0 || len(r.Trailer) != 0 || r.ContentLength < 1 || r.ContentLength > contracts.OwnerRelayMaxRequest {
		fail(400)
		return
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		fail(429)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	control := http.NewResponseController(w)
	if control.SetReadDeadline(deadline) != nil || control.SetWriteDeadline(deadline) != nil {
		fail(503)
		return
	}
	defer control.SetReadDeadline(time.Time{})
	defer control.SetWriteDeadline(time.Time{})
	peer, until, err := h.authenticate(ctx, r.TLS)
	if err != nil {
		fail(403)
		return
	}
	if control.SetReadDeadline(earlier(until, deadline)) != nil {
		fail(503)
		return
	}
	in, err := contracts.DecodeOwnerRelayRequest(http.MaxBytesReader(w, r.Body, contracts.OwnerRelayMaxRequest))
	if err != nil || ctx.Err() != nil || !h.now().Before(until) {
		fail(400)
		return
	}
	if control.SetReadDeadline(deadline) != nil {
		fail(503)
		return
	}
	x, l := in.Enrollment, in.Locator
	lease := value.WorkerOwnerLease{Request: value.WorkerOwnerRequest{ID: l.RequestID, InstallationID: x.InstallationID, SessionID: x.SessionID, WorkerID: x.WorkerID, PodUID: l.PodUID, ProcessEpoch: l.ProcessEpoch, Until: l.Until}, Fence: l.Fence, Started: l.Started}
	if in.Format != contracts.OwnerRelayFormat || x.Format != contracts.WorkerEnrollmentFormat || x.InstallationID != h.binding.InstallationID || l.PodUID != h.binding.PodUID || l.ProcessEpoch != h.binding.ProcessEpoch || !lease.Valid(h.now()) || !contracts.ValidWorkerNonce(x.Nonce) || len(x.CSR) < 32 || len(x.CSR) > 8192 {
		fail(400)
		return
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	secret := []byte(token)
	defer clear(secret)
	if !ok || !contracts.ValidWorkerToken(secret) {
		fail(403)
		return
	}
	deadline = earlier(deadline, lease.Request.Until)
	call, end := context.WithDeadline(ctx, deadline)
	defer end()
	// Peer admission covers receipt only. The exact operation independently
	// repeats human, worker, locator, audit and signing authority during work.
	delivery, err := h.owners.BeginOwnedWorkerEnrollment(call, lease, secret, x.CSR)
	if delivery != nil {
		defer delivery.Close()
	}
	if err != nil || delivery == nil || delivery.Context() == nil {
		fail(503)
		return
	}
	owner := delivery.Context()
	ownerDeadline, bounded := owner.Deadline()
	if !bounded || owner.Err() != nil || call.Err() != nil {
		fail(503)
		return
	}
	deadline = earlier(deadline, ownerDeadline)
	check, stopCheck := context.WithDeadline(owner, deadline)
	stopCall := context.AfterFunc(call, stopCheck)
	defer func() { stopCall(); stopCheck() }()
	last, outputUntil, err := h.authenticate(check, r.TLS)
	if err != nil || !samePeer(peer, last) || call.Err() != nil || owner.Err() != nil {
		fail(403)
		return
	}
	deadline = earlier(deadline, outputUntil)
	cert := delivery.Certificate()
	if !cert.Peer.Valid(h.now()) || cert.Peer.InstallationID != h.binding.InstallationID || cert.Peer.Role != "acquisition" || len(cert.DER) < 1 || len(cert.DER) > 16<<10 || len(cert.ChainDER) > 3 || artifact.Digest(sha256.Sum256(cert.DER)) != cert.Peer.Certificate {
		fail(503)
		return
	}
	total := len(cert.DER)
	for _, der := range cert.ChainDER {
		if len(der) < 1 || len(der) > 16<<10 {
			fail(503)
			return
		}
		total += len(der)
	}
	if total > 32<<10 {
		fail(503)
		return
	}
	chain := make([][]byte, len(cert.ChainDER))
	copy(chain, cert.ChainDER)
	out := contracts.WorkerEnrollmentResponse{Format: contracts.WorkerEnrollmentFormat, InstallationID: x.InstallationID, SessionID: x.SessionID, WorkerID: x.WorkerID, Nonce: x.Nonce, Certificate: cert.DER, Chain: chain}
	deadline = earlier(deadline, cert.Peer.NotAfter)
	b, err := contracts.EncodeOwnerRelayResponse(contracts.OwnerRelayResponse{Format: contracts.OwnerRelayFormat, Until: deadline, Enrollment: out})
	if err != nil || !h.now().Before(deadline) || call.Err() != nil || owner.Err() != nil || control.SetWriteDeadline(deadline) != nil {
		fail(503)
		return
	}
	write, stopWrite := context.WithDeadline(check, deadline)
	defer stopWrite()
	done := make(chan struct{})
	stop := context.AfterFunc(write, func() { _ = control.SetWriteDeadline(time.Now()); close(done) })
	defer func() {
		if !stop() {
			<-done
		}
	}()
	if write.Err() != nil {
		fail(503)
		return
	}
	w.Header().Set("Content-Type", contracts.OwnerRelayContentType)
	// A finite content length/normal completed response would release the remote
	// owner too early. Flush the single frame, then keep the original operation
	// attached until the downstream caller closes or an original deadline fires.
	if _, err := w.Write(b); err != nil {
		return
	}
	if control.Flush() != nil {
		return
	}
	<-write.Done()
}
