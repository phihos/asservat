// Package worker implements only confidential acquisition credential bootstrap.
// Native evidence and human credentials are absent from this protocol.
package worker

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
)

type Handler struct {
	enrollment   evidence.AcquisitionEnrollmentExchange
	installation string
	now          func() time.Time
	slots        chan struct{}
	// Refused, if set before serving, receives the parent purpose and the
	// staged error of a refused enrollment. The response stays a bare 503.
	Refused func(context.Context, string, error)
}

func NewHandler(installation string, enrollment evidence.WorkerEnrollmentExchange, now func() time.Time, concurrency int) (*Handler, error) {
	if enrollment == nil {
		return nil, artifact.ErrInvalid
	}
	return NewAcquisitionHandler(installation, evidence.DownloadEnrollmentExchange{Download: enrollment}, now, concurrency)
}

func NewAcquisitionHandler(installation string, enrollment evidence.AcquisitionEnrollmentExchange, now func() time.Time, concurrency int) (*Handler, error) {
	if !value.UUID(installation) || enrollment == nil || now == nil || concurrency < 1 || concurrency > 16 {
		return nil, artifact.ErrInvalid
	}
	return &Handler{enrollment: enrollment, installation: installation, now: now, slots: make(chan struct{}, concurrency)}, nil
}

// The private listener must pin server trust, enforce TLS 1.3, header/idle/time
// and connection bounds. Initial authentication is dedicated Pod TokenReview;
// demanding an already-issued client certificate would make bootstrap circular.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	fail := func(code int) { r.Close = true; w.Header().Set("Connection", "close"); w.WriteHeader(code) }
	if h == nil || h.enrollment == nil || h.now == nil || h.slots == nil {
		fail(503)
		return
	}
	if r.TLS == nil || !r.TLS.HandshakeComplete || r.TLS.Version != tls.VersionTLS13 {
		fail(403)
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != contracts.WorkerEnrollmentPath || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.IsAbs() || len(r.Header.Values("Content-Type")) != 1 || r.Header.Get("Content-Type") != "application/json" || len(r.Header.Values("Authorization")) != 1 || len(r.Header.Values("Cookie")) != 0 || len(r.Header.Values("Content-Encoding")) != 0 || r.ContentLength > contracts.WorkerEnrollmentMaxRequest || len(r.Trailer) != 0 {
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
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	secret := []byte(token)
	defer clear(secret)
	if !ok || !contracts.ValidWorkerToken(secret) {
		fail(403)
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
	in, err := contracts.DecodeWorkerEnrollmentRequest(http.MaxBytesReader(w, r.Body, contracts.WorkerEnrollmentMaxRequest))
	parent := value.AcquisitionParentFor(in.SessionID, in.QueryID)
	if err != nil || in.Format != contracts.WorkerEnrollmentFormat || in.InstallationID != h.installation || !parent.Valid() || !value.UUID(in.WorkerID) || !contracts.ValidWorkerNonce(in.Nonce) || len(in.CSR) < 32 || len(in.CSR) > 8192 {
		fail(400)
		return
	}
	delivery, err := h.enrollment.BeginAcquisitionEnrollment(ctx, in.InstallationID, parent, in.WorkerID, secret, in.CSR)
	if delivery != nil {
		defer delivery.Close()
	}
	if err != nil || delivery == nil || delivery.Context() == nil {
		if err != nil && h.Refused != nil {
			h.Refused(ctx, string(parent.Purpose), err)
		}
		fail(503)
		return
	}
	owner := delivery.Context()
	ownerDeadline, bounded := owner.Deadline()
	if !bounded || owner.Err() != nil || ctx.Err() != nil {
		fail(503)
		return
	}
	if ownerDeadline.Before(deadline) {
		deadline = ownerDeadline
	}
	cert := delivery.Certificate()
	if ctx.Err() != nil || owner.Err() != nil || !cert.Peer.Valid(h.now()) || cert.Peer.InstallationID != h.installation || cert.Peer.Role != "acquisition" || len(cert.DER) < 1 || len(cert.DER) > 16<<10 || len(cert.ChainDER) > 3 || artifact.Digest(sha256.Sum256(cert.DER)) != cert.Peer.Certificate {
		fail(503)
		return
	}
	chain := make([][]byte, len(cert.ChainDER))
	total := len(cert.DER)
	for i, der := range cert.ChainDER {
		if len(der) < 1 || len(der) > 16<<10 {
			fail(503)
			return
		}
		total += len(der)
		chain[i] = der
	}
	if total > 32<<10 {
		fail(503)
		return
	}
	out := contracts.WorkerEnrollmentResponse{Format: contracts.WorkerEnrollmentFormat, InstallationID: in.InstallationID, SessionID: in.SessionID, QueryID: in.QueryID, WorkerID: in.WorkerID, Nonce: in.Nonce, Certificate: cert.DER, Chain: chain}
	b, err := json.Marshal(out)
	if err != nil || len(b) > contracts.WorkerEnrollmentMaxResponse || ctx.Err() != nil || owner.Err() != nil || !cert.Peer.Valid(h.now()) {
		fail(503)
		return
	}
	if cert.Peer.NotAfter.Before(deadline) {
		deadline = cert.Peer.NotAfter
	}
	if control.SetWriteDeadline(deadline) != nil {
		fail(503)
		return
	}
	// Keep owner cancellation live during a blocked write. Join an already
	// started deadline callback before resetting the connection for reuse.
	interrupted := make(chan struct{})
	stop := context.AfterFunc(owner, func() { _ = control.SetWriteDeadline(time.Now()); close(interrupted) })
	defer func() {
		if !stop() {
			<-interrupted
		}
	}()
	if owner.Err() != nil || ctx.Err() != nil {
		fail(503)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
	_ = control.Flush()
}
