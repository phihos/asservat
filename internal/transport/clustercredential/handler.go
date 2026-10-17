// Package clustercredential serves the ADR-168 exporter-bound possession
// exchange on the hub's private listener. It carries public values only.
package clustercredential

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
)

// Presenter is the hub's possession check (fleetapp.ClusterCredentialVerifier).
type Presenter interface {
	Present(context.Context, value.ClusterCredentialRequest, []byte, []byte) (value.ClusterCredentialPresentation, error)
}

type Handler struct {
	presenter Presenter
	slots     chan struct{}
}

func NewHandler(p Presenter, concurrency int) (*Handler, error) {
	if p == nil || concurrency < 1 || concurrency > 16 {
		return nil, value.ErrClusterCredentialDenied
	}
	return &Handler{p, make(chan struct{}, concurrency)}, nil
}

// Exporter derives the 32-byte value both ends sign over from this TLS session.
func Exporter(state *tls.ConnectionState) ([]byte, error) {
	if state == nil || !state.HandshakeComplete || state.Version != tls.VersionTLS13 {
		return nil, value.ErrClusterCredentialDenied
	}
	return state.ExportKeyingMaterial(value.ClusterCredentialExporter, nil, contracts.ClusterCredentialExporterLen)
}

func Request(w contracts.ClusterCredentialWire) (value.ClusterCredentialRequest, error) {
	r := value.ClusterCredentialRequest{Operation: w.Operation, Profile: value.ClusterCredentialProfile{RootID: w.RootID, PeerID: w.PeerID, InstallationID: w.InstallationID, ClusterID: w.ClusterID}, Generation: w.Generation, PodUID: w.PodUID, ProcessEpoch: w.ProcessEpoch, NextKey: w.NextKey, RequestedAt: w.RequestedAt}
	for _, k := range []struct {
		raw []byte
		out *artifact.Digest
	}{{w.ClientKey, &r.ClientKey}, {w.ServerKey, &r.ServerKey}} {
		if len(k.raw) == 0 {
			continue
		}
		if len(k.raw) != len(k.out) {
			return r, value.ErrClusterCredentialDenied
		}
		copy(k.out[:], k.raw)
	}
	if !r.Valid() {
		return r, value.ErrClusterCredentialDenied
	}
	return r, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	fail := func(code int) { r.Close = true; w.Header().Set("Connection", "close"); w.WriteHeader(code) }
	if h == nil || h.presenter == nil {
		fail(http.StatusServiceUnavailable)
		return
	}
	exporter, err := Exporter(r.TLS)
	if err != nil {
		fail(http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != contracts.ClusterCredentialPath || r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/json" || len(r.Header.Values("Authorization")) != 0 || len(r.Header.Values("Cookie")) != 0 || r.ContentLength > contracts.ClusterCredentialMaxRequest {
		fail(http.StatusBadRequest)
		return
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		fail(http.StatusTooManyRequests)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	in, err := contracts.DecodeClusterCredentialWire(http.MaxBytesReader(w, r.Body, contracts.ClusterCredentialMaxRequest))
	if err != nil {
		fail(http.StatusBadRequest)
		return
	}
	request, err := Request(in)
	if err != nil {
		fail(http.StatusBadRequest)
		return
	}
	p, err := h.presenter.Present(ctx, request, in.Signature, exporter)
	switch {
	case errors.Is(err, value.ErrClusterCredentialFenced):
		fail(http.StatusConflict) // permanent: administrator reenrollment required
		return
	case err != nil || ctx.Err() != nil:
		fail(http.StatusForbidden)
		return
	}
	body, err := json.Marshal(contracts.ClusterCredentialReply{Format: contracts.ClusterCredentialWireFormat, LineageID: p.LineageID, Generation: p.Generation, CheckedAt: p.CheckedAt, ValidUntil: p.ValidUntil})
	if err != nil {
		fail(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// Wire encodes a signed request for the exchange or the lifecycle opening.
func Wire(r value.ClusterCredentialRequest, signature []byte) contracts.ClusterCredentialWire {
	w := contracts.ClusterCredentialWire{Format: contracts.ClusterCredentialWireFormat, Operation: r.Operation, RootID: r.Profile.RootID, PeerID: r.Profile.PeerID, InstallationID: r.Profile.InstallationID, ClusterID: r.Profile.ClusterID, Generation: r.Generation, PodUID: r.PodUID, ProcessEpoch: r.ProcessEpoch, NextKey: r.NextKey, RequestedAt: r.RequestedAt, Signature: signature}
	if r.Operation != value.ClusterRotation {
		w.ClientKey, w.ServerKey = append([]byte(nil), r.ClientKey[:]...), append([]byte(nil), r.ServerKey[:]...)
	}
	return w
}
