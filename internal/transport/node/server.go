package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/collector"
)

// Handler serves the three node routes. Enrollment needs no client
// certificate; poll and status need a client certificate that the TLS layer
// verified against the connector's node issuer and that still maps to the
// node's current process. Error bodies are empty: status codes are the only
// signal (400 invalid, 401 unknown process, 403 attestation denied, 409 stale
// process, 429 too soon, 503 unavailable).
type Handler struct {
	channel *delivery.NodeChannel
	hold    time.Duration
}

func NewHandler(ch *delivery.NodeChannel) (*Handler, error) {
	if ch == nil {
		return nil, delivery.ErrNodeInvalid
	}
	return &Handler{channel: ch, hold: collector.PollHold}, nil
}

func status(err error) int {
	switch {
	case errors.Is(err, delivery.ErrNodeInvalid):
		return http.StatusBadRequest
	case errors.Is(err, delivery.ErrNodeUnauthenticated):
		return http.StatusUnauthorized
	case errors.Is(err, delivery.ErrNodeDenied):
		return http.StatusForbidden
	case errors.Is(err, delivery.ErrNodeConflict):
		return http.StatusConflict
	case errors.Is(err, delivery.ErrNodeRateLimited):
		return http.StatusTooManyRequests
	}
	return http.StatusServiceUnavailable
}

func write(w http.ResponseWriter, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

func (h *Handler) peer(r *http.Request) (delivery.NodePeer, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 {
		return delivery.NodePeer{}, delivery.ErrNodeUnauthenticated
	}
	return h.channel.Peer(sha256.Sum256(r.TLS.PeerCertificates[0].Raw))
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.TLS == nil || r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/json" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	body := http.MaxBytesReader(w, r.Body, contracts.NodeMaxRequest)
	switch r.URL.Path {
	case contracts.NodeEnrollPath:
		req, err := contracts.DecodeNodeEnrollRequest(body)
		token := []byte(req.Token)
		defer clear(token)
		if err != nil || req.Format != contracts.NodeEnrollFormat || !contracts.ValidWorkerToken(token) || len(req.CSR) > contracts.NodeMaxCertificate {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		der, notAfter, id, err := h.channel.Enroll(r.Context(), token, req.CSR, req.BootID, req.Epoch)
		if err != nil {
			w.WriteHeader(status(err))
			return
		}
		write(w, contracts.NodeEnrollResponse{Format: contracts.NodeEnrollFormat, Certificate: der, NotAfter: notAfter, NodeName: id.NodeName, NodeUID: id.NodeUID})
	case contracts.NodePollPath:
		p, err := h.peer(r)
		if err != nil {
			w.WriteHeader(status(err))
			return
		}
		req, err := contracts.DecodeNodePollRequest(body)
		if err != nil || req.Format != contracts.NodePollFormat {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), h.hold+5*time.Second)
		defer cancel()
		work, err := h.channel.Poll(ctx, p, req.Epoch, req.After, h.hold)
		if err != nil {
			w.WriteHeader(status(err))
			return
		}
		out := contracts.NodePollResponse{Format: contracts.NodePollFormat, Work: []contracts.NodeWork{}}
		for _, item := range work {
			out.Work = append(out.Work, WireWork(item))
		}
		write(w, out)
	case contracts.NodeStatusPath:
		p, err := h.peer(r)
		if err != nil {
			w.WriteHeader(status(err))
			return
		}
		s, err := contracts.DecodeNodeStatus(body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		report, ok := DomainStatus(s)
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := h.channel.Report(p, s.Epoch, report); err != nil {
			w.WriteHeader(status(err))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(body, 1))
}

// encode marshals a request body; shared by the client.
func encode(v any) (*bytes.Reader, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(b), nil
}

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }
