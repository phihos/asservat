package mtls

import (
	"io"
	"net/http"
	"sync"

	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/fleet"
)

func streamHello(w http.ResponseWriter, r *http.Request) (contracts.ClusterObservationHello, error) {
	if r.ProtoMajor != 2 || r.TLS == nil || !r.TLS.HandshakeComplete || r.ContentLength != -1 || r.Method != http.MethodPost || r.URL.Path != contracts.ClusterObservationExchangePath || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Idempotency-Key") != "" {
		return contracts.ClusterObservationHello{}, value.ErrDenied
	}
	frame, err := contracts.ReadClusterObservationFrame(r.Body)
	if err != nil || frame.Kind != contracts.ClusterObservationHelloFrame {
		return contracts.ClusterObservationHello{}, value.ErrDenied
	}
	hello, err := contracts.DecodeClusterObservationHello(frame.Payload)
	clear(frame.Payload)
	if err != nil {
		return hello, err
	}
	w.Header().Set("Content-Type", contracts.ClusterObservationExchangeMedia)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	err = http.NewResponseController(w).Flush()
	return hello, err
}

type observationEnteredRead struct {
	io.ReadCloser
	entered chan struct{}
	once    sync.Once
}

func (r *observationEnteredRead) Read(b []byte) (int, error) {
	r.once.Do(func() { close(r.entered) })
	return r.ReadCloser.Read(b)
}
