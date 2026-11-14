package mtls

import (
	"net/http"

	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/fleet"
)

func operationStreamHello(w http.ResponseWriter, r *http.Request) (contracts.ClusterObservationHello, error) {
	if r.ProtoMajor != 2 || r.TLS == nil || !r.TLS.HandshakeComplete || r.ContentLength != -1 || r.Method != http.MethodPost || r.URL.Path != contracts.ClusterObservationOperationExchangePath || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Idempotency-Key") != "" {
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
	w.Header().Set("Content-Type", contracts.ClusterObservationOperationExchangeMedia)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	err = http.NewResponseController(w).Flush()
	return hello, err
}
