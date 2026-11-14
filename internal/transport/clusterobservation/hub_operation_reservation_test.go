package clusterobservation

import (
	"testing"
)

func cleanReservation(t *testing.T, e *hubObservationOperationEntry, r *HubObservationOperationReservation) {
	t.Helper()
	t.Cleanup(func() {
		closed := make(chan struct{})
		go func() { r.Close(); close(closed) }()
		e.close()
		<-closed
	})
}

func joinReservedHandler(e *hubObservationOperationEntry) <-chan struct{} {
	joined := make(chan struct{})
	go func() { <-e.resultDone; e.close(); close(joined) }()
	return joined
}
