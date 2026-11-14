package mtls

import (
	"context"

	app "asservat.local/asservat/internal/application/fleet"
)

// ConnectorObservationClient opens one purpose-fixed outbound standby at a
// time per admitted slot. Its address is an installed dial hint; the actual
// TLS server must belong to the independently read finite original-pool set.
// Open neither enrolls a process nor grants metadata authority. The attached
// channel performs fresh owner/source checks before each numbered proof.
type ConnectorObservationClient struct {
	base     *OwnerObservationClient
	producer *ConnectorObservationProducer
	metadata app.ClusterObservationExchange
}

// The callback only cancels; its join never waits for network work. The owning
// connection closes and joins actual I/O separately before releasing its slot.
func linkObservationCancellation(root context.Context, cancel context.CancelFunc) func() {
	done := make(chan struct{})
	stop := context.AfterFunc(root, func() { cancel(); close(done) })
	return func() {
		if !stop() {
			<-done
		}
	}
}
