package mtls

import (
	app "asservat.local/asservat/internal/application/fleet"
)

// ConnectorObservationOperationClient opens one purpose-fixed outbound standby at a
// time per admitted slot. Its address is an installed dial hint; the actual
// TLS server must belong to the independently read finite original-pool set.
// Open neither enrolls a process nor grants metadata authority. The attached
// channel performs fresh owner/source checks before each numbered proof.
type ConnectorObservationOperationClient struct {
	base     *OwnerObservationClient
	producer *ConnectorObservationOperationProducer
	metadata app.ClusterObservationExchange
}
