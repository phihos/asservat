package mtls

import (
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	value "asservat.local/asservat/internal/domain/fleet"
)

// ConnectorObservationProducer is local to the process owning the actual
// connector keys. It reads native proof and checks its own live key/leaf;
// observing never reconciles a process, enrolls, signs or activates a leaf.
type ConnectorObservationProducer struct {
	pin         value.ConnectorObservationPin
	credentials *ConnectorProcessCredentials
	attester    app.ConnectorObservationProofReader
	workloads   app.ConnectorObservationWorkloadReader
	now         func() time.Time
}

func NewConnectorObservationProducer(pin value.ConnectorObservationPin, credentials *ConnectorProcessCredentials, attester app.ConnectorObservationProofReader, workloads app.ConnectorObservationWorkloadReader, now func() time.Time) (*ConnectorObservationProducer, error) {
	if !pin.Valid() || credentials == nil || !credentials.profile.Equal(pin.Profile) || attester == nil || workloads == nil || now == nil {
		return nil, value.ErrInvalid
	}
	return &ConnectorObservationProducer{pin.Clone(), credentials, attester, workloads, now}, nil
}
