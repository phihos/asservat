package mtls

import (
	"context"
	"sync"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
)

// This distinct v2 producer accepts only the installed concrete native-operation
// port and actual process credentials. It cannot impersonate a legacy full
// source or attestation reader. Each stream's private channel owns one begin.
type ConnectorObservationOperationProducer struct {
	pin         value.ConnectorObservationPin
	credentials *ConnectorProcessCredentials
	native      app.ConnectorNativeObservationOperations
	now         func() time.Time
}

type connectorProducedOperation struct {
	producer     *ConnectorObservationOperationProducer
	root         context.Context
	cancel       context.CancelFunc
	joinProcess  func()
	native       app.ConnectorNativeObservationOperation
	keys         connectorObservationKeys
	request      value.OwnerObservationRequest
	channel      artifact.Digest
	id           string
	mu           sync.Mutex
	closed, busy bool
	ordinal      int
	until        time.Time
	last         *value.ConnectorObservationOperationValue
	joined       sync.WaitGroup
	closeOnce    sync.Once
}
