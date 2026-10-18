package mtls

import (
	"context"

	value "asservat.local/asservat/internal/domain/execution"
)

// ContextStartProcessReader returns the connector observation already verified
// inside this exact executor's complete native proof. The concrete producer
// must require the same process-owned credentials instance and preserve the
// proof's original interval, including its registration and closing source.
// It supplies no new observation from a cached DTO or caller-chosen identity.
// Readers without that composition retain the independent checks.
type ContextStartProcessReader interface {
	ReadAPIProcessConnector(context.Context, *ConnectorProcessCredentials) (value.APIProcessObservation, ConnectorProcessObservation, error)
}
