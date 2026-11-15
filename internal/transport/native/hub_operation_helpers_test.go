package native

import (
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
)

// Test constructors: each performs the full current admission check, then
// the production newHubOperationChecked.

func NewHubOperation(gate *evidence.NativeFrameGate, c contracts.NativeCommand, expected evidence.NativeContextSource, complete evidence.NativeCompletion) (*HubOperation, error) {
	if c.Kind == string(value.NativeResponse) {
		return nil, artifact.ErrInvalid
	}
	return newHubOperation(gate, c, expected, artifact.DownloadDeliveryLease{}, complete)
}

// NewHubResponseOperation pins the complete original delivery lease locally.
// Neither the worker command nor a matching range can substitute another owner,
// scope or current authority observation when acknowledging a final sink write.
func NewHubResponseOperation(gate *evidence.NativeFrameGate, c contracts.NativeCommand, expected evidence.NativeContextSource, delivery artifact.DownloadDeliveryLease, complete evidence.NativeCompletion) (*HubOperation, error) {
	if c.Kind != string(value.NativeResponse) || !delivery.Valid(time.Now()) {
		return nil, artifact.ErrInvalid
	}
	return newHubOperation(gate, c, expected, delivery, complete)
}
func newHubOperation(gate *evidence.NativeFrameGate, c contracts.NativeCommand, expected evidence.NativeContextSource, delivery artifact.DownloadDeliveryLease, complete evidence.NativeCompletion) (*HubOperation, error) {
	if gate == nil || complete == nil {
		return nil, artifact.ErrInvalid
	}
	checked, e := checkNativeAdmission(gate.Context(), gate)
	if e != nil {
		return nil, e
	}
	return newHubOperationChecked(gate, checked, c, expected, delivery, complete)
}
