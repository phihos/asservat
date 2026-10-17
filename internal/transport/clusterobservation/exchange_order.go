package clusterobservation

import "asservat.local/asservat/internal/contracts"

// One closed conversation, not a registry of messages/purposes. Send admission
// precedes writing; received frames pass this check before application dispatch.
// Any I/O failure closes the owning stream. It cannot rewind the order to retry
// an unknown write or reinterpret a partially read frame as another result.
type exchangeOrder struct {
	next   int
	bytes  int
	failed bool
}

type observationStep struct {
	kind         contracts.ClusterObservationFrameKind
	fromRegional bool
}

var observationSteps = [...]observationStep{
	{contracts.ClusterObservationHelloFrame, true},
	{contracts.ClusterObservationProbeFrame, false},
	{contracts.ClusterObservationSourceFrame, true},
	{contracts.ClusterObservationProbeFrame, false},
	{contracts.ClusterObservationSourceFrame, true},
	{contracts.ClusterObservationReadFrame, false},
	{contracts.ClusterObservationResultFrame, true},
	{contracts.ClusterObservationProbeFrame, false},
	{contracts.ClusterObservationSourceFrame, true},
	{contracts.ClusterObservationProbeFrame, false},
	{contracts.ClusterObservationSourceFrame, true},
	{contracts.ClusterObservationReceiptFrame, false},
}

func (o *exchangeOrder) admit(kind contracts.ClusterObservationFrameKind, fromRegional bool, bytes int) error {
	if o == nil || o.failed {
		return contracts.ErrClusterObservationProtocol
	}
	if o.next >= len(observationSteps) || o.next >= contracts.ClusterObservationMaximumFrames || bytes < 1 || bytes > contracts.ClusterObservationExchangeBytes-o.bytes-5 || observationSteps[o.next] != (observationStep{kind, fromRegional}) {
		o.failed = true
		return contracts.ErrClusterObservationProtocol
	}
	o.next++
	o.bytes += bytes + 5
	return nil
}

func (o *exchangeOrder) complete() bool {
	return o != nil && !o.failed && o.next == len(observationSteps)
}
