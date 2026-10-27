package targets

import "asservat.local/asservat/internal/domain/artifact"

// RecorderRequest asks the region whether the node collector on the node of
// one resolved Pod currently offers the packet recorder (ADR-248). It names
// the Pod by its resolved request and pin; the region reads the Pod's node
// itself.
type RecorderRequest struct {
	Target Request
	Pin    artifact.PinnedPod
}

func (r RecorderRequest) Valid() bool {
	return r.Target.Valid() && r.Pin.UID == r.Target.PodUID && r.Pin.Name == r.Target.PodName && r.Pin.NamespaceUID == r.Target.Namespace.UID && r.Pin.Namespace == r.Target.Namespace.Name
}

// Closed recorder answers. Only RecorderAvailable allows a manual packet
// capture to be accepted; the connector checks the node again before work.
const (
	RecorderAvailable   = "available"
	RecorderUnavailable = "unavailable" // no current collector report offers it
	RecorderNoNode      = "noNode"      // the Pod is not running on a node
)

type RecorderAnswer struct {
	Outcome string
}

func (a RecorderAnswer) Valid() bool {
	return a.Outcome == RecorderAvailable || a.Outcome == RecorderUnavailable || a.Outcome == RecorderNoNode
}
