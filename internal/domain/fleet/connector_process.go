package fleet

import "asservat.local/asservat/internal/domain/authorization"

// ConnectorProcessIdentity names one connector process: its peer binding, Pod
// and process epoch.
type ConnectorProcessIdentity struct {
	Binding              PeerBinding
	PodUID, ProcessEpoch string
}

func (p ConnectorProcessIdentity) Valid() bool {
	return p.Binding.Valid() && p.Binding.Role == ConnectorPeer && authorization.UUID(p.PodUID) && authorization.UUID(p.ProcessEpoch)
}
