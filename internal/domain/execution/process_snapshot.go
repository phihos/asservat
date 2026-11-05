package execution

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"time"
)

type ProcessSnapshotRequest struct {
	Pin                       artifact.PinnedPod
	NodeUID, NodeBootID, Mode string
	NativeLimit               int64
	NotBefore, Deadline       time.Time
}

func (r ProcessSnapshotRequest) Valid() bool {
	return identity.Text(r.Pin.Namespace, 63) && identity.Text(r.Pin.Name, 253) && identity.Text(r.Pin.UID, 128) &&
		identity.Text(r.Pin.NamespaceUID, 128) && identity.Text(r.Pin.NodeName, 253) && identity.Text(r.NodeUID, 128) &&
		authorization.UUID(r.NodeBootID) && (r.Mode == artifact.ProcessMain || r.Mode == artifact.ProcessAll) &&
		r.NativeLimit > 0 && r.NativeLimit <= artifact.ProcessNativeLimit && !r.NotBefore.IsZero() &&
		r.Deadline.After(r.NotBefore) && r.Deadline.Sub(r.NotBefore) <= 5*time.Second
}
