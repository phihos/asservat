package authorization

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"time"
)

// KeyWorkerBinding is assigned by protected dispatch, never inferred from a
// caller's labels or ownerReferences. Worker and evidence cluster IDs differ.
type KeyWorkerBinding struct {
	InstallationID, DownloadID, ClusterID string
	Namespace, NamespaceUID               string
	ServiceAccount, ServiceAccountUID     string
	Job, JobUID                           string
	Pod, PodUID                           string
	JobSpec, PodSpec                      artifact.Digest
}

func (b KeyWorkerBinding) Valid() bool {
	return UUID(b.InstallationID) && UUID(b.DownloadID) && UUID(b.ClusterID) && identity.Text(b.Namespace, 63) && identity.Text(b.NamespaceUID, 64) && identity.Text(b.ServiceAccount, 253) && identity.Text(b.ServiceAccountUID, 64) && identity.Text(b.Job, 63) && identity.Text(b.JobUID, 64) && identity.Text(b.Pod, 253) && UUID(b.PodUID) && b.JobSpec != (artifact.Digest{}) && b.PodSpec != (artifact.Digest{})
}

// KeyWorkerProof is a short-lived observation, not a certificate issuance or
// evidence grant. No bearer token or workload spec is persisted in it.
type KeyWorkerProof struct {
	Binding                KeyWorkerBinding
	Peer                   KeyPeer
	TokenDigest            artifact.Digest
	ObservedAt, FreshUntil time.Time
}

func (p KeyWorkerProof) Valid(now time.Time) bool {
	return p.Binding.Valid() && p.Peer.Valid(now) && p.Peer.Role == "acquisition" && p.Peer.InstallationID == p.Binding.InstallationID && p.Peer.PeerID == p.Binding.PodUID && p.TokenDigest != (artifact.Digest{}) && identity.Fresh(p.ObservedAt, p.FreshUntil, now, 5*time.Second) && !p.FreshUntil.After(p.Peer.NotAfter)
}
