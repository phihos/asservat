package analysis

import (
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// ContextProjectionWorkerBinding comes from protected query dispatch. It is
// deliberately independent of download worker/session types. Structural
// validity cannot establish actual Kubernetes admission or current ownership.
type ContextProjectionWorkerBinding struct {
	QueryID, WorkerID, InstallationID, ClusterID string
	Namespace, NamespaceUID                      string
	ServiceAccount, ServiceAccountUID            string
	Job, JobUID, Pod, PodUID                     string
	JobSpec, PodSpec                             artifact.Digest
	Configuration                                identity.Revision
}

func (b ContextProjectionWorkerBinding) Valid() bool {
	return authorization.UUID(b.QueryID) && authorization.UUID(b.WorkerID) && authorization.UUID(b.InstallationID) && authorization.UUID(b.ClusterID) &&
		identity.Text(b.Namespace, 63) && identity.Text(b.NamespaceUID, 64) && identity.Text(b.ServiceAccount, 253) && identity.Text(b.ServiceAccountUID, 64) &&
		identity.Text(b.Job, 63) && identity.Text(b.JobUID, 64) && identity.Text(b.Pod, 253) && authorization.UUID(b.PodUID) &&
		b.JobSpec != (artifact.Digest{}) && b.PodSpec != (artifact.Digest{}) && b.Configuration.Valid()
}

func (b ContextProjectionWorkerBinding) Matches(q ContextQuery, w ContextQueryWorker) bool {
	return b.Valid() && w.Matches(q) && b.QueryID == q.ID && b.WorkerID == q.WorkerID && b.InstallationID == q.Plan.InstallationID &&
		b.ClusterID == q.Plan.Profile.Path.AcquisitionClusterID && b.PodUID == w.PodUID && b.Configuration == w.Configuration
}

// This observation requires independent live token/object/protection and actual
// peer/process verification. It contains neither a token nor an unwrap permit.
type ContextProjectionWorkerProof struct {
	Binding                ContextProjectionWorkerBinding
	Peer                   authorization.KeyPeer
	ProcessEpoch           string
	PublicKey, TokenDigest artifact.Digest
	Protection             identity.Revision
	ObservedAt, ValidUntil time.Time
}

func (p ContextProjectionWorkerProof) Matches(q ContextQuery, w ContextQueryWorker, now time.Time) bool {
	return p.Binding.Matches(q, w) && p.Peer.Valid(now) && p.Peer.InstallationID == q.Plan.InstallationID && p.Peer.Role == "acquisition" &&
		p.Peer.PeerID == p.Binding.PodUID && p.Peer.PeerID == w.PeerID && p.Peer.Certificate == w.Certificate && p.ProcessEpoch == w.ProcessEpoch &&
		p.PublicKey != (artifact.Digest{}) && p.TokenDigest != (artifact.Digest{}) && p.Protection.Valid() &&
		identity.Fresh(p.ObservedAt, p.ValidUntil, now, 5*time.Second) && !p.ValidUntil.After(p.Peer.NotAfter) &&
		!p.Peer.NotAfter.After(q.CredentialUntil) && !p.ValidUntil.After(q.WorkerUntil)
}

type ContextProjectionKeyRole string

const (
	ContextProjectionDataKey     ContextProjectionKeyRole = "data-key"
	ContextProjectionIndexKey    ContextProjectionKeyRole = "index-key"
	ContextProjectionManifestKey ContextProjectionKeyRole = "manifest-key"
)

func (r ContextProjectionKeyRole) Mask() uint8 {
	switch r {
	case ContextProjectionDataKey:
		return 1
	case ContextProjectionIndexKey:
		return 2
	case ContextProjectionManifestKey:
		return 4
	default:
		return 0
	}
}

// ContextProjectionKeyBinding is the immutable query-only key child. The SQL
// consumer independently verifies the spent start and current request/worker;
// a serialized proof, certificate, Fresh bit or valid DTO is never sufficient.
type ContextProjectionKeyBinding struct {
	Purpose, ClaimID string
	Batch            ContextReadBatch
	SourceVersion    artifact.Digest
	Scope            authorization.KeyScope
	Worker           ContextProjectionWorkerProof
	Authority        ContextProjectionAuthority
	CreatedAt, Until time.Time
}

func (b ContextProjectionKeyBinding) Valid(q ContextQuery, now time.Time) bool {
	return b.Purpose == ContextProjectionPurpose && b.ClaimID == b.Batch.ID && b.Batch.Current(q, b.Authority, now) &&
		b.SourceVersion == q.Scope.Version && b.Scope.Valid() && b.Scope.Purpose == "artifact" && b.Scope.InstallationID == q.Plan.InstallationID &&
		b.Worker.Matches(q, b.Batch.Worker, now) && identity.Fresh(b.CreatedAt, b.Until, now, 5*time.Second) &&
		!b.CreatedAt.Before(b.Batch.StartedAt) && !b.Until.After(b.Batch.Until) && !b.Until.After(b.Worker.ValidUntil) &&
		!b.Until.After(b.Authority.ValidUntil) && !b.Until.After(q.ProviderUntil)
}
