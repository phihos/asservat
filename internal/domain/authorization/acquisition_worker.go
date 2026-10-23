package authorization

import (
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

// AcquisitionPurpose is closed. It selects the persisted parent and its own
// authorization checks; it never converts one parent's permit into another.
type AcquisitionPurpose string

const (
	AcquisitionDownload   AcquisitionPurpose = "native-download"
	AcquisitionProjection AcquisitionPurpose = "approved-pod-status"
)

// AcquisitionParent is a locator, not evidence authority. The worker cannot
// choose or change it after admission, including during enrollment or renewal.
type AcquisitionParent struct {
	Purpose AcquisitionPurpose
	ID      string
}

func (p AcquisitionParent) Valid() bool {
	return UUID(p.ID) && (p.Purpose == AcquisitionDownload || p.Purpose == AcquisitionProjection)
}

// AcquisitionParentFor decodes the two mutually exclusive existing-parent
// locators. An empty or mixed pair never falls back to download routing.
func AcquisitionParentFor(sessionID, queryID string) AcquisitionParent {
	if sessionID != "" && queryID == "" {
		return AcquisitionParent{Purpose: AcquisitionDownload, ID: sessionID}
	}
	if queryID != "" && sessionID == "" {
		return AcquisitionParent{Purpose: AcquisitionProjection, ID: queryID}
	}
	return AcquisitionParent{}
}

// AcquisitionWorkerIntent contains only immutable launch/identity facts. The
// corresponding download or query ledger retains the distinct authority and
// accounting. A valid intent alone cannot authorize a Job or evidence access.
type AcquisitionWorkerIntent struct {
	ID                  string
	Parent              AcquisitionParent
	Profile             DownloadWorkerProfile
	CreatedAt, RunUntil time.Time
}

func (i AcquisitionWorkerIntent) Valid() bool {
	return UUID(i.ID) && i.Parent.Valid() && i.Profile.Valid() && !i.CreatedAt.IsZero() &&
		i.RunUntil.Sub(i.CreatedAt) >= time.Second && !i.RunUntil.After(i.CreatedAt.Add(i.Profile.MaxRuntime))
}

func (i AcquisitionWorkerIntent) JobName() string {
	switch i.Parent.Purpose {
	case AcquisitionDownload:
		return "asservat-download-" + i.ID
	case AcquisitionProjection:
		return "asservat-query-" + i.ID
	default:
		return ""
	}
}

// Acquisition keeps native-download identity and historical launch templates
// unchanged. Callers still validate the original typed download admission.
func (i DownloadWorkerIntent) Acquisition() AcquisitionWorkerIntent {
	return AcquisitionWorkerIntent{ID: i.ID, Parent: AcquisitionParent{Purpose: AcquisitionDownload, ID: i.SessionID},
		Profile: i.Profile, CreatedAt: i.CreatedAt, RunUntil: i.RunUntil}
}

// AcquisitionWorkerBinding is the exact admitted Kubernetes identity shared by
// attestation and enrollment. Parent-specific key grants remain separate.
type AcquisitionWorkerBinding struct {
	Parent                            AcquisitionParent
	InstallationID, ClusterID         string
	Namespace, NamespaceUID           string
	ServiceAccount, ServiceAccountUID string
	Job, JobUID, Pod, PodUID          string
	JobSpec, PodSpec                  artifact.Digest
}

func (b AcquisitionWorkerBinding) Valid() bool {
	return b.Parent.Valid() && UUID(b.InstallationID) && UUID(b.ClusterID) &&
		identity.Text(b.Namespace, 63) && identity.Text(b.NamespaceUID, 64) &&
		identity.Text(b.ServiceAccount, 253) && identity.Text(b.ServiceAccountUID, 64) &&
		identity.Text(b.Job, 63) && identity.Text(b.JobUID, 64) && identity.Text(b.Pod, 253) && UUID(b.PodUID) &&
		b.JobSpec != (artifact.Digest{}) && b.PodSpec != (artifact.Digest{})
}

func (b KeyWorkerBinding) Acquisition() AcquisitionWorkerBinding {
	return AcquisitionWorkerBinding{Parent: AcquisitionParent{Purpose: AcquisitionDownload, ID: b.DownloadID},
		InstallationID: b.InstallationID, ClusterID: b.ClusterID, Namespace: b.Namespace, NamespaceUID: b.NamespaceUID,
		ServiceAccount: b.ServiceAccount, ServiceAccountUID: b.ServiceAccountUID,
		Job: b.Job, JobUID: b.JobUID, Pod: b.Pod, PodUID: b.PodUID, JobSpec: b.JobSpec, PodSpec: b.PodSpec}
}

// DownloadBinding refuses the query branch; it is identity conversion only,
// and never creates a DownloadAuthority or download session.
func (b AcquisitionWorkerBinding) DownloadBinding() (KeyWorkerBinding, bool) {
	if !b.Valid() || b.Parent.Purpose != AcquisitionDownload {
		return KeyWorkerBinding{}, false
	}
	return KeyWorkerBinding{InstallationID: b.InstallationID, DownloadID: b.Parent.ID, ClusterID: b.ClusterID,
		Namespace: b.Namespace, NamespaceUID: b.NamespaceUID, ServiceAccount: b.ServiceAccount, ServiceAccountUID: b.ServiceAccountUID,
		Job: b.Job, JobUID: b.JobUID, Pod: b.Pod, PodUID: b.PodUID, JobSpec: b.JobSpec, PodSpec: b.PodSpec}, true
}

type AcquisitionWorker struct {
	Intent  AcquisitionWorkerIntent
	Job     DownloadWorkerJob
	Binding AcquisitionWorkerBinding
}

type AcquisitionWorkerLaunch struct {
	Intent           AcquisitionWorkerIntent
	CheckedAt, Until time.Time
	MayCreate        bool
}

func (l AcquisitionWorkerLaunch) Valid(now time.Time) bool {
	return l.Intent.Valid() && identity.Fresh(l.CheckedAt, l.Until, now, 5*time.Second) && !l.Until.After(l.Intent.RunUntil)
}

func (l DownloadWorkerLaunch) Acquisition() AcquisitionWorkerLaunch {
	return AcquisitionWorkerLaunch{Intent: l.Intent.Acquisition(), CheckedAt: l.CheckedAt, Until: l.Until, MayCreate: l.MayCreate}
}

func (j DownloadWorkerJob) ValidAcquisition(i AcquisitionWorkerIntent) bool {
	return i.Valid() && j.IntentID == i.ID && identity.Text(j.UID, 64) && j.Spec != (artifact.Digest{})
}

func (w AcquisitionWorker) Valid() bool {
	i, b := w.Intent, w.Binding
	return i.Valid() && w.Job.IntentID == i.ID && identity.Text(w.Job.UID, 64) && w.Job.Spec != (artifact.Digest{}) &&
		b.Valid() && b.Parent == i.Parent && b.InstallationID == i.Profile.InstallationID && b.ClusterID == i.Profile.ClusterID &&
		b.Namespace == i.Profile.Namespace && b.NamespaceUID == i.Profile.NamespaceUID &&
		b.ServiceAccount == i.Profile.ServiceAccount && b.ServiceAccountUID == i.Profile.ServiceAccountUID &&
		b.Job == i.JobName() && b.JobUID == w.Job.UID && b.JobSpec == w.Job.Spec
}

func (w DownloadWorker) Acquisition() AcquisitionWorker {
	return AcquisitionWorker{Intent: w.Intent.Acquisition(), Job: w.Job, Binding: w.Binding.Acquisition()}
}

// CertificateEpoch uses the original admitted lifetime for either parent.
func (w AcquisitionWorker) CertificateEpoch(now time.Time) (int, time.Time, error) {
	if !w.Valid() {
		return 0, time.Time{}, artifact.ErrInvalid
	}
	return workerCertificatePeriod(w.Intent.CreatedAt, w.Intent.RunUntil, now)
}

// Current identity observations do not confer either parent's evidence rights.
type AcquisitionWorkerIdentity struct {
	Worker                 AcquisitionWorker
	ObservedAt, FreshUntil time.Time
}

func (o AcquisitionWorkerIdentity) Valid(now time.Time) bool {
	return o.Worker.Valid() && identity.Fresh(o.ObservedAt, o.FreshUntil, now, 5*time.Second) && !o.FreshUntil.After(o.Worker.Intent.RunUntil)
}
func (o DownloadWorkerIdentity) Acquisition() AcquisitionWorkerIdentity {
	return AcquisitionWorkerIdentity{Worker: o.Worker.Acquisition(), ObservedAt: o.ObservedAt, FreshUntil: o.FreshUntil}
}

type AcquisitionPeerProof struct {
	Binding                AcquisitionWorkerBinding
	Peer                   KeyPeer
	TokenDigest            artifact.Digest
	ObservedAt, FreshUntil time.Time
}

func (p AcquisitionPeerProof) Valid(now time.Time) bool {
	return p.Binding.Valid() && p.Peer.Valid(now) && p.Peer.Role == "acquisition" && p.Peer.InstallationID == p.Binding.InstallationID && p.Peer.PeerID == p.Binding.PodUID && p.TokenDigest != (artifact.Digest{}) && identity.Fresh(p.ObservedAt, p.FreshUntil, now, 5*time.Second) && !p.FreshUntil.After(p.Peer.NotAfter)
}

type AcquisitionWorkerTermination struct {
	Worker                 AcquisitionWorker
	TerminationDigest      artifact.Digest
	ObservedAt, FreshUntil time.Time
}

func (r AcquisitionWorkerTermination) Valid(now time.Time) bool {
	return r.Worker.Valid() && r.TerminationDigest != (artifact.Digest{}) && identity.Fresh(r.ObservedAt, r.FreshUntil, now, 5*time.Second)
}
func (r DownloadWorkerTermination) Acquisition() AcquisitionWorkerTermination {
	return AcquisitionWorkerTermination{Worker: r.Worker.Acquisition(), TerminationDigest: r.TerminationDigest, ObservedAt: r.ObservedAt, FreshUntil: r.FreshUntil}
}

type AcquisitionWorkerRetirement struct {
	Termination            AcquisitionWorkerTermination
	ObservedAt, FreshUntil time.Time
}

func (r AcquisitionWorkerRetirement) Valid(now time.Time) bool {
	return r.Termination.Valid(r.Termination.ObservedAt) && !r.ObservedAt.Before(r.Termination.ObservedAt) && identity.Fresh(r.ObservedAt, r.FreshUntil, now, 5*time.Second)
}

func (p KeyWorkerProof) Acquisition() AcquisitionPeerProof {
	return AcquisitionPeerProof{Binding: p.Binding.Acquisition(), Peer: p.Peer, TokenDigest: p.TokenDigest, ObservedAt: p.ObservedAt, FreshUntil: p.FreshUntil}
}
func (p AcquisitionPeerProof) DownloadProof() (KeyWorkerProof, bool) {
	b, ok := p.Binding.DownloadBinding()
	if !ok {
		return KeyWorkerProof{}, false
	}
	return KeyWorkerProof{Binding: b, Peer: p.Peer, TokenDigest: p.TokenDigest, ObservedAt: p.ObservedAt, FreshUntil: p.FreshUntil}, true
}
func (w AcquisitionWorker) CredentialTarget() WorkerCredentialTarget {
	out := WorkerCredentialTarget{InstallationID: w.Binding.InstallationID, WorkerID: w.Intent.ID, PodUID: w.Binding.PodUID, CreatedAt: w.Intent.CreatedAt, RunUntil: w.Intent.RunUntil}
	switch w.Intent.Parent.Purpose {
	case AcquisitionDownload:
		out.SessionID = w.Intent.Parent.ID
	case AcquisitionProjection:
		out.QueryID = w.Intent.Parent.ID
	}
	return out
}
