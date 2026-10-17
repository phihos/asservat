package authorization

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"strings"
	"time"
)

// DownloadWorkerProfile is independently configured installation data. It is
// never decoded from a developer's capture/download request.
// NativeWorkerMinimumMemory is a configured floor, not measured peak RSS.
// Deployed workload qualification remains required before enabling this mode.
const NativeWorkerMinimumMemory = 64 << 20

type DownloadWorkerProfile struct {
	Configuration                          identity.Revision
	InstallationID, ClusterID              string
	Namespace, NamespaceUID                string
	ServiceAccount, ServiceAccountUID      string
	Image, ControlConfig, ControlConfigUID string
	PriorityClass, PriorityClassUID        string
	ImagePullSecrets                       [4]string
	ControlDigest                          artifact.Digest
	CPUMillis, MemoryBytes                 int64
	MaxRuntime                             time.Duration
	StoreCredentialSecret                  string `json:",omitempty"`
	StoreCredentialSecretUID               string `json:",omitempty"`
}

func (p DownloadWorkerProfile) Valid() bool {
	if (p.StoreCredentialSecret == "") != (p.StoreCredentialSecretUID == "") || p.StoreCredentialSecret != "" && (!identity.Text(p.StoreCredentialSecret, 253) || !UUID(p.StoreCredentialSecretUID)) {
		return false
	}
	if p.StoreCredentialSecret != "" && p.MemoryBytes < NativeWorkerMinimumMemory {
		return false
	}
	if !p.Configuration.Valid() || !UUID(p.Configuration.UID) || !identity.Text(p.PriorityClass, 253) || !identity.Text(p.PriorityClassUID, 64) {
		return false
	}
	empty := false
	seen := map[string]bool{}
	for _, name := range p.ImagePullSecrets {
		if name == "" {
			empty = true
			continue
		}
		if empty || seen[name] || !identity.Text(name, 253) {
			return false
		}
		seen[name] = true
	}
	image := strings.Split(p.Image, "@sha256:")
	if len(image) != 2 || !identity.Text(image[0], 384) || len(image[1]) != 64 || strings.ContainsAny(p.Image, " \t\r\n") {
		return false
	}
	for _, c := range image[1] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return UUID(p.InstallationID) && UUID(p.ClusterID) && identity.Text(p.Namespace, 63) && identity.Text(p.NamespaceUID, 64) && identity.Text(p.ServiceAccount, 253) && identity.Text(p.ServiceAccountUID, 64) && identity.Text(p.ControlConfig, 253) && identity.Text(p.ControlConfigUID, 64) && p.ControlDigest != (artifact.Digest{}) && p.CPUMillis >= 10 && p.CPUMillis <= 4000 && p.MemoryBytes >= 16<<20 && p.MemoryBytes <= 8<<30 && p.MaxRuntime >= 30*time.Second && p.MaxRuntime <= 8*time.Hour && p.MaxRuntime%time.Second == 0
}

// WorkerIntent is frozen before audit or launch. Unknown launches remain paid.
type DownloadWorkerIntent struct {
	ID, SessionID       string
	Generation          int64
	Profile             DownloadWorkerProfile
	Authority           artifact.DownloadAuthority
	CreatedAt, RunUntil time.Time
}

func (i DownloadWorkerIntent) Valid() bool {
	return UUID(i.ID) && UUID(i.SessionID) && i.Generation > 0 && i.Generation <= artifact.MaxDownloadRequests && i.Profile.Valid() && i.Authority.Valid(i.CreatedAt) && i.Authority.Environment.Recovery().InstallationID == i.Profile.InstallationID && i.RunUntil.Sub(i.CreatedAt) >= time.Second && !i.RunUntil.After(i.CreatedAt.Add(i.Profile.MaxRuntime)) && !i.RunUntil.After(i.Authority.AccessUntil)
}
func (i DownloadWorkerIntent) JobName() string { return "asservat-download-" + i.ID }

type DownloadWorkerLaunch struct {
	Intent           DownloadWorkerIntent
	CheckedAt, Until time.Time
	MayCreate        bool
}

func (l DownloadWorkerLaunch) Valid(now time.Time) bool {
	return l.Intent.Valid() && identity.Fresh(l.CheckedAt, l.Until, now, 5*time.Second) && !l.Until.After(l.Intent.RunUntil)
}

// A receipt is not evidence authority. Specs and UIDs must come from a checked
// API response, never a client-provided label or an arbitrary existing Job.
type DownloadWorkerJob struct {
	IntentID, UID string
	Spec          artifact.Digest
}

func (r DownloadWorkerJob) Valid(i DownloadWorkerIntent) bool {
	return i.Valid() && r.IntentID == i.ID && identity.Text(r.UID, 64) && r.Spec != (artifact.Digest{})
}

type DownloadWorker struct {
	Intent  DownloadWorkerIntent
	Job     DownloadWorkerJob
	Binding KeyWorkerBinding
}

func (w DownloadWorker) Valid() bool {
	i, b := w.Intent, w.Binding
	return w.Job.Valid(i) && b.Valid() && b.InstallationID == i.Profile.InstallationID && b.DownloadID == i.SessionID && b.ClusterID == i.Profile.ClusterID && b.Namespace == i.Profile.Namespace && b.NamespaceUID == i.Profile.NamespaceUID && b.ServiceAccount == i.Profile.ServiceAccount && b.ServiceAccountUID == i.Profile.ServiceAccountUID && b.Job == i.JobName() && b.JobUID == w.Job.UID && b.JobSpec == w.Job.Spec
}

// A successful delete alone is insufficient: the driver must first observe all
// selected Job pods with known terminated containers, then prove API absence.
type DownloadWorkerTermination struct {
	Worker                 DownloadWorker
	TerminationDigest      artifact.Digest
	ObservedAt, FreshUntil time.Time
}

func (r DownloadWorkerTermination) Valid(now time.Time) bool {
	return r.Worker.Valid() && r.TerminationDigest != (artifact.Digest{}) && identity.Fresh(r.ObservedAt, r.FreshUntil, now, 5*time.Second)
}

// Termination is persisted before deletion, so a lost delete response can be
// reconciled without inventing process quiescence from a later 404.
type DownloadWorkerRetirement struct {
	Termination            DownloadWorkerTermination
	ObservedAt, FreshUntil time.Time
}

func (r DownloadWorkerRetirement) Valid(now time.Time) bool {
	return r.Termination.Valid(r.Termination.ObservedAt) && !r.ObservedAt.Before(r.Termination.ObservedAt) && identity.Fresh(r.ObservedAt, r.FreshUntil, now, 5*time.Second)
}
