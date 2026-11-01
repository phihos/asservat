package execution

import (
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// APIProcessBinding identifies the dedicated regional execution role. Its epoch
// is an instance fence, not proof that a Pod token proves process uniqueness.
// Only the locally owned process handle may provide a current observation.
type APIProcessBinding struct {
	InstallationID, ClusterID, IssuerEpoch         string
	NamespaceUID, AccountUID, PodUID, ProcessEpoch string
	StartupDigest, ImageDigest                     artifact.Digest
}

func (b APIProcessBinding) Valid() bool {
	for _, id := range []string{b.InstallationID, b.ClusterID, b.IssuerEpoch, b.NamespaceUID, b.AccountUID, b.PodUID, b.ProcessEpoch} {
		if !authorization.UUID(id) {
			return false
		}
	}
	return b.StartupDigest != (artifact.Digest{}) && b.ImageDigest != (artifact.Digest{})
}

type APIProcessObservation struct {
	Binding               APIProcessBinding
	CheckedAt, ValidUntil time.Time
}

func (o APIProcessObservation) Valid(now time.Time) bool {
	return o.Binding.Valid() && identity.Fresh(o.CheckedAt, o.ValidUntil, now, 5*time.Second)
}
func (o APIProcessObservation) Matches(b Binding) bool {
	return b.ExecutionClass == artifact.ContextAPIExecution && b.ClusterID == o.Binding.ClusterID && b.IssuerEpoch == o.Binding.IssuerEpoch && b.ExecutorPodUID == o.Binding.PodUID && b.ExecutorAccountUID == o.Binding.AccountUID && b.CollectorEpoch == o.Binding.ProcessEpoch
}

// PreparationCheck authorizes no acquisition. MayCreate must come only from an
// acknowledged first SQL execution preparation. Retry and unknown replies pass
// false, permitting only exact object lookup, never another CREATE.
type PreparationCheck struct {
	Binding               Binding
	CheckedAt, ValidUntil time.Time
	MayCreate             bool
}

func (p PreparationCheck) Valid(now time.Time) bool {
	return p.Binding.Valid() && p.Binding.ExecutionClass == artifact.ContextAPIExecution && identity.Fresh(p.CheckedAt, p.ValidUntil, now, 5*time.Second) && !p.ValidUntil.After(p.Binding.NotAfter) && !now.Before(p.Binding.NotBefore)
}

type PreparedStart struct{ ObjectUID, ResourceVersion string }

// APIExecution is immutable accepted effect identity and monotonic local outcome.
// Prepared alone permits no acquisition. Unknown starts cannot become a new one.
type APIExecution struct {
	WriterProtocol                     string `json:",omitempty"`
	RootID                             string
	Binding                            Binding
	Process                            APIProcessBinding
	ExpectationDigest                  artifact.Digest
	ObjectUID                          string
	Phase                              string // prepared, started, stored, captureFailed, targetGone, denied, storeUnconfirmed, cancelled
	StartedAt, AcquiredAt, CompletedAt time.Time
	Copies                             artifact.Copies
}

func (r APIExecution) Valid() bool {
	if r.WriterProtocol != "" && r.WriterProtocol != artifact.ContextWriterProtocol {
		return false
	}
	if !authorization.UUID(r.RootID) || !r.Binding.Valid() || r.Binding.ExecutionClass != artifact.ContextAPIExecution || !r.Process.Valid() || !(APIProcessObservation{Binding: r.Process}).Matches(r.Binding) || r.ExpectationDigest == (artifact.Digest{}) {
		return false
	}
	if r.ObjectUID != "" && !authorization.UUID(r.ObjectUID) {
		return false
	}
	switch r.Phase {
	case "prepared":
		return r.StartedAt.IsZero() && r.AcquiredAt.IsZero() && r.CompletedAt.IsZero() && r.Copies == (artifact.Copies{})
	case "started":
		return r.ObjectUID != "" && canonicalTime(r.StartedAt) && !r.StartedAt.Before(r.Binding.NotBefore) && r.StartedAt.Before(r.Binding.NotAfter) && r.AcquiredAt.IsZero() && r.CompletedAt.IsZero() && r.Copies == (artifact.Copies{})
	case "stored", "captureFailed", "targetGone", "denied", "storeUnconfirmed", "cancelled":
		if r.ObjectUID == "" || !canonicalTime(r.StartedAt) || r.StartedAt.Before(r.Binding.NotBefore) || !r.StartedAt.Before(r.Binding.NotAfter) || !canonicalTime(r.CompletedAt) || r.CompletedAt.Before(r.StartedAt) {
			return false
		}
		if r.Phase == "captureFailed" || r.Phase == "targetGone" || r.Phase == "denied" || r.Phase == "cancelled" {
			return r.AcquiredAt.IsZero() && r.Copies == (artifact.Copies{})
		}
		if !canonicalTime(r.AcquiredAt) || r.AcquiredAt.Before(r.StartedAt) || !r.AcquiredAt.Before(r.Binding.NotAfter) || r.CompletedAt.Before(r.AcquiredAt) {
			return false
		}
		return r.Phase == "stored" && r.Copies != (artifact.Copies{}) || r.Phase == "storeUnconfirmed" && r.Copies == (artifact.Copies{})
	}
	return false
}
