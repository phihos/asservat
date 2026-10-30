package capture

import (
	"errors"
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
)

// ErrRecorderUnavailable refuses submission of a reviewed packet or syscall
// plan (ADR-243). No node recorder exists yet, so the preview shows the plan
// and request_capture is refused before acceptance: nothing is reserved or charged.
var ErrRecorderUnavailable = errors.New("packet and syscall recorders are not available")

var (
	ErrPreviewExpired        = errors.New("context preview expired; review a new preview")
	ErrDiagnosticUnavailable = errors.New("requested context diagnostic is unavailable")
)

const (
	ContextDiagnosticName   = "builtin-pod-status-v1"
	MaxContextPreviewBytes  = 128 << 10
	MaxContextPreviewScope  = 64 << 10
	MaxPreviewsPerPrincipal = 10
	MaxPreviewsPerRoot      = 1000
)

// ProtectedReasonRef identifies separately encrypted, scope-bound control data.
// Its digest covers ciphertext, never free text. A reference is not authority;
// a current protected reader must check it before preview and new admission.
type ProtectedReasonRef struct {
	ID               string
	CiphertextDigest artifact.Digest
	ExpiresAt        time.Time
}

func (r ProtectedReasonRef) Valid() bool {
	return authorization.UUID(r.ID) && r.CiphertextDigest != (artifact.Digest{}) && previewTime(r.ExpiresAt)
}

// ContextIntent is private authored intent for the one implemented diagnostic,
// or (ADR-243) a reviewed capture profile composition. A transport must resolve
// its diagnostic handle and protect any free-text reason before constructing
// this value. It cannot substitute the broader incident-context preset.
type ContextIntent struct {
	// Snapshot is service-owned existing-source selection, never decoded by ordinary recipe routes.
	Snapshot        *planning.SourceSnapshotContext `json:",omitempty"`
	HistoryAuthored *HistoryAuthored                `json:",omitempty"`
	// RepeatedFrom is independently expiring provenance, never a read grant.
	RepeatedFrom     *HistoryLineage `json:",omitempty"`
	Target           targets.WorkloadRequest
	Diagnostic       string
	RequestedSeconds int64
	Reason           *ProtectedReasonRef
	// Sharing (ADR-235) is an optional capture-time share of the result.
	Sharing *ContextSharing `json:",omitempty"`
	// Composition (ADR-243) replaces Diagnostic. Such a preview is a reviewed
	// plan only: submission is refused with ErrRecorderUnavailable.
	Composition *planning.ProfileComposition `json:",omitempty"`
}

func (i ContextIntent) Valid() bool {
	if (i.HistoryAuthored != nil && (!i.HistoryAuthored.Valid() || i.HistoryAuthored.Target.ClusterID != i.Target.ClusterID)) || (i.RepeatedFrom != nil && (!authorization.UUID(i.RepeatedFrom.CaptureID) || i.RepeatedFrom.ExpiresAt.IsZero())) || !i.Target.Valid() || i.RequestedSeconds < 0 || i.RequestedSeconds > privacy.MaxAgeSeconds || (i.Reason != nil && !i.Reason.Valid()) || (i.Sharing != nil && !i.Sharing.Valid()) {
		return false
	}
	if i.Snapshot != nil {
		return i.Diagnostic == "" && i.Composition == nil && i.Snapshot.Request.Valid()
	}
	if i.Composition != nil {
		return i.Diagnostic == "" && i.Sharing == nil && i.Composition.Valid()
	}
	return i.Diagnostic == ContextDiagnosticName
}

// ContextStorageSelection records the reviewed placement without freshness or
// capacity authority. Only a current read and SQL admission can reserve it.
type ContextStorageSelection struct {
	StoreID, AllocationID            string
	PoolRevision, AllocationRevision int64
	BindingRevision                  identity.Revision
}

func (s ContextStorageSelection) Valid() bool {
	return authorization.UUID(s.StoreID) && authorization.UUID(s.AllocationID) && s.PoolRevision > 0 && s.AllocationRevision > 0 && s.BindingRevision.Valid()
}

// ContextRetentionReview contains relative retention and original policy
// provenance, deliberately excluding artifact dates, observations and proofs.
// Reviewing a preview must not consume the evidence's retention interval.
type ContextRetentionReview struct {
	PurposeRef                                              string
	RequestedSeconds, MaximumSeconds, DeletionBudgetSeconds int64
	Policies                                                []artifact.RetentionRule
}

func (r ContextRetentionReview) Valid() bool {
	if !identity.Text(r.PurposeRef, 128) || r.RequestedSeconds < 1 || r.RequestedSeconds > privacy.MaxAgeSeconds || r.MaximumSeconds < 1 || r.MaximumSeconds > privacy.MaxAgeSeconds || r.DeletionBudgetSeconds < 1 || r.DeletionBudgetSeconds > 86400 || r.DeletionBudgetSeconds >= r.MaximumSeconds || len(r.Policies) < 1 || len(r.Policies) > 64 {
		return false
	}
	seen := map[string]bool{}
	for _, p := range r.Policies {
		if !identity.Text(p.UID, 64) || p.Generation < 1 || p.Generation > 2147483647 || p.Digest == (artifact.Digest{}) || seen[p.UID] {
			return false
		}
		seen[p.UID] = true
	}
	return true
}

// ContextPreview is a bounded passive blueprint. No identity claims/groups,
// runtime proof or five-second observation may be persisted in it. Each ID is
// generated once by the service; expired previews cannot begin new collection.
type ContextPreview struct {
	Group                                                  *RecordingSaveGroupPreview     `json:",omitempty"`
	ExecutionClass                                         artifact.ContextExecutionClass `json:",omitempty"`
	ID, RootID, InstallationID, IssuerEpoch                string
	CaptureID, CaseID, OccurrenceID, ArtifactID, AttemptID string
	AssessmentID                                           string
	AssessmentRulesDigest                                  artifact.Digest
	Actor                                                  identity.Principal
	Intent                                                 ContextIntent
	Target                                                 targets.Request
	Pin                                                    artifact.PinnedPod
	Storage                                                ContextStorageSelection
	Retention                                              ContextRetentionReview
	Audience                                               []artifact.AudienceAssignment
	CanonicalScope                                         []byte
	ScopeDigest                                            artifact.Digest
	CreatedAt, Deadline                                    time.Time
	SelectionUntil                                         time.Time `json:",omitzero"`
}

// Executor is distinct from the immutable initiating principal of a manual
// existing-recording save. This routing identity is reauthorized at every
// effect; deriving it here cannot transfer source authority to the initiator.
func (p ContextPreview) Executor() identity.Principal {
	if p.Group != nil {
		return p.Group.Executor
	}
	if s := p.Intent.Snapshot; s != nil && s.TriggerKind == "recordingSave" {
		return authorization.PolicyPrincipal(p.InstallationID, s.PolicyUID)
	}
	return p.Actor
}

func previewTime(t time.Time) bool {
	return !t.IsZero() && t.Year() >= 2020 && t.Year() <= 9999 && t.Nanosecond()%1000 == 0
}

func (p ContextPreview) Valid() bool {
	if p.Group != nil {
		return p.Group.valid(p)
	}
	if p.Intent.Snapshot != nil && (!previewTime(p.SelectionUntil) || !p.SelectionUntil.After(p.CreatedAt) || p.SelectionUntil.After(p.CreatedAt.Add(time.Minute)) || !p.Intent.Snapshot.Request.ProcessingUntil.Equal(p.Deadline)) || p.Intent.Snapshot == nil && !p.SelectionUntil.IsZero() {
		return false
	}
	if (p.Intent.RepeatedFrom != nil && p.Deadline.After(p.Intent.RepeatedFrom.ExpiresAt)) || !authorization.UUID(p.RootID) || !authorization.UUID(p.InstallationID) || !authorization.UUID(p.IssuerEpoch) || !p.Actor.Valid() || !p.Intent.Valid() || !p.Target.Valid() || !p.storageValid() || !p.Retention.Valid() || !previewTime(p.CreatedAt) || !previewTime(p.Deadline) || !p.Deadline.After(p.CreatedAt) || (p.Intent.Snapshot == nil && p.Deadline.After(p.CreatedAt.Add(5*time.Minute))) || p.Intent.Reason != nil && p.Deadline.After(p.Intent.Reason.ExpiresAt) {
		return false
	}
	seen := map[string]bool{}
	for _, id := range []string{p.ID, p.CaptureID, p.CaseID, p.OccurrenceID, p.ArtifactID, p.AttemptID, p.AssessmentID} {
		if !authorization.UUID(id) || seen[id] {
			return false
		}
		seen[id] = true
	}
	if !p.ExecutionClass.Valid() || (p.ExecutionClass == artifact.ContextAPIExecution && p.Intent.Snapshot == nil && p.Pin.NodeName != "") || (p.ExecutionClass == artifact.ContextNodeExecution && !identity.Text(p.Pin.NodeName, 253)) {
		return false
	}
	if p.Intent.Target.ClusterID != p.Target.ClusterID || p.Intent.Target.Namespace != p.Target.Namespace.Name || p.Pin.Namespace != p.Target.Namespace.Name || p.Pin.NamespaceUID != p.Target.Namespace.UID || p.Pin.Name != p.Target.PodName || p.Pin.UID != p.Target.PodUID || !identity.Text(p.Pin.ControllerUID, 64) && p.Target.Workload.Kind != "Pod" {
		return false
	}
	if p.Intent.Target.Kind == "Pod" {
		if p.Intent.Target.Name != p.Target.PodName {
			return false
		}
	} else if p.Intent.Target.Kind != p.Target.Workload.Kind || p.Intent.Target.Name != p.Target.Workload.Name {
		return false
	}
	if len(p.CanonicalScope) < 1 || len(p.CanonicalScope) > MaxContextPreviewScope || p.ScopeDigest == (artifact.Digest{}) || p.AssessmentRulesDigest == (artifact.Digest{}) || len(p.Audience) < 1 || len(p.Audience) > 32 {
		return false
	}
	seen = map[string]bool{}
	for _, a := range p.Audience {
		if !authorization.UUID(a.AssignmentID) || seen[a.AssignmentID] || !identity.Text(a.Kind, 16) || !identity.Text(a.Issuer, 2048) || !identity.Text(a.SubjectID, 256) || !identity.Text(a.Role, 32) || !identity.Text(a.BasisKind, 32) || !identity.Text(a.BasisUID, 64) || a.BasisDigest == (artifact.Digest{}) {
			return false
		}
		seen[a.AssignmentID] = true
	}
	return true
}

// A composition preview (ADR-243) that no node recorder can run reserves no
// storage, so it carries none; an acceptable one (ADR-248) carries the same
// storage selection as a pod-status preview.
func (p ContextPreview) storageValid() bool {
	if p.Intent.Composition != nil && p.Storage == (ContextStorageSelection{}) {
		return true
	}
	return p.Storage.Valid()
}

func (p ContextPreview) Current(now time.Time) bool {
	return p.Valid() && !now.Before(p.CreatedAt) && now.Before(p.Deadline) && (p.SelectionUntil.IsZero() || now.Before(p.SelectionUntil))
}

func (p ContextPreview) Clone() ContextPreview {
	p.Group = p.Group.Clone()
	p.CanonicalScope = slices.Clone(p.CanonicalScope)
	p.Audience = slices.Clone(p.Audience)
	p.Retention.Policies = slices.Clone(p.Retention.Policies)
	if p.Intent.Reason != nil {
		r := *p.Intent.Reason
		p.Intent.Reason = &r
	}
	p.Intent.Sharing = p.Intent.Sharing.clone()
	p.Intent.Composition = p.Intent.Composition.Clone()
	p.Intent.Snapshot = p.Intent.Snapshot.Clone()
	p.Intent.HistoryAuthored = p.Intent.HistoryAuthored.Clone()
	if p.Intent.RepeatedFrom != nil {
		l := *p.Intent.RepeatedFrom
		p.Intent.RepeatedFrom = &l
	}
	return p
}

// ReplayQuery carries newly verified identity/recovery only. Its read-only
// consumer checks current stored-target entitlement before exposing an existing
// operation; it never requires a live pod, an unexpired preview or old proofs.
type ReplayQuery struct {
	RootID, PreviewID, IdempotencyKey string
	SubmissionDigest                  artifact.Digest
	Identity                          identity.Identity
	Recovery                          artifact.RecoveryProof
}

func (q ReplayQuery) Valid(now time.Time) bool {
	return authorization.UUID(q.RootID) && authorization.UUID(q.PreviewID) && identity.Text(q.IdempotencyKey, 128) && q.SubmissionDigest != (artifact.Digest{}) && q.Identity.Valid(now) && q.Recovery.Valid(now)
}
