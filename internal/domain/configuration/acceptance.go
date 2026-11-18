package configuration

import (
	"slices"
	"strconv"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// Accepted input is produced by the protected source reconciler, never by a
// browser/MCP argument or CRD status. Stream and sequence fence old reconcilers.
type PermissionBatch struct {
	RootID, Epoch, RequestID string
	ExpectedSequence         int64
	TrustDigest, InputDigest artifact.Digest
	ObservedAt, FreshUntil   time.Time
	Bases                    []PermissionBasis
	// UnavailableSources are PermissionSources whose current namespace
	// observation is unknown (ADR-242). Their accepted assignments are kept,
	// neither retired nor renewed, and grant nothing until a fresh
	// observation is accepted. SourcesUnavailable applies this to every
	// source because the source list itself could not be read.
	UnavailableClusters []string `json:",omitempty"`
	UnavailableSources  []string `json:",omitempty"`
	SourcesUnavailable  bool     `json:",omitempty"`
	// Namespaces is the minimized namespace observation the source bases were
	// derived from; nil while none is current.
	Namespaces *NamespaceObservation `json:",omitempty"`
	// RemoteNamespaces are the minimized observations of other joined
	// clusters' namespaces (ADR-247), one per cluster in cluster order.
	RemoteNamespaces []NamespaceObservation `json:",omitempty"`
	// Workloads are the minimized workload observations the workloadMetadata
	// bases were derived from (ADR-247).
	Workloads []WorkloadObservation `json:",omitempty"`
	// ReviewSources are the accepted decision-time sources (ADR-245). They
	// carry no subject; per-principal assignments are minted only by a
	// recorded allowed review. A source missing from a batch retires its
	// assignments unless SourcesUnavailable keeps them without renewal.
	ReviewSources []ReviewSource `json:",omitempty"`
}
type PermissionBasis struct {
	Resource Resource
	Scope    Scope
	// ScopeDigest is the effective, normalized authority scope, independent of
	// display reasons and subject ordering. SpecDigest remains full provenance.
	ScopeDigest artifact.Digest
	Effect      string
	Subjects    []Subject
	Roles       []string
	NotAfter    time.Time
	Automation  *authorization.AutomationEnvelope `json:",omitempty"`
	// ObservationVersion pins the namespace metadata observation for implicit
	// sources. The PermissionSource resourceVersion alone cannot detect changes
	// in the namespace that it maps.
	ObservationVersion string
	// Continuity is only true for an authenticated, gap-free event sequence.
	// A standalone relist cannot assert it for metadata-based ownership.
	Continuous bool
}
type PermissionFence struct {
	RootID, Epoch string
	Sequence      int64
	TrustDigest   artifact.Digest
	LeaseUntil    time.Time
	Initialized   bool
}
type PermissionAcceptance struct {
	PermissionFence
	AuditID              string
	Assignments, Retired int
}

func (p PermissionBasis) Key() string {
	k := p.Resource.Kind + ":" + strconv.Itoa(len(p.Resource.UID)) + ":" + p.Resource.UID + ":" + p.Scope.ClusterID + ":" + p.Scope.Namespace.UID
	// ADR-247: a workloadMetadata source has one basis per workload.
	if p.Resource.Kind == "PermissionSource" && len(p.Scope.Workloads) == 1 {
		k += ":" + p.Scope.Workloads[0].UID
	}
	return k
}

// Roles are the roles a binding or source may grant.
var Roles = []string{"workload-maintainer", "evidence-reader", "evidence-owner", "action-approver"}

// Current verifies the original observation and every basis expiry against
// now. SQL checks these bounds again before committing an immutable batch.
func (b PermissionBatch) Current(now time.Time) bool {
	return identity.Fresh(b.ObservedAt, b.FreshUntil, now, 5*time.Second) &&
		!slices.ContainsFunc(b.Bases, func(p PermissionBasis) bool { return !p.NotAfter.IsZero() && !now.Before(p.NotAfter) })
}

// Validate checks a prepared batch. No count limits: Kubernetes object limits
// bound each spec and the store pages its rows.
func (b PermissionBatch) Validate(now time.Time) error {
	if !authorization.UUID(b.RootID) || !authorization.UUID(b.Epoch) || !authorization.UUID(b.RequestID) || b.ExpectedSequence < 0 || b.TrustDigest == (artifact.Digest{}) || b.InputDigest == (artifact.Digest{}) || !b.Current(now) {
		return ErrInvalid
	}
	if b.Namespaces != nil && !b.Namespaces.Valid() || !identity.Strings(b.UnavailableSources, len(b.UnavailableSources), 64) || b.SourcesUnavailable && len(b.UnavailableSources) > 0 || !RemoteNamespacesValid(b.Namespaces, b.RemoteNamespaces) || !WorkloadObservationsValid(b.Workloads) {
		return ErrInvalid
	}
	if b.SourcesUnavailable && len(b.ReviewSources) > 0 {
		return ErrInvalid
	}
	reviews := map[string]bool{}
	for _, r := range b.ReviewSources {
		if !r.Valid() || reviews[r.Resource.UID] || slices.Contains(b.UnavailableSources, r.Resource.UID) {
			return ErrInvalid
		}
		reviews[r.Resource.UID] = true
	}
	seen := map[string]bool{}
	for _, p := range b.Bases {
		if p.Resource.Kind == "PermissionSource" && (b.SourcesUnavailable || slices.Contains(b.UnavailableSources, p.Resource.UID)) {
			return ErrInvalid
		}
		r := p.Resource
		if !identity.Text(r.UID, 64) || seen[p.Key()] || !identity.Text(r.ResourceVersion, 128) || r.Generation < 1 || r.Generation > 2147483647 || r.SpecDigest == (artifact.Digest{}) || p.ScopeDigest == (artifact.Digest{}) || !authorization.UUID(p.Scope.ClusterID) || !identity.Text(p.Scope.Namespace.UID, 64) || !identity.Text(p.Scope.Namespace.Name, 63) || !authorization.ValidPermissionBasisKind(r.Kind) || (p.Effect != "Allow" && p.Effect != "Deny") || len(p.Subjects) < 1 || len(p.Roles) == 0 || !identity.Strings(p.Roles, len(p.Roles), 32) {
			return ErrInvalid
		}
		seen[p.Key()] = true
		if r.Deleting && p.Effect == "Allow" {
			return ErrInvalid
		}
		// Only a ClusterAccessBinding covers every namespace of its cluster;
		// a selector-narrowed one has one basis per selected namespace.
		if r.Kind != ClusterAccessBindingKind && p.Scope.Namespace == AllNamespaces || r.Kind == ClusterAccessBindingKind && (len(p.Scope.Workloads) > 0 || p.Automation != nil) {
			return ErrInvalid
		}
		// A namespaceMetadata source grants one role to groups over a whole
		// namespace (REQ-PER-003), a workloadMetadata source over one workload
		// (REQ-PER-005, ADR-247); neither denies.
		if r.Kind == "PermissionSource" && (p.Effect != "Allow" || !identity.Text(p.ObservationVersion, 128) || len(p.Scope.Workloads) > 1 || len(p.Roles) != 1 || slices.ContainsFunc(p.Subjects, func(s Subject) bool { return s.Kind != "Group" })) {
			return ErrInvalid
		}
		if p.Automation != nil {
			if r.Kind != "AccessBinding" || p.Effect != "Allow" || !p.Automation.Valid() || !slices.Contains(p.Roles, "workload-maintainer") {
				return ErrInvalid
			}
			for _, subject := range p.Subjects {
				if subject.Kind != "Group" {
					return ErrInvalid
				}
			}
		}
		for _, role := range p.Roles {
			if !slices.Contains(Roles, role) {
				return ErrInvalid
			}
		}
		subjects := map[Subject]bool{}
		for _, s := range p.Subjects {
			if (s.Kind != "User" && s.Kind != "Group" && s.Kind != "Workload") || !identity.Text(s.Issuer, 2048) || !identity.Text(s.ID, 256) || subjects[s] {
				return ErrInvalid
			}
			subjects[s] = true
		}
		workloads := map[string]bool{}
		for _, w := range p.Scope.Workloads {
			if (w.Kind != "Deployment" && w.Kind != "StatefulSet") || !identity.Text(w.Name, 253) || w.UID != "" && !identity.Text(w.UID, 64) || workloads[w.Kind+"/"+w.Name] {
				return ErrInvalid
			}
			workloads[w.Kind+"/"+w.Name] = true
		}
	}
	return nil
}

// RemoteNamespacesValid requires valid remote observations in strictly
// ascending cluster order, none for the hub observation's cluster.
func RemoteNamespacesValid(hub *NamespaceObservation, remote []NamespaceObservation) bool {
	for i, o := range remote {
		if !o.Valid() || i > 0 && remote[i-1].ClusterID >= o.ClusterID || hub != nil && hub.ClusterID == o.ClusterID {
			return false
		}
	}
	return true
}
