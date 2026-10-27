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
	Initial                  *PermissionInitialization
	// UnavailableSources are PermissionSources whose current namespace
	// observation is unknown (ADR-242). Their accepted assignments are kept,
	// neither retired nor renewed, and grant nothing until a fresh
	// observation is accepted. SourcesUnavailable applies this to every
	// source because the source list itself could not be read.
	UnavailableSources []string `json:",omitempty"`
	SourcesUnavailable bool     `json:",omitempty"`
	// Namespaces is the minimized namespace observation the source bases were
	// derived from; nil while none is current.
	Namespaces *NamespaceObservation `json:",omitempty"`
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
	return p.Resource.Kind + ":" + strconv.Itoa(len(p.Resource.UID)) + ":" + p.Resource.UID + ":" + p.Scope.ClusterID + ":" + p.Scope.Namespace.UID
}

func (b PermissionBatch) Validate(now time.Time) error {
	if !authorization.UUID(b.RootID) || !authorization.UUID(b.Epoch) || !authorization.UUID(b.RequestID) || b.ExpectedSequence < 0 || b.TrustDigest == (artifact.Digest{}) || b.InputDigest == (artifact.Digest{}) || !identity.Fresh(b.ObservedAt, b.FreshUntil, now, 5*time.Second) || len(b.Bases) > 1024 {
		return ErrInvalid
	}
	if b.Namespaces != nil && !b.Namespaces.Valid() || !identity.Strings(b.UnavailableSources, 1024, 64) || b.SourcesUnavailable && len(b.UnavailableSources) > 0 {
		return ErrInvalid
	}
	seen := map[string]bool{}
	rows := 0
	for _, p := range b.Bases {
		if p.Resource.Kind == "PermissionSource" && (b.SourcesUnavailable || slices.Contains(b.UnavailableSources, p.Resource.UID)) {
			return ErrInvalid
		}
		r := p.Resource
		if !identity.Text(r.UID, 64) || seen[p.Key()] || !identity.Text(r.ResourceVersion, 128) || r.Generation < 1 || r.Generation > 2147483647 || r.SpecDigest == (artifact.Digest{}) || p.ScopeDigest == (artifact.Digest{}) || !authorization.UUID(p.Scope.ClusterID) || !identity.Text(p.Scope.Namespace.UID, 64) || !identity.Text(p.Scope.Namespace.Name, 63) || (r.Kind != "AccessBinding" && r.Kind != "PermissionSource") || (p.Effect != "Allow" && p.Effect != "Deny") || len(p.Subjects) < 1 || len(p.Subjects) > 32 || !identity.Strings(p.Roles, 4, 32) || len(p.Roles) == 0 || len(p.Scope.Workloads) > 64 {
			return ErrInvalid
		}
		seen[p.Key()] = true
		if r.Deleting && p.Effect == "Allow" {
			return ErrInvalid
		}
		if r.Kind == "PermissionSource" && p.Effect != "Allow" {
			return ErrInvalid
		}
		// A namespaceMetadata source grants one role to groups over a whole
		// namespace (REQ-PER-003); it names no workloads and never denies.
		if r.Kind == "PermissionSource" && (!identity.Text(p.ObservationVersion, 128) || len(p.Scope.Workloads) != 0 || len(p.Roles) != 1 || slices.ContainsFunc(p.Subjects, func(s Subject) bool { return s.Kind != "Group" })) {
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
			if !slices.Contains([]string{"workload-maintainer", "evidence-reader", "evidence-owner", "action-approver"}, role) {
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
			if (w.Kind != "Deployment" && w.Kind != "StatefulSet") || !identity.Text(w.Name, 253) || !identity.Text(w.UID, 64) || workloads[w.UID] {
				return ErrInvalid
			}
			workloads[w.UID] = true
		}
		if !p.NotAfter.IsZero() && !now.Before(p.NotAfter) {
			return ErrInvalid
		}
		rows += len(p.Subjects) * len(p.Roles)
	}
	if rows > 4096 {
		return ErrLimit
	}
	return nil
}
