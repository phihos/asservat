// Package configuration holds observed configuration values. Observation is not
// acceptance: these types cannot serve as permission or execution grants.
package configuration

import (
	"errors"
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

var (
	ErrInvalid     = errors.New("invalid permission observation request")
	ErrUnavailable = errors.New("permission configuration unavailable")
	ErrDenied      = errors.New("permission configuration read denied")
	ErrChanged     = errors.New("permission source identity changed")
	ErrLimit       = errors.New("permission configuration limit exceeded")
)

type Resource struct {
	ClusterID, Namespace, NamespaceUID, Kind, Name, UID, ResourceVersion string
	Generation                                                           int64
	SpecDigest                                                           artifact.Digest
	Deleting                                                             bool
}
type Subject struct{ Kind, Issuer, ID string }
type NamespaceRef struct{ Name, UID string }
type WorkloadRef struct{ Kind, Name, UID string }
type Scope struct {
	ClusterID string
	Namespace NamespaceRef
	Workloads []WorkloadRef
}
type Binding struct {
	Resource   Resource
	Effect     string
	Subjects   []Subject
	Roles      []string
	Scope      Scope
	NotAfter   time.Time
	Automation *authorization.AutomationEnvelope
}
type Protection struct{ Mode, ReviewRef, GuardRef string }
type Mapping struct {
	Field, Key, Mode, Issuer string
	Values                   map[string][]string
}
type Source struct {
	Resource              Resource
	Enabled               bool
	Type, ClusterID, Role string
	NamespaceSelector     map[string]string
	ExcludedNamespaces    []string
	MaxDecisionAge        time.Duration
	MaxNamespaces         int
	Protection            Protection
	Mapping               Mapping
	// WorkloadSelector selects the Deployments/StatefulSets a
	// workloadMetadata source reads (REQ-PER-005).
	WorkloadSelector map[string]string `json:",omitempty"`
	// IdentityMappingRef, AdmissionParity and AccessReviewCheck configure the
	// decision-time kubernetesExec/kubernetesAccessReview sources
	// (REQ-PER-004, ADR-245).
	IdentityMappingRef string          `json:",omitempty"`
	AdmissionParity    AdmissionParity `json:",omitzero"`
	AccessReviewCheck  string          `json:",omitempty"`
}

// AdmissionParity is the administrator's attestation that a SAR-based
// source's authorizer decision is not narrowed by admission (REQ-PER-004).
type AdmissionParity struct{ Mode, ReviewRef, AdapterRef string }

// Snapshot contains a complete binding list and an independently observed
// allow-only source list, NOT an atomic snapshot across
// resource kinds, an admission receipt, or a SQL accepted projection. RVs are
// opaque. Status/field managers/writer annotations are deliberately absent.
type Snapshot struct {
	ClusterID                                     string
	ControlNamespace                              NamespaceRef
	BindingResourceVersion, SourceResourceVersion string
	ObservedAt, FreshUntil                        time.Time
	Bindings                                      []Binding
	Sources                                       []Source
	SourcesComplete                               bool
	InvalidSources                                []Resource
}

// NamespaceQuery is assembled internally from configured keys, not from a
// public evidence request. Only these metadata keys may leave the reader.
type NamespaceQuery struct {
	Namespace                 NamespaceRef
	LabelKeys, AnnotationKeys []string
}
type NamespaceMetadata struct {
	ClusterID              string
	Namespace              NamespaceRef
	ResourceVersion        string
	ObservedAt, FreshUntil time.Time
	Deleting               bool
	Labels, Annotations    map[string]string
}

// NamespaceKeys are the metadata keys a namespace observation records: the
// selector labels and mapping keys of one cluster's namespaceMetadata sources.
// Every other label and annotation stays in the cluster.
type NamespaceKeys struct{ Labels, Annotations []string }

// ObservedNamespace is one namespace reduced to the observed keys. A value is
// kept only as the lower-case hex SHA-256 of its exact bytes; "" marks a value
// that can never map (longer than 256 bytes or with control characters).
// ResourceVersion is opaque and empty in an accepted NamespaceObservation.
type ObservedNamespace struct {
	Name, UID           string
	ResourceVersion     string            `json:",omitempty"`
	Deleting            bool              `json:",omitempty"`
	Labels, Annotations map[string]string `json:",omitempty"`
}

// NamespaceList is a complete paginated LIST of one cluster's namespaces at
// one collection resourceVersion, reduced to those carrying an observed key.
// ObservedAt is taken before the first page was requested.
type NamespaceList struct {
	ClusterID, ResourceVersion string
	Keys                       NamespaceKeys
	ObservedAt                 time.Time
	Namespaces                 []ObservedNamespace
}

// NamespaceEvent is one validated namespace watch transition, reduced like a
// NamespaceList entry (a namespace without observed keys has none). Bookmarks
// carry only the cursor.
type NamespaceEvent struct {
	Type, ResourceVersion string
	Namespace             *ObservedNamespace
}

// NamespaceObservation is the accepted, minimized namespace observation of a
// permission batch (ADR-242): keys, names, UIDs and value digests, no times or
// resource versions. It is recorded in the authority audit event and is what
// the impact preview evaluates proposed sources against.
type NamespaceObservation struct {
	ClusterID  string
	Keys       NamespaceKeys
	Namespaces []ObservedNamespace
}

// MaxObservedNamespaces bounds one cluster's observation; more namespaces
// carrying an observed key make the observation unavailable, never partial.
const MaxObservedNamespaces = 4096

// Why a namespaceMetadata source grants nothing or cannot be evaluated
// (ADR-242). Disabled, SourceUnsupported and TooManyNamespaces are settled
// configuration: the source grants nothing. MetadataUnavailable and
// MetadataNotObserved mean that its current namespace metadata is unknown.
const (
	SourceDisabled          = "Disabled"
	SourceUnsupported       = "SourceUnsupported"
	SourceTooManyNamespaces = "TooManyNamespaces"
	MetadataUnavailable     = "MetadataUnavailable"
	MetadataNotObserved     = "MetadataNotObserved"
	// DecisionTimeSource is a supported kubernetesExec/kubernetesAccessReview
	// source (ADR-245): it grants per principal and Pod at request time, so
	// a configuration preview cannot evaluate it.
	DecisionTimeSource = "DecisionTimeSource"
)

// NamespaceGrant is one namespace that a source currently grants to Subjects.
type NamespaceGrant struct {
	Namespace       NamespaceRef
	ResourceVersion string
	Subjects        []Subject
}

func hexDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func (k NamespaceKeys) Valid() bool {
	return len(k.Labels)+len(k.Annotations) <= 32 && slices.IsSorted(k.Labels) && slices.IsSorted(k.Annotations) &&
		identity.Strings(k.Labels, 32, 317) && identity.Strings(k.Annotations, 32, 317)
}

// Valid checks one observed namespace against keys; live requires the opaque
// resourceVersion of a current observation, an accepted one has none.
func (n ObservedNamespace) Valid(k NamespaceKeys, live bool) bool {
	if !identity.Text(n.Name, 63) || !identity.Text(n.UID, 64) || live != (n.ResourceVersion != "") || len(n.ResourceVersion) > 128 || len(n.Labels)+len(n.Annotations) == 0 {
		return false
	}
	for _, m := range []struct {
		values map[string]string
		keys   []string
	}{{n.Labels, k.Labels}, {n.Annotations, k.Annotations}} {
		for key, v := range m.values {
			if !slices.Contains(m.keys, key) || v != "" && !hexDigest(v) {
				return false
			}
		}
	}
	return true
}

func (o NamespaceObservation) Valid() bool {
	if !authorization.UUID(o.ClusterID) || !o.Keys.Valid() || len(o.Keys.Labels)+len(o.Keys.Annotations) == 0 || len(o.Namespaces) > MaxObservedNamespaces {
		return false
	}
	names := map[string]bool{}
	for i, n := range o.Namespaces {
		if !n.Valid(o.Keys, false) || names[n.Name] || i > 0 && o.Namespaces[i-1].UID >= n.UID {
			return false
		}
		names[n.Name] = true
	}
	return true
}

type Target struct {
	ClusterID string
	Namespace NamespaceRef
	Workload  WorkloadRef
}

// Candidate lacks an assignment ID by design. Accepted configuration, source
// protection/directory qualification and persistent assignment reconciliation
// MUST run before converting one to an authorization.CurrentAssignment.
type Candidate struct {
	Basis        Resource
	Subject      Subject
	Role, Effect string
}
type Proposal struct {
	Candidates []Candidate
	Reason     string
}

func ProposeBinding(b Binding, target Target, now time.Time) Proposal {
	if b.Scope.ClusterID != target.ClusterID || b.Scope.Namespace != target.Namespace || (len(b.Scope.Workloads) != 0 && !slices.Contains(b.Scope.Workloads, target.Workload)) {
		return Proposal{Reason: "OutsideScope"}
	}
	if (b.Resource.Deleting && b.Effect == "Allow") || (!b.NotAfter.IsZero() && !now.Before(b.NotAfter)) {
		return Proposal{Reason: "InactiveBinding"}
	}
	if b.Effect != "Allow" && b.Effect != "Deny" {
		return Proposal{Reason: "InvalidBinding"}
	}
	var out []Candidate
	for _, subject := range b.Subjects {
		for _, role := range b.Roles {
			out = append(out, Candidate{b.Resource, subject, role, b.Effect})
		}
	}
	return Proposal{Candidates: out, Reason: "RequiresAcceptance"}
}

// Why a guarded or group-ID source grants nothing for now (ADR-247): its
// admission guard proof or the configured group directory is not current.
// Like MetadataUnavailable, the source's accepted assignments are kept but
// grant nothing until a current observation is accepted.
const (
	GuardUnavailable     = "GuardUnavailable"
	DirectoryUnavailable = "DirectoryUnavailable"
)

// NamespaceGuardProof is a current proof that an enforcing admission guard
// protects these namespace label and annotation keys of one cluster against
// writers other than its administrators (ADR-247): a live dry-run denial of
// an unprivileged probe, within its original interval. It says nothing about
// historical values: the source's reviewRef attests their review.
type NamespaceGuardProof struct {
	ClusterID, Name           string
	LabelKeys, AnnotationKeys []string
	ObservedAt, FreshUntil    time.Time
}

// GroupDirectory is the administrator-configured set of stable group IDs of
// one issuer (the protected identity settings' eligibleGroups) that groupID
// mapping validates values against (ADR-247). It is not a directory reader.
type GroupDirectory struct {
	Issuer                 string
	Groups                 []string
	ObservedAt, FreshUntil time.Time
}

// SourceEvidence is what a guarded or group-ID source needs at evaluation
// time; nil fields are unknown.
type SourceEvidence struct {
	Guard *NamespaceGuardProof
	// WorkloadGuard proves the workload metadata guard of a
	// workloadMetadata source's cluster (ADR-247).
	WorkloadGuard *NamespaceGuardProof
	Directory     *GroupDirectory
	Now           time.Time
}

func (p *NamespaceGuardProof) Current(now time.Time) bool {
	return p != nil && !now.Before(p.ObservedAt) && now.Before(p.FreshUntil) && p.FreshUntil.Sub(p.ObservedAt) <= 30*time.Second
}

func (d *GroupDirectory) Current(now time.Time) bool {
	return d != nil && !now.Before(d.ObservedAt) && now.Before(d.FreshUntil) && d.FreshUntil.Sub(d.ObservedAt) <= 5*time.Minute
}
