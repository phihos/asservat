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
}

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

// NamespaceQuery is assembled internally from a source's configured keys, not
// from a public evidence request. Only these metadata keys may leave the reader.
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

// ProposeNamespace expands value maps only; groupID needs qualified directory
// validation and is intentionally not guessed here. A declaration of a guard or
// administrator review is never treated as proof that it is current/enforced.
func ProposeNamespace(s Source, ns NamespaceMetadata, target Target, now time.Time) Proposal {
	if s.Type != "namespaceMetadata" {
		return Proposal{Reason: "UnsupportedSource"}
	}
	if !s.Enabled || s.Resource.Deleting {
		return Proposal{Reason: "DisabledSource"}
	}
	if target.ClusterID != s.ClusterID || ns.ClusterID != s.ClusterID || ns.Namespace != target.Namespace || ns.Deleting || slices.Contains(s.ExcludedNamespaces, ns.Namespace.Name) {
		return Proposal{Reason: "OutsideScope"}
	}
	if !identity.Fresh(ns.ObservedAt, ns.FreshUntil, now, 60*time.Second) || s.MaxDecisionAge < time.Second || s.MaxDecisionAge > time.Minute || !now.Before(ns.ObservedAt.Add(s.MaxDecisionAge)) {
		return Proposal{Reason: "StaleNamespace"}
	}
	for key, value := range s.NamespaceSelector {
		if actual, ok := ns.Labels[key]; !ok || actual != value {
			return Proposal{Reason: "OutsideScope"}
		}
	}
	var value string
	switch s.Mapping.Field {
	case "annotation":
		value = ns.Annotations[s.Mapping.Key]
	case "label":
		value = ns.Labels[s.Mapping.Key]
	default:
		return Proposal{Reason: "InvalidMapping"}
	}
	if !identity.Text(value, 256) {
		return Proposal{Reason: "UnmappedValue"}
	}
	if s.Mapping.Mode == "groupID" {
		return Proposal{Reason: "DirectoryValidationRequired"}
	}
	if s.Mapping.Mode != "valueMap" {
		return Proposal{Reason: "InvalidMapping"}
	}
	groups := s.Mapping.Values[value]
	if !identity.Strings(groups, 16, 256) || len(groups) == 0 {
		return Proposal{Reason: "UnmappedValue"}
	}
	var out []Candidate
	for _, group := range groups {
		out = append(out, Candidate{s.Resource, Subject{"Group", s.Mapping.Issuer, group}, s.Role, "Allow"})
	}
	return Proposal{Candidates: out, Reason: "RequiresProtectionQualification"}
}
