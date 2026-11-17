// Package privacy defines pure retention rules. Policy observations and the
// resulting deadlines are not collection, disclosure or preservation grants.
package privacy

import (
	"errors"
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

var (
	ErrInvalid     = errors.New("invalid retention input")
	ErrUnavailable = errors.New("complete current retention policy unavailable")
	ErrConflict    = errors.New("incompatible retention policies")
	ErrExpired     = errors.New("retention leaves no usable time")
)

const MaxAgeSeconds int64 = 315360000

type Rule struct {
	Name                          string
	PrivacyClasses, EvidenceTypes []string
	MaxAgeSeconds                 int64
}

// Policy has already been matched against protected cluster/namespace/workload
// metadata. Baseline is determined by configuration provenance, not its name.
type Policy struct {
	Revision                                              identity.Revision
	Baseline                                              bool
	PurposeRef                                            string
	DefaultSeconds, MaximumSeconds, DeletionBudgetSeconds int64
	Rules                                                 []Rule
}

// PolicySet is the current policies matching one target; Revision digests them.
type PolicySet struct {
	Target   authorization.Target
	Revision identity.Revision
	Policies []Policy
}

// Input classifications are derived by the qualified producer, never supplied
// as a user claim that arbitrary data is nonpersonal or innocuous context.
type Input struct {
	ControlKind string `json:",omitempty"` // "case-metadata" only for protected parameter/control records
	Target      authorization.Target
	// Labels select label-scoped policies; nil when not observed.
	Labels                     *TargetLabels `json:",omitempty"`
	PrivacyClass, EvidenceType string
	RequestedSeconds           int64 // zero selects the lowest applicable default
	AnchorAt                   time.Time
	Parents                    []Deadlines
}

type Deadlines struct{ AnchorAt, ExpiresAt, DeleteBy time.Time }
type Resolution struct {
	Target                                                  authorization.Target
	PolicyRevision                                          identity.Revision
	PurposeRef, PrivacyClass, EvidenceType                  string
	RequestedSeconds, MaximumSeconds, DeletionBudgetSeconds int64
	Policies                                                []artifact.RetentionRule
	Deadlines
	// ValidUntil is the access end (ExpiresAt).
	ValidUntil time.Time
}

func age(n int64) bool { return n >= 1 && n <= MaxAgeSeconds }
func class(s string) bool {
	return slices.Contains([]string{"unknown", "potentialPersonalData", "personalData", "specialCategoryPossible", "verifiedNonPersonal"}, s)
}
func evidenceType(s string) bool {
	return slices.Contains([]string{"coreDump", "heapDump", "packetCapture", "syscallTrace", "logs", "files", "profile", "commandOutput", "context", "other"}, s)
}
func finiteTime(t time.Time) bool {
	return !t.IsZero() && t.Year() >= 2020 && t.Year() <= 9999 && t.Nanosecond()%1000 == 0
}
func (d Deadlines) Valid() bool {
	return d.ValidRetained() && d.AnchorAt.Before(d.ExpiresAt)
}

// A retained object can have its entire readable interval closed. Original
// registrations and new acquisition still require strictly positive read time.
func (d Deadlines) ValidRetained() bool {
	return finiteTime(d.AnchorAt) && finiteTime(d.ExpiresAt) && finiteTime(d.DeleteBy) && !d.ExpiresAt.Before(d.AnchorAt) && d.ExpiresAt.Before(d.DeleteBy)
}

func (p Policy) Valid() bool {
	if !p.Revision.Valid() || !identity.Text(p.PurposeRef, 128) || !age(p.DefaultSeconds) || !age(p.MaximumSeconds) || p.DeletionBudgetSeconds < 1 || p.DeletionBudgetSeconds >= p.MaximumSeconds {
		return false
	}
	seen := map[string]bool{}
	for _, r := range p.Rules {
		if !identity.Text(r.Name, 63) || seen[r.Name] || !age(r.MaxAgeSeconds) || r.MaxAgeSeconds <= p.DeletionBudgetSeconds || !identity.Strings(r.PrivacyClasses, 5, 32) || !identity.Strings(r.EvidenceTypes, 10, 32) {
			return false
		}
		seen[r.Name] = true
		for _, c := range r.PrivacyClasses {
			if !class(c) {
				return false
			}
		}
		for _, t := range r.EvidenceTypes {
			if !evidenceType(t) {
				return false
			}
		}
	}
	return true
}

func matchesClass(rule []string, observed string) bool {
	if len(rule) == 0 || slices.Contains(rule, observed) {
		return true
	}
	switch observed {
	case "unknown":
		return slices.Contains(rule, "potentialPersonalData")
	case "personalData":
		return slices.Contains(rule, "potentialPersonalData")
	case "specialCategoryPossible":
		return slices.Contains(rule, "personalData") || slices.Contains(rule, "potentialPersonalData")
	}
	return false
}

// Resolve takes the intersection, never a priority override. It retains every
// matched policy reference even if a rule did not supply the shortest maximum.
// Scope matching and source protection must be established by the reader.
func Resolve(set PolicySet, in Input, now time.Time) (Resolution, error) {
	r, err := resolveDeadlines(set, in, now)
	if err != nil {
		return Resolution{}, err
	}
	if !now.Before(r.ExpiresAt) {
		return Resolution{}, ErrExpired
	}
	return r, nil
}

func resolveDeadlines(set PolicySet, in Input, now time.Time) (Resolution, error) {
	var out Resolution
	if (in.ControlKind != "" && in.ControlKind != "case-metadata") || !in.Target.Valid() || !class(in.PrivacyClass) || !evidenceType(in.EvidenceType) || in.RequestedSeconds < 0 || in.RequestedSeconds > MaxAgeSeconds || !finiteTime(in.AnchorAt) || in.AnchorAt.After(now) || len(in.Parents) > 64 {
		return out, ErrInvalid
	}
	if set.Target != in.Target || !set.Revision.Valid() || len(set.Policies) < 1 {
		return out, ErrUnavailable
	}
	maximum, requested, budget := MaxAgeSeconds, MaxAgeSeconds, int64(0)
	baseline := 0
	seen := map[string]bool{}
	refs := make([]artifact.RetentionRule, 0, len(set.Policies))
	purpose := ""
	for _, p := range set.Policies {
		if !p.Valid() || seen[p.Revision.UID] {
			return out, ErrUnavailable
		}
		seen[p.Revision.UID] = true
		if p.Baseline {
			baseline++
		}
		if purpose != "" && purpose != p.PurposeRef {
			return out, ErrConflict
		}
		purpose = p.PurposeRef
		requested = min(requested, p.DefaultSeconds)
		maximum = min(maximum, p.MaximumSeconds)
		budget = max(budget, p.DeletionBudgetSeconds)
		for _, r := range p.Rules {
			if matchesClass(r.PrivacyClasses, in.PrivacyClass) && (len(r.EvidenceTypes) == 0 || in.EvidenceType == "other" || slices.Contains(r.EvidenceTypes, in.EvidenceType)) {
				maximum = min(maximum, r.MaxAgeSeconds)
			}
		}
		refs = append(refs, artifact.RetentionRule{UID: p.Revision.UID, Generation: p.Revision.Generation, Digest: artifact.Digest(p.Revision.Digest)})
	}
	if baseline != 1 {
		return out, ErrUnavailable
	}
	if budget >= maximum {
		return out, ErrConflict
	}
	if in.RequestedSeconds != 0 {
		requested = in.RequestedSeconds
	}
	anchor := in.AnchorAt.UTC()
	for _, p := range in.Parents {
		if !p.Valid() || p.AnchorAt.After(now) {
			return out, ErrInvalid
		}
		anchor = identity.Earlier(anchor, p.AnchorAt.UTC())
	}
	hard := anchor.Add(time.Duration(maximum) * time.Second)
	for _, p := range in.Parents {
		hard = identity.Earlier(hard, p.DeleteBy.UTC())
	}
	expires := identity.Earlier(anchor.Add(time.Duration(requested)*time.Second), hard.Add(-time.Duration(budget)*time.Second))
	for _, p := range in.Parents {
		expires = identity.Earlier(expires, p.ExpiresAt.UTC())
	}
	deadlines := Deadlines{AnchorAt: anchor, ExpiresAt: expires, DeleteBy: identity.Earlier(hard, expires.Add(time.Duration(budget)*time.Second))}
	if !deadlines.Valid() {
		return out, ErrExpired
	}
	slices.SortFunc(refs, func(a, b artifact.RetentionRule) int {
		if a.UID < b.UID {
			return -1
		}
		if a.UID > b.UID {
			return 1
		}
		return 0
	})
	return Resolution{Target: in.Target, PolicyRevision: set.Revision, PurposeRef: purpose, PrivacyClass: in.PrivacyClass, EvidenceType: in.EvidenceType, RequestedSeconds: requested, MaximumSeconds: maximum, DeletionBudgetSeconds: budget, Policies: refs, Deadlines: deadlines, ValidUntil: expires}, nil
}

// CaseMetadataPolicy projects the explicitly configured metadata lifetime.
// Rules naming evidence kinds do not govern a user-authored control record;
// general data-class restrictions continue to apply.
func CaseMetadataPolicy(p ScopedPolicy) Policy {
	out := p.Policy
	out.DefaultSeconds, out.MaximumSeconds = p.CaseDefaultSeconds, p.CaseMaximumSeconds
	out.Rules = nil
	for _, r := range p.Policy.Rules {
		if len(r.EvidenceTypes) == 0 {
			out.Rules = append(out.Rules, r)
		}
	}
	return out
}
