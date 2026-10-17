// Package authorization owns pure eligibility rules. Eligibility does not grant
// execution or disclosure: capacity, accepted scope, audit and custody still gate
// those effects. Inputs come from current protected projections, not a request.
package authorization

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"slices"
	"time"
)

type Operation string

const (
	CollectContext   Operation = "collectContext"
	ReadApproved     Operation = "readApproved"
	DownloadApproved Operation = "downloadApproved"
)

type Target struct{ ClusterID, NamespaceUID, WorkloadUID, PodUID string }
type CurrentAssignment struct {
	Audience               artifact.AudienceAssignment
	ObservedAt, FreshUntil time.Time
}

// A projection is already narrowed to an exact whole-pod target. DeniesComplete
// must attest the complete authoritative deny set, not just received allow rows.
type Projection struct {
	Target                 Target
	Revision               identity.Revision
	ObservedAt, FreshUntil time.Time
	DeniesComplete         bool
	// The complete deny snapshot has its own five-second maximum, including an
	// empty set. Positive configuration freshness cannot renew this deadline.
	DeniesObservedAt, DeniesFreshUntil time.Time
	Allows, Denies                     []CurrentAssignment
}

// Retained is loaded from committed, verified evidence provenance. The future
// catalog adapter must not populate it from stored_unpublished copy receipts.
type Retained struct {
	ArtifactID string
	Target     Target
	DataClass  string
	ExpiresAt  time.Time
	Audience   []artifact.AudienceAssignment
}
type Result struct {
	Eligible                             bool
	Reason                               string
	Principal                            identity.Principal
	IdentityRevision, PermissionRevision identity.Revision
	ValidUntil                           time.Time
	ContributingAssignments              []artifact.AudienceAssignment
}

func UUID(s string) bool {
	if len(s) != 36 || s == "00000000-0000-0000-0000-000000000000" {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !(c >= 'a' && c <= 'f' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
func (t Target) Valid() bool {
	return UUID(t.ClusterID) && identity.Text(t.NamespaceUID, 64) && identity.Text(t.WorkloadUID, 64) && identity.Text(t.PodUID, 64)
}
func (op Operation) Valid() bool {
	return op == CollectContext || op == ReadApproved || op == DownloadApproved
}
func validAudience(a artifact.AudienceAssignment) bool {
	return (a.Kind == "User" || a.Kind == "Group" || a.Kind == "Workload") && identity.Text(a.Issuer, 2048) && identity.Text(a.SubjectID, 256) && validRole(a.Role) && (a.BasisKind == "AccessBinding" || a.BasisKind == "PermissionSource") && identity.Text(a.BasisUID, 64) && UUID(a.AssignmentID) && a.BasisDigest != (artifact.Digest{})
}
func validRole(role string) bool {
	return role == "evidence-reader" || role == "workload-maintainer" || role == "evidence-owner" || role == "action-approver"
}
func permits(role string, op Operation) bool {
	switch op {
	case CollectContext:
		return role == "workload-maintainer"
	case ReadApproved, DownloadApproved:
		return role == "evidence-reader" || role == "workload-maintainer" || role == "evidence-owner"
	}
	return false
}
func matches(a artifact.AudienceAssignment, i identity.Identity) bool {
	if a.Issuer != i.Principal.Issuer {
		return false
	}
	switch a.Kind {
	case "Group":
		return slices.Contains(i.Groups, a.SubjectID)
	case "User":
		return i.Principal.Kind == identity.Human && a.SubjectID == i.Principal.Subject
	case "Workload":
		return i.Principal.Kind == identity.Workload && a.SubjectID == i.Principal.Subject
	}
	return false
}
func rowsValid(rows []CurrentAssignment) bool {
	if len(rows) > 256 {
		return false
	}
	seen := map[string]bool{}
	for _, a := range rows {
		if !validAudience(a.Audience) || seen[a.Audience.AssignmentID] {
			return false
		}
		seen[a.Audience.AssignmentID] = true
	}
	return true
}
func (e Retained) valid() bool {
	if !UUID(e.ArtifactID) || !e.Target.Valid() || e.ExpiresAt.IsZero() || len(e.Audience) < 1 || len(e.Audience) > 32 {
		return false
	}
	seen := map[string]bool{}
	for _, a := range e.Audience {
		if !validAudience(a) || seen[a.AssignmentID] {
			return false
		}
		seen[a.AssignmentID] = true
	}
	return true
}

// Evaluate is the ordinary context/approved-evidence facet only. It has no share
// or raw-grant fallback. Adding those must preserve deny and retained audiences.
func Evaluate(i identity.Identity, p Projection, op Operation, t Target, e *Retained, now time.Time) Result {
	return evaluate(i, p, op, t, e, now, true)
}

// ScopeEligibility checks ordinary target eligibility before any evidence lookup.
// Its contributing assignments are NOT a complete acquisition audience and do
// not grant access to an artifact. Evaluate still requires retained provenance.
func ScopeEligibility(i identity.Identity, p Projection, op Operation, t Target, now time.Time) Result {
	return evaluate(i, p, op, t, nil, now, false)
}

func evaluate(i identity.Identity, p Projection, op Operation, t Target, e *Retained, now time.Time, requireRetained bool) Result {
	deny := func(reason string) Result { return Result{Reason: reason} }
	if !op.Valid() || !t.Valid() {
		return deny("InvalidRequest")
	}
	if !i.Valid(now) {
		return deny("IdentityUnavailable")
	}
	if !p.Revision.Valid() || p.Target != t || !p.DeniesComplete || !identity.Fresh(p.ObservedAt, p.FreshUntil, now, 60*time.Second) || !identity.Fresh(p.DeniesObservedAt, p.DeniesFreshUntil, now, 5*time.Second) || !rowsValid(p.Allows) || !rowsValid(p.Denies) {
		return deny("PermissionUnavailable")
	}
	if op == CollectContext && e != nil {
		return deny("InvalidRequest")
	}
	if requireRetained && op != CollectContext && (e == nil || !e.valid() || e.Target != t || !now.Before(e.ExpiresAt)) {
		return deny("EvidenceUnavailable")
	}
	if e != nil && e.DataClass != "metadata" && e.DataClass != "extract" {
		return deny("RawAccessUnsupported")
	}
	until := identity.Earlier(i.ValidUntil, p.FreshUntil)
	until = identity.Earlier(until, p.DeniesFreshUntil)
	// All authoritative denies must remain current, even if an allow is fresh.
	for _, d := range p.Denies {
		if !identity.Fresh(d.ObservedAt, d.FreshUntil, now, 5*time.Second) {
			return deny("PermissionUnavailable")
		}
		until = identity.Earlier(until, d.FreshUntil)
		if matches(d.Audience, i) && permits(d.Audience.Role, op) {
			return deny("ExplicitDeny")
		}
	}
	required := []string{"evidence:read"}
	if op == CollectContext {
		required = []string{"evidence:capture"}
	}
	if op == DownloadApproved {
		required = append(required, "evidence:download")
	}
	for _, scope := range required {
		if !slices.Contains(i.Scopes, scope) {
			return deny("InsufficientScope")
		}
	}
	var audience []artifact.AudienceAssignment
	for _, a := range p.Allows {
		if !identity.Fresh(a.ObservedAt, a.FreshUntil, now, 60*time.Second) || !matches(a.Audience, i) || !permits(a.Audience.Role, op) {
			continue
		}
		if e != nil && !slices.Contains(e.Audience, a.Audience) {
			continue
		}
		audience = append(audience, a.Audience)
		until = identity.Earlier(until, a.FreshUntil)
	}
	if len(audience) == 0 {
		return deny("NoEntitlement")
	}
	if len(audience) > 32 && (op == CollectContext || requireRetained) {
		return deny("AudienceOverflow")
	}
	if e != nil {
		until = identity.Earlier(until, e.ExpiresAt)
	}
	// Deterministic provenance; a role is not an effect capability or raw grant.
	slices.SortFunc(audience, func(a, b artifact.AudienceAssignment) int {
		if a.AssignmentID < b.AssignmentID {
			return -1
		}
		if a.AssignmentID > b.AssignmentID {
			return 1
		}
		return 0
	})
	return Result{true, "Eligible", i.Principal, i.Policy, p.Revision, until, audience}
}
