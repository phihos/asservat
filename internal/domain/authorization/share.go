package authorization

import (
	"slices"
	"strings"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

// ADR-232 (S-06 increment 1): a concrete share of one stored pod-status
// artifact. A share grants ReadApproved of exactly that artifact to its
// recipients and, since ADR-233, DownloadApproved of the same artifact; it
// never grants collection, raw access or inventory. It is evaluated only after
// ordinary eligibility fails.
const (
	// ShareMaxLifetime bounds every share; ShareDefaultLifetime is used when
	// the creator names no expiry. Both are constants, not configuration.
	ShareMaxLifetime     = 7 * 24 * time.Hour
	ShareDefaultLifetime = 24 * time.Hour
	ShareMaxRecipients   = 8
	ShareMaxManagers     = 8
	// ShareMaxActivePerArtifact bounds unrevoked, unexpired shares of one artifact.
	ShareMaxActivePerArtifact = 32
	ShareScope                = "evidence:share"
	// ShareMaxRevision is the wire contract's revision bound; transfers past
	// it are refused (a share lives at most seven days).
	ShareMaxRevision = 1000000000
)

// SharePhase is derived at read time; only revocation is stored.
type SharePhase string

const (
	ShareActive    SharePhase = "Active"
	ShareExpired   SharePhase = "Expired"
	ShareRevoked   SharePhase = "Revoked"
	ShareSuspended SharePhase = "Suspended"
)

// ShareRecipient is an issuer-scoped stable user or group ID. Display names
// are never recipients.
type ShareRecipient struct {
	Kind, Issuer, ID string
}

func (r ShareRecipient) Valid() bool {
	return (r.Kind == "User" || r.Kind == "Group") && identity.Text(r.Issuer, 2048) && identity.Text(r.ID, 256)
}

// Key is the recipient's lookup key: one per recipient, matched against the
// keys of the caller's current principal and groups.
func (r ShareRecipient) Key() string { return r.Kind + "\n" + r.Issuer + "\n" + r.ID }

// RecipientKeys are the keys a current identity can match: its own user key
// (humans only, as ordinary User assignments) and one per current group.
func RecipientKeys(i identity.Identity) []string {
	var keys []string
	if i.Principal.Kind == identity.Human {
		keys = append(keys, ShareRecipient{"User", i.Principal.Issuer, i.Principal.Subject}.Key())
	}
	for _, g := range i.Groups {
		keys = append(keys, ShareRecipient{"Group", i.Principal.Issuer, g}.Key())
	}
	return keys
}

func (r ShareRecipient) matches(i identity.Identity) bool {
	if r.Issuer != i.Principal.Issuer {
		return false
	}
	if r.Kind == "User" {
		return i.Principal.Kind == identity.Human && r.ID == i.Principal.Subject
	}
	return slices.Contains(i.Groups, r.ID)
}

// Share is one stored share row. Management pins the creator's contributing
// evidence-owner assignments at creation, including their basis digests: a
// share is managed only while one of exactly these assignments is current.
// A removed and re-granted assignment is a new assignment ID, so a share once
// suspended is never silently restored (REQ-SHR-004/007).
type Share struct {
	ID, RootID, ArtifactID, CaseID string
	Target                         Target
	Version                        artifact.Digest
	Creator                        identity.Principal
	Management                     []artifact.AudienceAssignment
	Recipients                     []ShareRecipient
	CreatedAt, ExpiresAt           time.Time
	RevokedAt                      time.Time
	Revision                       int64
	// ObservedAt/ValidUntil bound this read of the row (at most five seconds).
	ObservedAt, ValidUntil time.Time
}

func (s Share) Valid() bool {
	if !UUID(s.ID) || !UUID(s.RootID) || !UUID(s.ArtifactID) || !UUID(s.CaseID) || !s.Target.Valid() || s.Version == (artifact.Digest{}) ||
		!s.Creator.Valid() || s.Creator.Kind != identity.Human || s.CreatedAt.IsZero() || !s.ExpiresAt.After(s.CreatedAt) || s.ExpiresAt.Sub(s.CreatedAt) > ShareMaxLifetime ||
		len(s.Management) < 1 || len(s.Management) > ShareMaxManagers || len(s.Recipients) < 1 || len(s.Recipients) > ShareMaxRecipients ||
		// Every transfer (ADR-238) and the one revocation add one revision.
		s.Revision < 1 || s.Revision > ShareMaxRevision || !s.RevokedAt.IsZero() && s.Revision < 2 {
		return false
	}
	seen := map[string]bool{}
	for _, a := range s.Management {
		if !validAudience(a) || a.Role != "evidence-owner" || seen[a.AssignmentID] {
			return false
		}
		seen[a.AssignmentID] = true
	}
	keys := map[string]bool{}
	for _, r := range s.Recipients {
		if !r.Valid() || r.Issuer != s.Creator.Issuer || keys[r.Key()] {
			return false
		}
		keys[r.Key()] = true
	}
	return true
}

// Phase derives the share's state from the current permission projection of
// its target. Revoked and Expired are final; Suspended means no pinned
// management assignment is current (or a current deny names it).
func (s Share) Phase(p Projection, now time.Time) SharePhase {
	switch {
	case !s.RevokedAt.IsZero():
		return ShareRevoked
	case !now.Before(s.ExpiresAt):
		return ShareExpired
	case len(s.managers(p, now)) == 0:
		return ShareSuspended
	}
	return ShareActive
}

// managers returns the pinned assignments that are still exactly current
// allows of the projection and not named by a current deny. The creator's own
// user deny suspends the share too. A projection for another target manages
// nothing.
func (s Share) managers(p Projection, now time.Time) []CurrentAssignment {
	if p.Target != s.Target {
		return nil
	}
	creator := identity.Identity{Principal: s.Creator}
	for _, d := range p.Denies {
		if matches(d.Audience, creator) && permits(d.Audience.Role, ReadApproved) {
			return nil
		}
	}
	var out []CurrentAssignment
	for _, pinned := range s.Management {
		named := false
		for _, d := range p.Denies {
			if d.Audience.Kind == pinned.Kind && d.Audience.Issuer == pinned.Issuer && d.Audience.SubjectID == pinned.SubjectID && permits(d.Audience.Role, ReadApproved) {
				named = true
			}
		}
		if named {
			continue
		}
		for _, a := range p.Allows {
			if a.Audience == pinned && identity.Fresh(a.ObservedAt, a.FreshUntil, now, 60*time.Second) {
				out = append(out, a)
			}
		}
	}
	return out
}

// EvaluateShare is the recipient branch of ReadApproved. Callers use it only
// after ordinary eligibility failed. Current denies win exactly as in the
// ordinary evaluator; the share must be active, name the caller and cover the
// exact target (and, with e, the exact artifact, with at least one current
// pinned manager inside the artifact's retained audience). It never grants
// CollectContext; DownloadApproved is EvaluateShareFor.
func EvaluateShare(i identity.Identity, p Projection, t Target, e *Retained, s Share, now time.Time) Result {
	return evaluateShare(ReadApproved, i, p, t, e, s, now)
}

// EvaluateShareFor is EvaluateShare for ReadApproved or DownloadApproved.
// DownloadApproved (ADR-233) also requires the evidence:download scope, as the
// ordinary facet does; denies of either operation's roles win alike.
func EvaluateShareFor(op Operation, i identity.Identity, p Projection, t Target, e *Retained, s Share, now time.Time) Result {
	return evaluateShare(op, i, p, t, e, s, now)
}

func evaluateShare(op Operation, i identity.Identity, p Projection, t Target, e *Retained, s Share, now time.Time) Result {
	deny := func(reason string) Result { return Result{Reason: reason} }
	if op != ReadApproved && op != DownloadApproved || !t.Valid() || !s.Valid() || s.Target != t {
		return deny("InvalidRequest")
	}
	if !i.Valid(now) {
		return deny("IdentityUnavailable")
	}
	if !projectionCurrent(p, t, now) {
		return deny("PermissionUnavailable")
	}
	if !identity.Fresh(s.ObservedAt, s.ValidUntil, now, 5*time.Second) {
		return deny("ShareUnavailable")
	}
	until := identity.Earlier(identity.Earlier(i.ValidUntil, p.FreshUntil), identity.Earlier(p.DeniesFreshUntil, s.ValidUntil))
	for _, d := range p.Denies {
		if !identity.Fresh(d.ObservedAt, d.FreshUntil, now, PermissionObservationInterval) {
			return deny("PermissionUnavailable")
		}
		until = identity.Earlier(until, d.FreshUntil)
		if matches(d.Audience, i) && permits(d.Audience.Role, op) {
			return deny("ExplicitDeny")
		}
	}
	if !slices.Contains(i.Scopes, "evidence:read") || op == DownloadApproved && !slices.Contains(i.Scopes, "evidence:download") {
		return deny("InsufficientScope")
	}
	recipient := false
	for _, r := range s.Recipients {
		recipient = recipient || r.matches(i)
	}
	if !recipient {
		return deny("NoEntitlement")
	}
	switch s.Phase(p, now) {
	case ShareRevoked:
		return deny("ShareRevoked")
	case ShareExpired:
		return deny("ShareExpired")
	case ShareSuspended:
		return deny("ShareSuspended")
	}
	managers := s.managers(p, now)
	if e != nil {
		if !e.valid() || e.ArtifactID != s.ArtifactID || e.Target != t || !now.Before(e.ExpiresAt) {
			return deny("EvidenceUnavailable")
		}
		if e.DataClass != "metadata" {
			return deny("RawAccessUnsupported")
		}
		managers = slices.DeleteFunc(managers, func(a CurrentAssignment) bool { return !slices.Contains(e.Audience, a.Audience) })
		if len(managers) == 0 {
			return deny("ShareSuspended")
		}
		until = identity.Earlier(until, e.ExpiresAt)
	}
	contributing := make([]artifact.AudienceAssignment, 0, len(managers))
	for _, a := range managers {
		until = identity.Earlier(until, a.FreshUntil)
		contributing = append(contributing, a.Audience)
	}
	until = identity.Earlier(until, s.ExpiresAt)
	slices.SortFunc(contributing, func(a, b artifact.AudienceAssignment) int { return strings.Compare(a.AssignmentID, b.AssignmentID) })
	return Result{true, "Shared", i.Principal, i.Policy, p.Revision, until, contributing}
}

// ShareManagement checks a creator's current authority to share one artifact:
// ordinary ReadApproved of the artifact (retained audience included), the
// evidence:share scope and at least one contributing evidence-owner
// assignment. It returns the assignments to pin (at most ShareMaxManagers).
func ShareManagement(i identity.Identity, p Projection, t Target, e *Retained, now time.Time) (Result, []artifact.AudienceAssignment) {
	return SelectShareManagement(i, p, t, e, ManagementRequest{}, now)
}

// ManagementRequest is an explicit management selection (REQ-SHR-008,
// ADR-238). The zero value selects the default. Mode "creator" pins the
// caller's own individual evidence-owner assignments; mode "teams" pins the
// caller's evidence-owner assignments of exactly the named groups (stable IDs
// of the caller's issuer). Every selected team must be one the caller holds:
// selecting a team the caller does not belong to needs a management
// delegation this release does not offer, so it is refused
// (ManagementNotHeld), never silently dropped.
type ManagementRequest struct {
	Mode  string
	Teams []string
}

func (r ManagementRequest) Valid() bool {
	switch r.Mode {
	case "":
		return len(r.Teams) == 0
	case "creator":
		return len(r.Teams) == 0
	case "teams":
		if len(r.Teams) < 1 || len(r.Teams) > ShareMaxManagers {
			return false
		}
		seen := map[string]bool{}
		for _, g := range r.Teams {
			if !identity.Text(g, 256) || seen[g] {
				return false
			}
			seen[g] = true
		}
		return true
	}
	return false
}

// SelectShareManagement is ShareManagement with an explicit selection. The
// caller's current contributing evidence-owner assignments for the artifact
// (ordinary ReadApproved, retained audience included) are the only
// candidates, so a selection can never add a team the caller does not hold
// now or that is outside the artifact's audience.
func SelectShareManagement(i identity.Identity, p Projection, t Target, e *Retained, m ManagementRequest, now time.Time) (Result, []artifact.AudienceAssignment) {
	if e == nil || i.Principal.Kind != identity.Human || !m.Valid() {
		return Result{Reason: "InvalidRequest"}, nil
	}
	r := Evaluate(i, p, ReadApproved, t, e, now)
	if !r.Eligible {
		return r, nil
	}
	if !slices.Contains(i.Scopes, ShareScope) {
		return Result{Reason: "InsufficientScope"}, nil
	}
	// Default management (REQ-SHR-008, ADR-232 increment 4): the creator's
	// contributing evidence-owner Group assignments (the owner teams); only
	// without any team, the creator's individual User assignments. More than
	// eight is refused rather than silently truncated.
	var teams, personal []artifact.AudienceAssignment
	for _, a := range r.ContributingAssignments {
		switch {
		case a.Role != "evidence-owner":
		case a.Kind == "Group":
			teams = append(teams, a)
		case a.Kind == "User":
			personal = append(personal, a)
		}
	}
	var owners []artifact.AudienceAssignment
	switch m.Mode {
	case "":
		owners = teams
		if len(owners) == 0 {
			owners = personal
		}
	case "creator":
		if owners = personal; len(owners) == 0 {
			return Result{Reason: "ManagementNotHeld"}, nil
		}
	case "teams":
		for _, g := range m.Teams {
			n := len(owners)
			for _, a := range teams {
				if a.SubjectID == g {
					owners = append(owners, a)
				}
			}
			if len(owners) == n {
				return Result{Reason: "ManagementNotHeld"}, nil
			}
		}
	}
	if len(owners) == 0 {
		return Result{Reason: "NoOwnerAuthority"}, nil
	}
	if len(owners) > ShareMaxManagers {
		return Result{Reason: "ManagementTooBroad"}, nil
	}
	return r, owners
}

// AdministeredShareManagement is the scoped management delegation of an
// installation administrator (ADR-238): it pins the current evidence-owner
// Group assignments of the named teams (stable IDs of issuer) that cover the
// target and are inside the artifact's retained audience, whether or not the
// administrator belongs to them. Each team needs at least one such current,
// undenied assignment (else ManagementNotHeld); more than eight assignments
// are refused. It never adds an assignment outside the retained audience, so
// it cannot widen who may read the artifact, and it grants the administrator
// nothing. The caller checks the administrator authority first.
func AdministeredShareManagement(issuer string, p Projection, t Target, e *Retained, teams []string, now time.Time) (Result, []artifact.AudienceAssignment) {
	m := ManagementRequest{Mode: "teams", Teams: teams}
	if e == nil || !m.Valid() || !identity.Text(issuer, 2048) || !t.Valid() || e.Target != t || !e.valid() {
		return Result{Reason: "InvalidRequest"}, nil
	}
	if !projectionCurrent(p, t, now) {
		return Result{Reason: "PermissionUnavailable"}, nil
	}
	until := identity.Earlier(p.FreshUntil, p.DeniesFreshUntil)
	var owners []artifact.AudienceAssignment
	for _, g := range teams {
		n := len(owners)
		for _, a := range p.Allows {
			x := a.Audience
			if x.Kind != "Group" || x.Issuer != issuer || x.SubjectID != g || x.Role != "evidence-owner" || !slices.Contains(e.Audience, x) || !identity.Fresh(a.ObservedAt, a.FreshUntil, now, 60*time.Second) {
				continue
			}
			denied := false
			for _, d := range p.Denies {
				denied = denied || d.Audience.Kind == "Group" && d.Audience.Issuer == issuer && d.Audience.SubjectID == g && permits(d.Audience.Role, ReadApproved)
			}
			if !denied {
				owners = append(owners, x)
				until = identity.Earlier(until, a.FreshUntil)
			}
		}
		if len(owners) == n {
			return Result{Reason: "ManagementNotHeld"}, nil
		}
	}
	if len(owners) > ShareMaxManagers {
		return Result{Reason: "ManagementTooBroad"}, nil
	}
	return Result{Eligible: true, Reason: "Administered", PermissionRevision: p.Revision, ValidUntil: until, ContributingAssignments: owners}, owners
}

// ManagedBy returns the pinned management assignments that i holds now
// (ADR-232 increment 4). i must be a human with evidence:share, the target's
// projection current, no current deny may name i, and the assignment must
// still be exactly a current allow (Share.managers). Holding one makes i a
// current manager of s, who may list and revoke it. Group membership changes
// within the same assignment keep a team member managing; a newly added owner
// binding is a new assignment ID and manages no older share. The second
// result bounds the answer's validity.
func (s Share) ManagedBy(i identity.Identity, p Projection, now time.Time) ([]artifact.AudienceAssignment, time.Time) {
	if !s.Valid() || !i.Valid(now) || i.Principal.Kind != identity.Human || !slices.Contains(i.Scopes, ShareScope) || !projectionCurrent(p, s.Target, now) {
		return nil, time.Time{}
	}
	until := identity.Earlier(i.ValidUntil, identity.Earlier(p.FreshUntil, p.DeniesFreshUntil))
	for _, d := range p.Denies {
		if !identity.Fresh(d.ObservedAt, d.FreshUntil, now, PermissionObservationInterval) || matches(d.Audience, i) && permits(d.Audience.Role, ReadApproved) {
			return nil, time.Time{}
		}
		until = identity.Earlier(until, d.FreshUntil)
	}
	var held []artifact.AudienceAssignment
	for _, a := range s.managers(p, now) {
		if matches(a.Audience, i) {
			held = append(held, a.Audience)
			until = identity.Earlier(until, a.FreshUntil)
		}
	}
	if len(held) == 0 {
		return nil, time.Time{}
	}
	return held, until
}

// projectionCurrent is the ordinary evaluator's projection precondition.
func projectionCurrent(p Projection, t Target, now time.Time) bool {
	return p.Revision.Valid() && p.Target == t && p.DeniesComplete && identity.Fresh(p.ObservedAt, p.FreshUntil, now, 60*time.Second) &&
		identity.Fresh(p.DeniesObservedAt, p.DeniesFreshUntil, now, PermissionObservationInterval) && rowsValid(p.Allows) && rowsValid(p.Denies)
}
