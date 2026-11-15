package authorization

import (
	"slices"
	"strings"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

// ADR-232: a concrete share of one stored artifact grants ReadApproved and
// DownloadApproved of exactly that artifact to its recipients. It never
// grants collection, raw access or inventory and is evaluated only after
// ordinary eligibility fails. A share lasts until its expiry, which defaults
// to and never exceeds the artifact's access end (ADR-335 D7).
const (
	ShareScope = "evidence:share"
	// ShareMaxRevision is the wire contract's revision bound.
	ShareMaxRevision = 1000000000
)

// SharePhase is derived at read time; only revocation is stored.
type SharePhase string

const (
	ShareActive  SharePhase = "Active"
	ShareExpired SharePhase = "Expired"
	ShareRevoked SharePhase = "Revoked"
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
// (humans only) and one per current group.
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

// Share is one stored share row. Management records the managing groups (or
// the creator) by stable ID (ADR-330 D11): a manager is a human with
// evidence:share who is in a managing group now. Assignment IDs in the
// stored entries are provenance only.
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
		!s.Creator.Valid() || s.Creator.Kind != identity.Human || s.CreatedAt.IsZero() || !s.ExpiresAt.After(s.CreatedAt) ||
		len(s.Management) < 1 || len(s.Recipients) < 1 ||
		// Every transfer (ADR-238) and the one revocation add one revision.
		s.Revision < 1 || s.Revision > ShareMaxRevision || !s.RevokedAt.IsZero() && s.Revision < 2 {
		return false
	}
	for _, a := range s.Management {
		if !validAudience(a) || !sharingRole(a.Role) {
			return false
		}
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

// sharingRole is the role that carries sharing authority.
func sharingRole(role string) bool { return role == "evidence-owner" }

// Phase derives the share's state. Revoked and Expired are final.
func (s Share) Phase(now time.Time) SharePhase {
	switch {
	case !s.RevokedAt.IsZero():
		return ShareRevoked
	case !now.Before(s.ExpiresAt):
		return ShareExpired
	}
	return ShareActive
}

// EvaluateShare is the recipient branch of ReadApproved. Callers use it only
// after ordinary eligibility failed. Current denies win exactly as in the
// ordinary evaluator; the share must be active, name the caller and cover the
// exact target (and, with e, the exact unexpired artifact).
func EvaluateShare(i identity.Identity, p Projection, t Target, e *Retained, s Share, now time.Time) Result {
	return evaluateShare(ReadApproved, i, p, t, e, s, now)
}

// EvaluateShareFor is EvaluateShare for ReadApproved or DownloadApproved.
// DownloadApproved (ADR-233) also requires the evidence:download scope.
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
	if !slices.ContainsFunc(s.Recipients, func(r ShareRecipient) bool { return r.matches(i) }) {
		return deny("NoEntitlement")
	}
	switch s.Phase(now) {
	case ShareRevoked:
		return deny("ShareRevoked")
	case ShareExpired:
		return deny("ShareExpired")
	}
	if e != nil {
		if !e.valid() || e.ArtifactID != s.ArtifactID || e.Target != t || !now.Before(e.ExpiresAt) {
			return deny("EvidenceUnavailable")
		}
		if e.DataClass != "metadata" {
			return deny("RawAccessUnsupported")
		}
		until = identity.Earlier(until, e.ExpiresAt)
	}
	contributing := slices.Clone(s.Management)
	slices.SortFunc(contributing, func(a, b artifact.AudienceAssignment) int { return strings.Compare(a.AssignmentID, b.AssignmentID) })
	return Result{true, "Shared", i.Principal, i.Policy, p.Revision, identity.Earlier(until, s.ExpiresAt), contributing}
}

// ShareManagement checks a creator's current authority to share one artifact:
// ordinary ReadApproved of the artifact (retained audience included), the
// evidence:share scope and at least one contributing sharing assignment. It
// returns the management to record.
func ShareManagement(i identity.Identity, p Projection, t Target, e *Retained, now time.Time) (Result, []artifact.AudienceAssignment) {
	return SelectShareManagement(i, p, t, e, ManagementRequest{}, now)
}

// ManagementRequest is an explicit management selection (REQ-SHR-008,
// ADR-238). The zero value selects the default. Mode "creator" records the
// caller personally; mode "teams" records exactly the named groups, each of
// which the caller must hold now (else ManagementNotHeld).
type ManagementRequest struct {
	Mode  string
	Teams []string
}

func (r ManagementRequest) Valid() bool {
	switch r.Mode {
	case "", "creator":
		return len(r.Teams) == 0
	case "teams":
		return len(r.Teams) >= 1 && identity.Strings(r.Teams, len(r.Teams), 256)
	}
	return false
}

// SelectShareManagement is ShareManagement with an explicit selection. Only
// the caller's current contributing sharing assignments for the artifact are
// candidates, so a selection never adds a group outside the audience.
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
	// Default: the creator's groups with sharing authority; only without
	// any, the creator personally.
	var teams, personal []artifact.AudienceAssignment
	for _, a := range r.ContributingAssignments {
		switch {
		case !sharingRole(a.Role):
		case a.Kind == "Group":
			teams = append(teams, a)
		case a.Kind == "User":
			personal = append(personal, a)
		}
	}
	var owners []artifact.AudienceAssignment
	switch m.Mode {
	case "":
		if owners = teams; len(owners) == 0 {
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
	return r, owners
}

// AdministeredShareManagement is the scoped management delegation of an
// installation administrator (ADR-238): the named groups' current sharing
// assignments that cover the target inside the artifact's retained audience,
// whether or not the administrator belongs to them. It never widens who may
// read the artifact and grants the administrator nothing. The caller checks
// the administrator authority first.
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
			if x.Kind != "Group" || x.Issuer != issuer || x.SubjectID != g || !sharingRole(x.Role) || !slices.Contains(e.Audience, x) || !identity.Fresh(a.ObservedAt, a.FreshUntil, now, 60*time.Second) {
				continue
			}
			if !slices.ContainsFunc(p.Denies, func(d CurrentAssignment) bool {
				return d.Audience.Kind == "Group" && d.Audience.Issuer == issuer && d.Audience.SubjectID == g && permits(d.Audience.Role, ReadApproved)
			}) {
				owners = append(owners, x)
				until = identity.Earlier(until, a.FreshUntil)
			}
		}
		if len(owners) == n {
			return Result{Reason: "ManagementNotHeld"}, nil
		}
	}
	return Result{Eligible: true, Reason: "Administered", PermissionRevision: p.Revision, ValidUntil: until, ContributingAssignments: owners}, owners
}

// ManagedBy returns the recorded management entries that i holds now: a
// human with evidence:share in a managing group (or the recorded user).
// Holding one makes i a current manager who may list, transfer and revoke.
// The second result bounds the answer's validity.
func (s Share) ManagedBy(i identity.Identity, now time.Time) ([]artifact.AudienceAssignment, time.Time) {
	if !s.Valid() {
		return nil, time.Time{}
	}
	return managedBy(s.Management, i, now)
}

// ManagerDenied reports whether a current Deny on the share target removes
// i's management (Gitar #266): a fresh projection whose deny snapshot names
// i for the sharing role, or a projection that is not current. Creator and
// administrator revocation do not consult it.
func ManagerDenied(p Projection, t Target, i identity.Identity, now time.Time) bool {
	if !projectionCurrent(p, t, now) {
		return true
	}
	for _, d := range p.Denies {
		if !identity.Fresh(d.ObservedAt, d.FreshUntil, now, PermissionObservationInterval) || matches(d.Audience, i) && sharingRole(d.Audience.Role) {
			return true
		}
	}
	return false
}

// PolicySharingManagedBy is ManagedBy for a recurring policy sharing
// instruction (ADR-239).
func PolicySharingManagedBy(management []artifact.AudienceAssignment, i identity.Identity, now time.Time) ([]artifact.AudienceAssignment, time.Time) {
	return managedBy(management, i, now)
}

func managedBy(management []artifact.AudienceAssignment, i identity.Identity, now time.Time) ([]artifact.AudienceAssignment, time.Time) {
	if !i.Valid(now) || i.Principal.Kind != identity.Human || !slices.Contains(i.Scopes, ShareScope) {
		return nil, time.Time{}
	}
	var held []artifact.AudienceAssignment
	for _, a := range management {
		if matches(a, i) {
			held = append(held, a)
		}
	}
	if len(held) == 0 {
		return nil, time.Time{}
	}
	return held, i.ValidUntil
}

// projectionCurrent is the ordinary evaluator's projection precondition.
func projectionCurrent(p Projection, t Target, now time.Time) bool {
	return p.Revision.Valid() && p.Target == t && p.DeniesComplete && identity.Fresh(p.ObservedAt, p.FreshUntil, now, 60*time.Second) &&
		identity.Fresh(p.DeniesObservedAt, p.DeniesFreshUntil, now, PermissionObservationInterval) && rowsValid(p.Allows) && rowsValid(p.Denies)
}

// PolicyShareManagement checks an activating human's authority to attach a
// recurring sharing instruction to a policy (ADR-239): ordinary scope
// eligibility to read the workload's evidence, the evidence:share scope and
// at least one contributing sharing Group assignment of the policy's
// automation AccessBinding for one of its sponsoring groups. Those groups
// manage the instruction.
func PolicyShareManagement(i identity.Identity, p Projection, t Target, delegation string, sponsors []string, now time.Time) (Result, []artifact.AudienceAssignment) {
	if i.Principal.Kind != identity.Human || delegation == "" {
		return Result{Reason: "InvalidRequest"}, nil
	}
	return policyShareOwners(i, ScopeEligibility(i, p, ReadApproved, t, now), delegation, sponsors)
}

// PolicyWorkloadShareManagement applies the same rules to a future-replica
// workload scope.
func PolicyWorkloadShareManagement(i identity.Identity, p WorkloadProjection, t WorkloadTarget, delegation string, sponsors []string, now time.Time) (Result, []artifact.AudienceAssignment) {
	if i.Principal.Kind != identity.Human || delegation == "" {
		return Result{Reason: "InvalidRequest"}, nil
	}
	return policyShareOwners(i, WorkloadScopeEligibility(i, p, ReadApproved, t, now), delegation, sponsors)
}

func policyShareOwners(i identity.Identity, r Result, delegation string, sponsors []string) (Result, []artifact.AudienceAssignment) {
	if !r.Eligible {
		return r, nil
	}
	if !slices.Contains(i.Scopes, ShareScope) {
		return Result{Reason: "InsufficientScope"}, nil
	}
	var owners []artifact.AudienceAssignment
	for _, a := range r.ContributingAssignments {
		if sharingRole(a.Role) && a.Kind == "Group" && a.BasisKind == "AccessBinding" && a.BasisUID == delegation && a.Issuer == i.Principal.Issuer && slices.Contains(sponsors, a.SubjectID) {
			owners = append(owners, a)
		}
	}
	if len(owners) == 0 {
		return Result{Reason: "NoOwnerAuthority"}, nil
	}
	slices.SortFunc(owners, func(a, b artifact.AudienceAssignment) int { return strings.Compare(a.AssignmentID, b.AssignmentID) })
	return r, owners
}
