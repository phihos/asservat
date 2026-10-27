package capture

import (
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// ADR-239 (S-06 increment 8): bounded recurring-policy sharing. A DebugPolicy
// may name recipients of its future captures together with a capture limit
// and an absolute end. There is no SharingIntent record: the policy
// acceptance carries one immutable instruction and a counter, each admitted
// occurrence capture consumes one slot and copies the ADR-235 capture
// instruction, and publication materializes one ordinary share.
const (
	// PolicyShareMaxCaptures bounds the captures one acceptance may share
	// (REQ-SHR-005: maxCaptures 1–100).
	PolicyShareMaxCaptures = 100
	// PolicySharingStatement is the fixed review text of an activation that
	// shares (REQ-SHR-005: preview/review must say so).
	PolicySharingStatement = "Repeated collections will be shared"
)

// PolicySharing is a compiled DebugPolicy spec.sharing block: shape only.
// Time and authority are checked at activation, never by the compiler, so
// polling an accepted policy never fails because its end has passed.
type PolicySharing struct {
	Recipients  []authorization.ShareRecipient
	MaxCaptures int
	NotAfter    time.Time
}

// Valid checks 1..8 distinct recipients of one issuer, 1..100 captures and a
// second-precision end.
func (s PolicySharing) Valid() bool {
	if len(s.Recipients) < 1 || len(s.Recipients) > authorization.ShareMaxRecipients || s.MaxCaptures < 1 || s.MaxCaptures > PolicyShareMaxCaptures || s.NotAfter.IsZero() || s.NotAfter.Year() > 9999 {
		return false
	}
	seen := map[string]bool{}
	for _, r := range s.Recipients {
		if !r.Valid() || r.Issuer != s.Recipients[0].Issuer || seen[r.Key()] {
			return false
		}
		seen[r.Key()] = true
	}
	return true
}

// PolicyShareInstruction is the accepted sharing decision, stored in the
// immutable acceptance record (and so in its encrypted audit). Creator is the
// activating human; Management is the policy's owner teams: the automation
// binding's current evidence-owner Group assignments of the sponsoring groups.
type PolicyShareInstruction struct {
	Creator     identity.Principal
	Management  []artifact.AudienceAssignment
	Recipients  []authorization.ShareRecipient
	MaxCaptures int
	NotAfter    time.Time
}

func (s PolicyShareInstruction) Valid() bool {
	if !s.Creator.Valid() || s.Creator.Kind != identity.Human || len(s.Management) < 1 || len(s.Management) > authorization.ShareMaxManagers || !(PolicySharing{Recipients: s.Recipients, MaxCaptures: s.MaxCaptures, NotAfter: s.NotAfter}).Valid() || s.Recipients[0].Issuer != s.Creator.Issuer {
		return false
	}
	for i, a := range s.Management {
		if a.Role != "evidence-owner" || a.Kind != "Group" || !authorization.UUID(a.AssignmentID) || i > 0 && s.Management[i-1].AssignmentID >= a.AssignmentID {
			return false
		}
	}
	return true
}

// Policy sharing states reported by get_policy_status. Only revocation is
// stored; the others are derived from the counter, the end and the source.
const (
	PolicySharingActive       = "active"
	PolicySharingLimitReached = "limitReached"
	PolicySharingExpired      = "expired"
	PolicySharingRevoked      = "revoked"
	// PolicySharingStopped: the DebugPolicy changed after acceptance (a new
	// generation), which stops sharing until a new revision is activated.
	PolicySharingStopped = "stopped"
)

// PolicySharingStatus is the content-free sharing projection of one
// acceptance.
type PolicySharingStatus struct {
	Instruction PolicyShareInstruction
	Spent       int64
	RevokedAt   time.Time
}

// State derives the sharing state at now for a policy observed at generation.
func (s PolicySharingStatus) State(now time.Time, accepted, observed int64) string {
	switch {
	case !s.RevokedAt.IsZero():
		return PolicySharingRevoked
	case observed != accepted:
		return PolicySharingStopped
	case !now.Before(s.Instruction.NotAfter):
		return PolicySharingExpired
	case s.Spent >= int64(s.Instruction.MaxCaptures):
		return PolicySharingLimitReached
	}
	return PolicySharingActive
}
