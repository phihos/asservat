package authorization

import (
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

// PolicyGrantAttachment is immutable semantic/idempotency state of one explicit
// activate_policy control. It is not durable object audit or independently
// issued authority. The original grant/acceptance, expiry and spend remain.
type PolicyGrantAttachment struct {
	ID, RootID, InstallationID, PolicyUID, AcceptanceID, GrantID string
	AuthorityDigest                                              artifact.Digest
	AuthoredGrantRef                                             string
	Actor                                                        identity.Principal
	AttachedAt                                                   time.Time
}

func (a PolicyGrantAttachment) Valid() bool {
	return UUID(a.ID) && UUID(a.RootID) && UUID(a.InstallationID) && identity.Text(a.PolicyUID, 64) && UUID(a.AcceptanceID) && UUID(a.GrantID) && a.AuthorityDigest != (artifact.Digest{}) && (a.AuthoredGrantRef == "" || a.AuthoredGrantRef == a.GrantID) && a.Actor.Valid() && a.Actor.Kind == identity.Human && !a.AttachedAt.IsZero()
}

// Matches controls only whether this original pointer may be reused. The SQL
// grant and current policy/delegation checks still authorize every effect.
// A changed authored grantRef stops reuse without modifying collection scope.
func (a PolicyGrantAttachment) Matches(root, acceptance string, p AcceptedPolicyAuthority, authored string) bool {
	return a.Valid() && a.RootID == root && a.InstallationID == p.InstallationID && a.PolicyUID == p.PolicyUID && a.AcceptanceID == acceptance && a.AuthorityDigest == p.ScopeDigest && a.AuthoredGrantRef == authored && (authored == "" || authored == a.GrantID)
}

func CheckPolicyGrantAttachment(g Grant, p AcceptedPolicyAuthority, authored string, now time.Time) error {
	if authored != "" && authored != g.ID {
		return ErrGrantScope
	}
	return CheckPolicyGrantCurrent(g, p, WorkloadTarget{p.ClusterID, p.NamespaceUID, p.WorkloadUID}, now)
}
