package privacy

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"time"
)

// ProcessingAuthority is request-owned current authority, never a stored
// operator/group grant. The SQL adapter checks it again after every lock wait.
type ProcessingAuthority struct {
	Identity               identity.Identity
	Policy                 DownloadPolicy
	Recovery               artifact.RecoveryProof
	ObservedAt, ValidUntil time.Time
}

func (a ProcessingAuthority) Valid(now time.Time) bool {
	return a.Identity.Valid(now) && a.Policy.Valid(now) && a.Policy.Operator(a.Identity, now) && a.Recovery.Valid(now) && a.Policy.InstallationID == a.Recovery.InstallationID && a.Policy.RecoveryEpoch == a.Recovery.IssuerEpoch && identity.Fresh(a.ObservedAt, a.ValidUntil, now, 5*time.Second) && !a.ValidUntil.After(a.Identity.ValidUntil) && !a.ValidUntil.After(a.Policy.FreshUntil) && !a.ValidUntil.After(a.Recovery.FreshUntil)
}

// ProcessingChange is an explicit private administrator request. Rule scope
// never comes from evidence values submitted by an ordinary reader. An exact
// release names the previous restrictive revision; normal grants are unrelated.
type ProcessingChange struct {
	RequestID, RuleID string
	Action            string
	ExpectedRevision  int64
	Scope             ProcessingScope
}

func (c ProcessingChange) Valid() bool {
	if !authorization.UUID(c.RequestID) {
		return false
	}
	switch c.Action {
	case "initialize_processing":
		return c.RuleID == "" && c.ExpectedRevision == 0 && c.Scope == (ProcessingScope{})
	case "restrict_processing":
		return authorization.UUID(c.RuleID) && c.ExpectedRevision >= 0 && c.ExpectedRevision < MaxProcessingChanges-1 && c.ExpectedRevision%2 == 0 && c.Scope.Valid()
	case "release_processing":
		return authorization.UUID(c.RuleID) && c.ExpectedRevision > 0 && c.ExpectedRevision < MaxProcessingChanges && c.ExpectedRevision%2 == 1 && c.Scope.Valid()
	}
	return false
}

type ProcessingReceipt struct {
	RootID, Epoch, RequestID, RuleID, OperationID, State string
	Revision, Sequence                                   int64
	ObservedAt, ValidUntil                               time.Time
}

func (r ProcessingReceipt) Valid(now time.Time) bool {
	if !authorization.UUID(r.RootID) || !authorization.UUID(r.Epoch) || !authorization.UUID(r.RequestID) || !authorization.UUID(r.OperationID) || r.Sequence < 1 || !identity.Fresh(r.ObservedAt, r.ValidUntil, now, 5*time.Second) {
		return false
	}
	if r.State == "initialized" {
		return r.RuleID == "" && r.Revision == 0
	}
	return authorization.UUID(r.RuleID) && r.Revision > 0 && r.Revision <= MaxProcessingChanges && (r.State == "restricted" && r.Revision%2 == 1 || r.State == "released" && r.Revision%2 == 0)
}
