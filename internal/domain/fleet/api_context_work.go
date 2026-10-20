package fleet

import (
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// APIContextExecutor is the exact regional process selected by protected startup.
// It carries no node authority and cannot be selected by a public capture caller.
// Its epoch remains distinct from the independently enrolled connector process.
type APIContextExecutor struct {
	NamespaceUID, AccountUID, PodUID, ProcessEpoch string
	StartupDigest, ImageDigest                     artifact.Digest
}

func (p APIContextExecutor) Valid() bool {
	for _, id := range []string{p.NamespaceUID, p.AccountUID, p.PodUID, p.ProcessEpoch} {
		if !authorization.UUID(id) {
			return false
		}
	}
	return p.StartupDigest != (artifact.Digest{}) && p.ImageDigest != (artifact.Digest{})
}

// APIContextChannel binds one live conversation, not a durable dispatch lease.
// Both peer bindings come from actual TLS and current accepted registry reads.
type APIContextChannel struct {
	RootID, ExchangeID, Challenge string
	Hub                           OwnerBinding
	Connector                     ConnectorProcessIdentity
	ConnectorLeaf                 artifact.Digest
	Executor                      APIContextExecutor
}

func (c APIContextChannel) Valid() bool {
	return authorization.UUID(c.RootID) && authorization.UUID(c.ExchangeID) && authorization.UUID(c.Challenge) && c.Hub.Valid() && c.Connector.Valid() && c.ConnectorLeaf != (artifact.Digest{}) && c.Executor.Valid() && c.Hub.InstallationID == c.Connector.Binding.InstallationID && c.Hub.IssuerEpoch == c.Connector.Binding.IssuerEpoch && c.Executor.PodUID == c.Connector.PodUID && c.Executor.ProcessEpoch != c.Connector.ProcessEpoch
}

type APIContextReceiver struct {
	Channel                APIContextChannel
	ObservedAt, ValidUntil time.Time
}

func (r APIContextReceiver) Valid(now time.Time) bool {
	return r.Channel.Valid() && identity.Fresh(r.ObservedAt, r.ValidUntil, now, 5*time.Second)
}

// APIContextWork is a signed reference to one accepted API profile. Human groups
// and scopes never enter this value. Signature validity is not effect authority.
// The receiver separately resolves every digest against accepted SQL/local facts.
type APIContextWork struct {
	Channel                                                    APIContextChannel
	CaptureID, AttemptID                                       string
	Actor                                                      identity.Principal
	Target                                                     authorization.Target
	ScopeDigest, ExpectationDigest, IntentDigest, BudgetDigest artifact.Digest
	Capability                                                 identity.Revision
	ProjectionDigest                                           artifact.Digest
	IssuedAt, NotAfter                                         time.Time
}

func (w APIContextWork) Valid(now time.Time) bool {
	if !w.Channel.Valid() || !authorization.UUID(w.CaptureID) || !authorization.UUID(w.AttemptID) || !w.Actor.Valid() || w.Actor.Kind != identity.Human || !w.Target.Valid() || w.Target.ClusterID != w.Channel.Connector.Binding.ClusterID || !w.Capability.Valid() || !identity.Fresh(w.IssuedAt, w.NotAfter, now, 5*time.Second) {
		return false
	}
	for _, d := range []artifact.Digest{w.ScopeDigest, w.ExpectationDigest, w.IntentDigest, w.BudgetDigest, w.ProjectionDigest} {
		if d == (artifact.Digest{}) {
			return false
		}
	}
	for _, t := range []time.Time{w.IssuedAt, w.NotAfter} {
		if t.Location() != time.UTC || t.Nanosecond()%1000 != 0 {
			return false
		}
	}
	return true
}
func (w APIContextWork) Matches(r APIContextReceiver, now time.Time) bool {
	return r.Valid(now) && w.Valid(now) && w.Channel == r.Channel
}

// MismatchStep names the first failed Matches condition, for diagnostics.
func (w APIContextWork) MismatchStep(r APIContextReceiver, now time.Time) string {
	switch {
	case !r.Valid(now):
		return "receiver"
	case !w.Valid(now) && !now.Before(w.NotAfter):
		return "expired"
	case !w.Valid(now):
		return "work"
	case w.Channel != r.Channel:
		return "channel"
	}
	return "none"
}

type APIContextWorkTrust struct {
	RootID, InstallationID, ClusterID, IssuerEpoch string
	Trust                                          WorkTrust
}

func (t APIContextWorkTrust) Valid(now time.Time) bool {
	for _, id := range []string{t.RootID, t.InstallationID, t.ClusterID, t.IssuerEpoch} {
		if !authorization.UUID(id) {
			return false
		}
	}
	if !t.Trust.Valid(now) || t.Trust.FreshUntil.After(t.Trust.ObservedAt.Add(5*time.Second)) {
		return false
	}
	for _, k := range t.Trust.Keys {
		if k.ClusterID != t.ClusterID || k.IssuerEpoch != t.IssuerEpoch {
			return false
		}
	}
	return true
}
func (t APIContextWorkTrust) Matches(w APIContextWork) bool {
	return t.RootID == w.Channel.RootID && t.InstallationID == w.Channel.Connector.Binding.InstallationID && t.ClusterID == w.Target.ClusterID && t.IssuerEpoch == w.Channel.Connector.Binding.IssuerEpoch
}

type AuthenticatedAPIContextWork struct {
	Work                   APIContextWork
	KeyID                  string
	TrustRevision          identity.Revision
	VerifiedAt, ValidUntil time.Time
}

func (w AuthenticatedAPIContextWork) Valid(now time.Time) bool {
	return w.Work.Valid(now) && identity.Text(w.KeyID, 128) && w.TrustRevision.Valid() && identity.Fresh(w.VerifiedAt, w.ValidUntil, now, 5*time.Second) && !w.ValidUntil.After(w.Work.NotAfter)
}

// APIContextOwnerCandidates is a complete bounded discovery observation. Empty
// means no current candidate; none of its values supplies an address or permit.
type APIContextOwnerCandidates struct {
	Pool                   OwnerPool
	Owners                 []OwnerBinding
	ObservedAt, ValidUntil time.Time
}

func (o APIContextOwnerCandidates) Valid(now time.Time) bool {
	// This value cannot establish that its reader returned a complete set.
	// Legacy context-start discovery retains its own explicit >16 rejection;
	// the opted observation reader must independently reject limit+1 overflow.
	maximum := 16
	if o.Pool.NativeCandidateLimit != 0 {
		maximum = o.Pool.NativeCandidateLimit
	}
	if !o.Pool.Valid() || o.Pool.NativePort == 0 || len(o.Owners) > maximum || !identity.Fresh(o.ObservedAt, o.ValidUntil, now, 5*time.Second) {
		return false
	}
	seen := make(map[OwnerBinding]bool, len(o.Owners))
	for _, b := range o.Owners {
		if !b.Valid() || b.InstallationID != o.Pool.InstallationID || b.ClusterID != o.Pool.ClusterID || b.IssuerEpoch != o.Pool.IssuerEpoch {
			return false
		}
		if seen[b] {
			return false
		}
		seen[b] = true
	}
	return true
}
