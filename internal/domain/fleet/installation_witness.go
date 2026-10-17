package fleet

import (
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// DatabaseIncarnation is an observed PostgreSQL process/database identity, not
// proof of durability, first installation, or permission to clear recovery.
type DatabaseIncarnation struct {
	StartedAt     time.Time
	DatabaseOID   uint32
	SchemaVersion int64
}

func (d DatabaseIncarnation) Valid() bool {
	return d.StartedAt.Year() >= 2020 && d.StartedAt.Year() <= 9999 && d.StartedAt.Nanosecond()%1000 == 0 && d.DatabaseOID != 0 && d.SchemaVersion > 0 && d.SchemaVersion <= 1_000_000
}

// InitialActivationClaim is a single immutable attempt. Its original deadline
// survives retries. Consumption never asserts that SQL is pristine or audited.
type InitialActivationClaim struct {
	ID                  string
	Database            DatabaseIncarnation
	FleetSource         identity.Revision
	PlanDigest          artifact.Digest
	NotBefore, NotAfter time.Time
}

func (c InitialActivationClaim) Valid() bool {
	return authorization.UUID(c.ID) && c.Database.Valid() && c.FleetSource.Valid() && c.PlanDigest != (artifact.Digest{}) && c.NotBefore.Year() >= 2020 && c.NotAfter.Year() <= 9999 && c.NotBefore.Nanosecond()%1000 == 0 && c.NotAfter.Nanosecond()%1000 == 0 && !c.Database.StartedAt.After(c.NotBefore) && c.NotAfter.After(c.NotBefore) && !c.NotAfter.After(c.NotBefore.Add(5*time.Minute))
}

func (c InitialActivationClaim) Current(now time.Time) bool {
	return c.Valid() && !now.Before(c.NotBefore) && now.Before(c.NotAfter)
}

// SQL and wire roundtrips discard time-zone/monotonic representation, not instants.
func (c InitialActivationClaim) Same(other InitialActivationClaim) bool {
	return c.ID == other.ID && c.Database.DatabaseOID == other.Database.DatabaseOID && c.Database.SchemaVersion == other.Database.SchemaVersion && c.Database.StartedAt.Equal(other.Database.StartedAt) && c.FleetSource == other.FleetSource && c.PlanDigest == other.PlanDigest && c.NotBefore.Equal(other.NotBefore) && c.NotAfter.Equal(other.NotAfter)
}

// InstallationWitnessScope is private installation input. Missing/replaced
// objects or accounts require recovery; consumers cannot enroll new identities.
type InstallationWitnessScope struct {
	InstallationID, IssuerEpoch, ClusterID string
	Namespace, NamespaceUID, Name, UID     string
	WriterAccount, WriterAccountUID        string
}

func (s InstallationWitnessScope) Valid() bool {
	return authorization.UUID(s.InstallationID) && authorization.UUID(s.IssuerEpoch) && authorization.UUID(s.ClusterID) && identity.Text(s.Namespace, 63) && authorization.UUID(s.NamespaceUID) && identity.Text(s.Name, 253) && authorization.UUID(s.UID) && identity.Text(s.WriterAccount, 63) && authorization.UUID(s.WriterAccountUID)
}

func (s InstallationWitnessScope) WriterUsername() string {
	return "system:serviceaccount:" + s.Namespace + ":" + s.WriterAccount
}

// An observation of permanent consumption is not an activation authorization.
// Expired claims remain observable for recovery diagnostics but cannot be used
// for a new SQL activation. There is no reset, delete, or refund transition.
type InstallationWitness struct {
	Scope                  InstallationWitnessScope
	Claim                  *InitialActivationClaim
	ResourceVersion        string
	ObservedAt, FreshUntil time.Time
}

func (w InstallationWitness) Valid(now time.Time) bool {
	return w.Scope.Valid() && identity.Text(w.ResourceVersion, 128) && (w.Claim == nil || w.Claim.Valid()) && identity.Fresh(w.ObservedAt, w.FreshUntil, now, 5*time.Second)
}
