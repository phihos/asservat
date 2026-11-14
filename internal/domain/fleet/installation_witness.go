package fleet

import (
	"time"

	"asservat.local/asservat/internal/domain/artifact"
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

// InstallationWitnessScope is private installation input. Missing/replaced
// objects or accounts require recovery; consumers cannot enroll new identities.
type InstallationWitnessScope struct {
	InstallationID, IssuerEpoch, ClusterID string
	Namespace, NamespaceUID, Name, UID     string
	WriterAccount, WriterAccountUID        string
}
