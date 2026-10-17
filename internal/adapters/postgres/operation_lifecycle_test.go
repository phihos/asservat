package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"github.com/jackc/pgx/v5/pgtype"
	"testing"
	"time"
)

func TestOperationLifecycleCannotTreatCurrentRestartActivationAsHistoricalReconciliation(t *testing.T) {
	installation := "00000000-0000-4000-8000-000000000001"
	epoch := id("00000000-0000-4000-8000-000000000002")
	old := time.Date(2026, 10, 11, 10, 0, 0, 0, time.UTC)
	d := custodydb.OperationAuditLifecycle{InstallationID: id(installation), IssuerEpoch: epoch, PostmasterAt: ts(old), DatabaseOid: pgtype.Uint32{Uint32: 1234, Valid: true}}
	trust := custodydb.FleetCurrentTrust{IssuerEpoch: epoch}
	current := custodydb.ReadContextDatabaseIncarnationRow{PostmasterAt: ts(old), DatabaseOid: d.DatabaseOid}
	if !operationLifecycleIncarnation(d, trust, current, installation) {
		t.Fatal("same immutable incarnation denied")
	}
	current.PostmasterAt = ts(old.Add(time.Minute))
	if operationLifecycleIncarnation(d, trust, current, installation) {
		t.Fatal("ordinary post-restart activation remapped historical closure")
	}
	current.PostmasterAt = ts(old)
	current.DatabaseOid.Uint32++
	if operationLifecycleIncarnation(d, trust, current, installation) {
		t.Fatal("database replacement accepted historical completion")
	}
	current.DatabaseOid = d.DatabaseOid
	trust.IssuerEpoch = id("00000000-0000-4000-8000-000000000003")
	if operationLifecycleIncarnation(d, trust, current, installation) {
		t.Fatal("new issuer accepted old completion")
	}
}
