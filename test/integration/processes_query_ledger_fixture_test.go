package integration

import (
	"asservat.local/asservat/migrations"
	"context"
	"crypto/tls"
	"encoding/json"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/fleet"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Real protected admission/publication, original audience and compiled query/key
// roles; the process inventory, node/Job/issuer and transport join are synthetic.
func TestProcessesQueryLifecycleWithRealServices(t *testing.T) {
	withCapacityProducerFixture(t, func(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope fleet.InstallationWitnessScope, claim string, administration fleet.Administration, objects *objectstore.AuthorityObjects) {
		withProtectedContextQueryLedger(t, ctx, admin, address, tlsConfig, scope, claim, administration, objects, qualifyProcessesQueryLifecycle, false, false, false, false, false, false, false, false, true)
	})
}
func processesQueryComposition() planvalue.ProfileComposition {
	return planvalue.ProfileComposition{Components: []planvalue.ProfileComponent{{ID: "saved", Profile: planvalue.ProfileRef{Catalog: "builtin", Name: "inspect-processes", Version: "v1"}, Edits: []planvalue.ProfileEdit{{ActionID: "processes", Field: "actionMaxBytes", Number: artifact.ProcessNativeLimit}}}}, MaxTotalBytes: artifact.ProcessNativeLimit, MaxDuration: "10s"}
}
func processesQuerySyntheticNative(t *testing.T, e artifact.ContextExpectation, from, until time.Time) []byte {
	t.Helper()
	inventory := artifact.ProcessInventory{Format: artifact.ProcessFormat, PodUID: e.PodUID, NodeUID: custodyID(), NodeBootID: custodyID(), Mode: e.Processes.Mode, StartedAt: from, CompletedAt: until, Origins: []artifact.ProcessOrigin{}, Processes: []artifact.ProcessRecord{}, Gaps: []string{"sourceUnavailable"}}
	if !inventory.Valid() {
		t.Fatal("synthetic process inventory invalid")
	}
	out, err := json.Marshal(inventory)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func qualifyProcessesQueryLifecycle(t *testing.T, f *queryLedgerFixture) {
	t.Helper()
	ctx, s := f.base.ctx, f.scenario
	f.refresh(t)
	routes, err := postgres.NewContextCaseReads(ctx, f.base.roles["hub-runtime"], s.a.RootID, s.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	n := time.Now().UTC()
	who := s.a.Eligibility.VerifiedIdentity
	who.VerifiedAt, who.ValidUntil = n, n.Add(5*time.Second)
	who.Scopes = []string{"evidence:read"}
	proof, err := s.recovery.reader.RecoveryState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	e := f.published.Expectation
	candidate, err := routes.ResolveTargetDiscoveryRoute(ctx, e.CaptureUID, who, proof)
	if err != nil || candidate.CaptureID != e.CaptureUID || candidate.ArtifactID != e.Registration.Location.ArtifactID || candidate.CaseID != e.CaseID || candidate.NativeType != artifact.ProcessesArtifact {
		t.Fatal("exact published process capture route", err)
	}
	if _, err = routes.ResolveTargetDiscoveryRoute(ctx, custodyID(), who, proof); err == nil {
		t.Fatal("unrelated capture routed")
	}
	// Exercise the same real one-batch/three-key-role/closure lifecycle as other
	// approved metadata, with a read-only current maintainer and exact source.
	qualifySharedProjectionLifecycle(t, f)
	refuseRetainedProcessesDowngrade(t, f)
}

func refuseRetainedProcessesDowngrade(t *testing.T, f *queryLedgerFixture) {
	t.Helper()
	db := stdlib.OpenDB(*f.base.admin.Config().ConnConfig)
	defer db.Close()
	p, err := goose.NewProvider(goose.DialectPostgres, db, migrations.Files(), goose.WithDisableGlobalRegistry(true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.DownTo(f.base.ctx, 141); err == nil || !strings.Contains(err.Error(), "retained process snapshots require schema 142") {
		t.Fatal("retained process source/query/audit rollback fence", err)
	}
	head, err := p.GetDBVersion(f.base.ctx)
	if err != nil || head != 142 {
		t.Fatal("failed rollback changed schema", head, err)
	}
	t.Log("retained process capture/query/audit refuses142Down141 without erasing logical spend")
}
