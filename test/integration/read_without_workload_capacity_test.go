package integration

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/application/evidence"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Maintainer decision (2026-10-23, migration 00076): reading stored evidence
// does not depend on the source workload's live capacity observation. After
// the workload's binding observation has expired, as after its deletion,
// capture admission for it is refused while native download preparation and
// the complete approved query flow (admission, worker batch claim, polls and
// its finite accounting) still succeed for the already published context.
func TestEvidenceReadsWithoutWorkloadCapacityWithRealPostgres(t *testing.T) {
	withCapacityProducerFixture(t, func(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope fleet.InstallationWitnessScope, claim string, administration fleet.Administration, objects *objectstore.AuthorityObjects) {
		withProtectedContextQueryLedger(t, ctx, admin, address, tlsConfig, scope, claim, administration, objects, func(t *testing.T, f *queryLedgerFixture) {
			f.expireWorkloadObservation(t)
			f.downloadWithoutWorkloadObservation(t)
			qualifyContextQueries(t, f)
			f.base.assertAdmission(t, 0, f.enrolled, false)
		})
	})
}

// expireWorkloadObservation stops refreshing the workload and moves its last
// binding observation one hour into the past. The capacity_workload row is
// retained (its guard forbids deletion), as for a deleted workload.
func (f *queryLedgerFixture) expireWorkloadObservation(t *testing.T) {
	t.Helper()
	f.workloadGone = true
	b := f.base
	tx, err := b.admin.Begin(b.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(b.ctx, "SET LOCAL session_replication_role=replica"); err != nil {
		t.Fatal(err)
	}
	// One timestamp for both bounds: two clock_timestamp() calls differ and can
	// exceed the table's exact 30-second CHECK (observed in a fixture run).
	tag, err := tx.Exec(b.ctx, `UPDATE context_storage_binding SET observed_at=statement_timestamp()-interval '1 hour',fresh_until=statement_timestamp()-interval '1 hour'+interval '30 seconds' WHERE root_id=$1 AND allocation_id=$2`, b.input.PermissionRootID, f.enrolled.AllocationID)
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatal("expire workload binding", err)
	}
	if err = tx.Commit(b.ctx); err != nil {
		t.Fatal(err)
	}
	// Collection for this workload is refused: legacy custody registration,
	// the storage reader and managed admission of both allocation kinds.
	b.assertAdmission(t, 0, f.enrolled, false)
}

func (f *queryLedgerFixture) downloadWithoutWorkloadObservation(t *testing.T) {
	t.Helper()
	b, s, e := f.base, f.scenario, f.published.Expectation
	var pools []*pgxpool.Pool
	defer func() {
		for _, p := range pools {
			p.Close()
		}
	}()
	pool := func(role, password string) *pgxpool.Pool {
		p := b.fixturePool(role, password)
		pools = append(pools, p)
		return p
	}
	catalogPool := pool("context_catalog_read_runtime", "synthetic-context-read")
	catalog, err := postgres.NewContextPublications(b.ctx, catalogPool, s.a.RootID)
	if err != nil {
		t.Fatal(err)
	}
	processing, err := postgres.NewProcessingReads(b.ctx, catalogPool, s.a.RootID, s.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	actor := s.a.Eligibility.VerifiedIdentity
	actor.Scopes = []string{"evidence:read", "evidence:download"}
	gate := authapp.ContextDownloadAuthority{RootID: s.a.RootID, Identities: nativeDownloadTestIdentity{value: actor, expires: time.Now().Add(2 * time.Minute)}, Permissions: s.p, Catalog: catalog, Retention: privacyapp.RetentionResolver{RetainedPolicies: s.retention, Now: time.Now}, Environment: authapp.CurrentDownloadEnvironment{RootID: s.a.RootID, InstallationID: b.input.InstallationID, Policies: processingTestPolicy{value: b.processingPolicy}, Recovery: s.recovery.reader, Processing: processing, Now: time.Now}, Now: time.Now}
	scope := artifact.DownloadScope{RootID: s.a.RootID, ArtifactID: e.Registration.Location.ArtifactID, CaptureID: e.CaptureUID, ClusterID: e.Registration.Location.ClusterID, NamespaceUID: e.NamespaceUID, WorkloadUID: e.WorkloadUID, PodUID: e.PodUID, Version: evidence.ContextCopiesDigest(f.published.Copies), Principal: actor.Principal}
	authority, err := gate.CheckDownload(b.ctx, "synthetic-reference", scope)
	if err != nil {
		t.Fatal("download authority without workload observation", err)
	}
	downloads, err := postgres.NewDownloads(b.ctx, pool("download_runtime", "synthetic-download"), s.a.RootID, postgres.EffectTransactionGuards{Retention: s.retention.guard, Recovery: s.recovery.guard})
	if err != nil {
		t.Fatal(err)
	}
	n := time.Now().UTC().Truncate(time.Microsecond)
	original := capacityNativeSession(scope, f.enrolled.DownloadAllocationID, custodyID(), n, identity.Earlier(f.root.PlannedUntil, authority.AccessUntil))
	session, err := downloads.ReserveDownload(b.ctx, evidence.DownloadReservation{Session: original, IdempotencyDigest: artifact.Digest{28}, Authority: authority})
	if err != nil {
		t.Fatal("download preparation without workload observation", err)
	}
	if _, err = downloads.BeginDownloadBatch(b.ctx, session.ID, authority, artifact.DownloadBatch{ID: custodyID(), Purpose: artifact.DownloadMetadata, ReadBytes: 4 << 20}); err != nil {
		t.Fatal("download charge without workload observation", err)
	}
	var managed bool
	if err = b.admin.QueryRow(b.ctx, `SELECT capacity_account_id=$2 AND capacity_backing IS NOT NULL AND octet_length(capacity_backing_digest)=32 FROM artifact_download WHERE id=$1`, session.ID, f.enrolled.ID).Scan(&managed); err != nil || !managed {
		t.Fatal("session lacks its original managed snapshot", err)
	}
	// The workload stayed unobserved throughout; reading did not refresh it.
	var stale bool
	if err = b.admin.QueryRow(b.ctx, `SELECT clock_timestamp()>=fresh_until FROM context_storage_binding WHERE root_id=$1 AND allocation_id=$2`, b.input.PermissionRootID, f.enrolled.AllocationID).Scan(&stale); err != nil || !stale {
		t.Fatal("workload observation was renewed", err)
	}
}
