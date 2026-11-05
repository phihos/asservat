package integration

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/fleet"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Each test owns its pristine protected root and actual compiled hub role.
// SQL/S3 publication, native-key use, outcome and close are real; Job/Pod,
// issuer and positive transport/termination proofs remain supplied test inputs.
func TestProjectionSingleBatchEarlyCleanupWithRealServices(t *testing.T) {
	projectionEarlyCleanupWithRealServices(t, true)
}
func TestProjectionTwoBatchCleanupStaysChargedWithRealServices(t *testing.T) {
	projectionEarlyCleanupWithRealServices(t, false)
}
func projectionEarlyCleanupWithRealServices(t *testing.T, single bool) {
	withCapacityProducerFixture(t, func(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope fleet.InstallationWitnessScope, claim string, administration fleet.Administration, objects *objectstore.AuthorityObjects) {
		withProtectedContextQueryLedger(t, ctx, admin, address, tlsConfig, scope, claim, administration, objects, func(t *testing.T, f *queryLedgerFixture) {
			qualifySharedProjectionLifecycleClient(t, f, "", 0, func(stage string, f *queryLedgerFixture, workers *postgres.ProjectionWorkers, q query.ContextQuery, w value.AcquisitionWorker) {
				if !time.Now().Before(w.Intent.RunUntil) || (q.Scope.ReadBatches() == 1) != single {
					t.Fatal("early cleanup fixture lacks original headroom/scope", stage, q.Scope.ReadBatches())
				}
				ctx := f.base.ctx
				now := time.Now().UTC().Truncate(time.Microsecond)
				proof := value.AcquisitionWorkerTermination{Worker: w, TerminationDigest: artifact.Digest{73}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
				rows, err := workers.ExpiredProjectionWorkers(ctx)
				if err != nil {
					t.Fatal("compiled cleanup candidates", stage, err)
				}
				eligible := stage == "joined" && single
				if !eligible {
					if len(rows) != 0 {
						t.Fatal("unfinished or multi-batch worker selected early", stage, len(rows))
					}
					if _, err := workers.ConfirmProjectionTermination(ctx, proof); err == nil {
						t.Fatal("unfinished or multi-batch proof retired early", stage)
					}
					return
				}
				if len(rows) != 1 || rows[0].State.Worker != w || !rows[0].State.Intent.Query.Equal(q) {
					t.Fatal("completed single batch not selected early", len(rows), stage)
				}
				var before string
				snapshot := func() string {
					t.Helper()
					var s string
					if err := f.base.admin.QueryRow(ctx, `SELECT jsonb_build_array((SELECT allocated FROM context_query_backing WHERE root_id=$1),(SELECT coalesce(sum(allocated),0) FROM context_query_principal WHERE root_id=$1),(SELECT count(*) FROM context_query WHERE root_id=$1),(SELECT count(*) FROM context_query_batch b JOIN context_query q ON q.id=b.query_id WHERE q.root_id=$1),(SELECT coalesce(sum(used_roles),0) FROM context_query_key_binding k JOIN context_query q ON q.id=k.query_id WHERE q.root_id=$1))::text`, q.Scope.RootID).Scan(&s); err != nil {
						t.Fatal("logical spend snapshot", err)
					}
					return s
				}
				before = snapshot()
				wrong := proof
				wrong.Worker.Binding.PodUID = "replacement"
				if _, err := workers.ConfirmProjectionTermination(ctx, wrong); err == nil {
					t.Fatal("replacement positive proof accepted")
				}
				accepted, err := workers.ConfirmProjectionTermination(ctx, proof)
				if err != nil || accepted != proof {
					t.Fatal("exact early positive proof refused", err)
				}
				var active int
				count := func() int {
					t.Helper()
					if err := f.base.admin.QueryRow(ctx, `SELECT count(*) FROM download_worker WHERE root_id=$1 AND retired_proof_json IS NULL AND abandoned_at IS NULL`, q.Scope.RootID).Scan(&active); err != nil {
						t.Fatal(err)
					}
					return active
				}
				if count() != 1 {
					t.Fatal("termination alone released physical capacity")
				}
				// The following positive UID-delete/absence input is synthetic. Real API
				// termination and deletion checks are covered separately; no absence is
				// inferred from this database fixture or the original RunUntil.
				retired := value.AcquisitionWorkerRetirement{Termination: accepted, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
				if err := workers.RetireProjectionWorker(ctx, retired); err != nil {
					t.Fatal("persist exact retirement", err)
				}
				if count() != 0 || snapshot() != before {
					t.Fatal("retirement failed physical release or refunded logical spend")
				}
				var stored []byte
				if err := f.base.admin.QueryRow(ctx, `SELECT intent_json FROM download_worker WHERE id=$1`, w.Intent.ID).Scan(&stored); err != nil {
					t.Fatal(err)
				}
				var original query.ContextProjectionWorkerIntent
				if json.Unmarshal(stored, &original) != nil || original.Worker != w.Intent || !original.Query.Equal(q) {
					t.Fatal("early cleanup changed original worker/query deadlines")
				}
				// Reuse the complete production-role admission/enrollment/native-key
				// lifecycle for a successor, with the same original backing/source.
				// This is actual admission after retirement, not a count-only claim.
				qualifySharedProjectionLifecycleClient(t, f, "", 1)
				if !time.Now().Before(w.Intent.RunUntil) || count() != 1 {
					t.Fatal("successor admission waited for old maximum or changed capacity")
				}
				t.Log("compiled early cleanup: exact single joined batch selected, positive termination retained capacity until exact retirement; original worker/query deadlines and logical spend unchanged; Job/Pod/transport proofs synthetic")
			})
		}, false, false, false, single)
	})
}
