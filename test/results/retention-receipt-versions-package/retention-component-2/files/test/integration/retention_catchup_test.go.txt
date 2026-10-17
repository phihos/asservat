package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/jose"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/application/planning"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/privacy"
	"github.com/jackc/pgx/v5/pgxpool"
)

func qualifyRetentionCatchup(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, create func(*testing.T, int64) captureAdmissionScenario) {
	runtime := poolFor("retention_catchup_runtime", "synthetic-retention-catchup")
	defer runtime.Close()
	sourcePool := poolFor("retention_source_runtime", "synthetic-retention-source")
	defer sourcePool.Close()
	for _, q := range []string{"UPDATE retention_source SET recovery_blocked=false", "UPDATE retention_source SET suspended=false", "UPDATE retention_checkpoint SET audit_acknowledged_at=clock_timestamp()", "UPDATE retention_decision SET audit_acknowledged_at=clock_timestamp()", "UPDATE custody_attempt SET expires_at=expires_at", "DELETE FROM retention_catchup"} {
		if _, err := runtime.Exec(ctx, q); err == nil {
			t.Fatal("catch-up role exceeds purpose", q)
		}
	}
	qualifyRetentionAdmissionReceiptHistory(t, ctx, admin, create)
	t.Run("retention-catchup-pages-apply-lowering-before-raising", func(t *testing.T) {
		s := create(t, 3)
		locations := []artifact.Location{}
		for i := 0; i < 3; i++ {
			a := s.a
			a.IdempotencyKey = custodyID()
			a.SubmissionDigest[1] = byte(i)
			input := a.Plan.Input
			input.CaptureID = custodyID()
			var err error
			a.Plan, err = planning.CompileContext(input, time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			a.Registration.Location.ArtifactID = custodyID()
			a.Registration.Location.AttemptID = custodyID()
			accepted, err := s.s.AdmitContext(ctx, a)
			if err != nil {
				t.Fatal(err)
			}
			locations = append(locations, accepted.Expectation.Registration.Location)
		}
		worker, err := postgres.NewRetention(ctx, runtime, s.a.RootID)
		if err != nil {
			t.Fatal(err)
		}
		sources, err := postgres.NewRetentionSources(ctx, sourcePool, s.a.RootID)
		if err != nil {
			t.Fatal(err)
		}
		ref := s.retention.fence.Source
		start := app.RetentionStart{Fence: s.retention.fence}
		checkpoint := s.retention.checkpoint
		policy := checkpoint.Transition.List.Snapshot.Policies[0]
		var now time.Time

		apply := func(e app.PolicyEvent) {
			t.Helper()
			j, err := app.ResumeRetentionJournal(checkpoint.Transition.List)
			if err != nil {
				t.Fatal(err)
			}
			if err = j.Apply(e); err != nil {
				t.Fatal(err)
			}
			next, err := j.HistoricalCheckpoint()
			if err != nil {
				t.Fatal(err)
			}
			f := start.Fence
			f.Sequence = checkpoint.Record.Sequence
			checkpoint, err = sources.AcceptRetention(ctx, app.RetentionTransition{ID: custodyID(), Fence: f, List: next, Event: &e})
			if err != nil {
				t.Fatal(err)
			}
		}
		// A metadata update queues one complete pass after the artifacts exist.
		apply(app.PolicyEvent{Type: "MODIFIED", ResourceVersion: "101", Policy: &policy})
		var shorteningID string
		for i, maximum := range []int64{600, 86400} {
			next := policy
			next.Policy.MaximumSeconds = maximum
			next.Policy.Revision.Generation = int64(i + 2)
			next.Policy.Revision.Digest = artifact.Digest{byte(i + 6)}
			apply(app.PolicyEvent{Type: "MODIFIED", ResourceVersion: []string{"102", "103"}[i], Policy: &next})
			if i == 0 {
				shorteningID = checkpoint.Record.ID
			}
		}
		auditPool := poolFor("retention_source_audit_runtime", "synthetic-retention-source-audit")
		defer auditPool.Close()
		auditor, err := postgres.NewRetentionSources(ctx, auditPool, s.a.RootID)
		if err != nil {
			t.Fatal(err)
		}
		if err = (app.RetentionAcceptancePublisher{Journal: auditor, Writer: &objectstore.RetentionAcceptanceObjects{Store: store, Seal: keys, Open: keys}}).Publish(ctx, 64); err != nil {
			t.Fatal(err)
		}
		// Missing immutable audit versions cannot stop restrictive historical
		// application. The exact original receipt is restored after these
		// actual three deadline reductions; it never supplies current authority.
		withHistoricalRetentionReceipt(t, ctx, admin, s.a.RootID, shorteningID, "checkpoint", "", func() {
			// Eight workers compete for single-item pages. Root/job locks must keep
			// each cursor exact, with the entire earlier checkpoint applied first.
			var wg sync.WaitGroup
			results := make(chan privacy.RetentionCatchupPage, 8)
			errs := make(chan error, 8)
			for range 8 {
				wg.Go(func() { p, err := worker.ReconcileRetentionPage(ctx, ref, 1); results <- p; errs <- err })
			}
			wg.Wait()
			close(results)
			close(errs)
			for err := range errs {
				if err != nil {
					t.Fatal(err)
				}
			}
			visited, shortened, completed := 0, 0, 0
			for p := range results {
				visited += p.Visited
				shortened += p.Shortened
				if p.Complete {
					completed++
				}
			}
			for i := 0; i < 10; i++ {
				p, err := worker.ReconcileRetentionPage(ctx, ref, 1)
				if err != nil {
					t.Fatal(err)
				}
				if p.Idle {
					break
				}
				visited += p.Visited
				shortened += p.Shortened
				if p.Complete {
					completed++
				}
			}
			if visited != 9 || shortened != 3 || completed != 3 {
				t.Fatal("lost/repeated pages", visited, shortened, completed)
			}
			for _, loc := range locations {
				r, err := worker.RetainedArtifact(ctx, loc)
				if err != nil || r.Sequence != 1 || !r.Effective.DeleteBy.Equal(r.Registration.AnchorAt.Add(10*time.Minute)) || !r.Effective.ExpiresAt.Equal(r.Registration.AnchorAt.Add(5*time.Minute)) {
					t.Fatal("relaxation overtook shortening", r, err)
				}
			}
			var effects int
			if err = admin.QueryRow(ctx, "SELECT count(*) FROM retention_catchup_effect e JOIN retention_checkpoint c ON c.id=e.checkpoint_id WHERE c.root_id=$1", s.a.RootID).Scan(&effects); err != nil || effects != 3 {
				t.Fatal("missing exact lifecycle links", effects, err)
			}
			if _, err = admin.Exec(ctx, "UPDATE retention_catchup SET completed_at=NULL WHERE checkpoint_id=$1", checkpoint.Record.ID); err == nil {
				t.Fatal("completed catch-up rewound")
			}
		})
		// Completed pages are insufficient while a caused lifecycle decision
		// still lacks its authenticated durable object receipt.
		readPool := poolFor("retention_source_read_runtime", "synthetic-retention-source-read")
		defer readPool.Close()
		lifecyclePool := poolFor("retention_audit_runtime", "synthetic-retention-audit")
		defer lifecyclePool.Close()
		reader, err := postgres.NewRetentionSources(ctx, readPool, s.a.RootID)
		if err != nil {
			t.Fatal(err)
		}
		latest := checkpoint.Transition.List
		now = time.Now().UTC().Truncate(time.Microsecond)
		latest.Snapshot.ObservedAt, latest.Snapshot.FreshUntil = now, now.Add(5*time.Second)
		f := start.Fence
		f.Sequence = checkpoint.Record.Sequence
		if err = sources.ObserveRetention(ctx, app.RetentionObservation{Fence: f, List: latest, Protection: privacy.SourceProtection{SourceClusterID: ref.ClusterID, ControlNamespaceUID: ref.ControlNamespaceUID, Digest: ref.ProtectionDigest, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}}); err != nil {
			t.Fatal(err)
		}
		if _, err = reader.AcceptedRetentionSource(ctx, f.RootID, ref); err == nil {
			t.Fatal("source Ready with unaudited deadline changes")
		}
		lifecycle, err := postgres.NewRetention(ctx, lifecyclePool, s.a.RootID)
		if err != nil {
			t.Fatal(err)
		}
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := jose.NewLifecycleSignatures(f.RootID, "lifecycle", priv, map[string]ed25519.PublicKey{"lifecycle": pub})
		if err != nil {
			t.Fatal(err)
		}
		if err = (privacyapp.LifecyclePublisher{Ledger: lifecycle, Objects: &objectstore.LifecycleObjects{Store: store, Seal: keys, Open: keys, Signer: signer, Verifier: signer}}).Publish(ctx); err != nil {
			t.Fatal(err)
		}
		if ready, err := reader.AcceptedRetentionSource(ctx, f.RootID, ref); err != nil || !ready.Ready {
			t.Fatal("fully audited source unavailable", err)
		}
		qualifyRetentionLifecycleReceiptHistory(t, ctx, admin, reader, f.RootID, ref, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Microsecond)
			current := latest
			current.Snapshot.ObservedAt, current.Snapshot.FreshUntil = now, now.Add(5*time.Second)
			if err := sources.ObserveRetention(ctx, app.RetentionObservation{Fence: f, List: current, Protection: privacy.SourceProtection{SourceClusterID: ref.ClusterID, ControlNamespaceUID: ref.ControlNamespaceUID, Digest: ref.ProtectionDigest, ObservedAt: now, FreshUntil: current.Snapshot.FreshUntil}}); err != nil {
				t.Fatal(err)
			}
		})
		// Current labels cannot stand in for unobserved historical selector facts.
		scoped := policy
		scoped.Name = "new-selector"
		scoped.Policy.Revision.UID = "new-selector"
		scoped.Policy.Baseline = false
		scoped.Scope.NamespaceLabels = map[string]string{"owner": "team"}
		apply(app.PolicyEvent{Type: "ADDED", ResourceVersion: "selector:4", Policy: &scoped})
		if _, err = worker.ReconcileRetentionPage(ctx, ref, 1); err == nil {
			t.Fatal("unknown selector history silently skipped")
		}
		var recorded int64
		if err = admin.QueryRow(ctx, "SELECT visited FROM retention_catchup WHERE checkpoint_id=$1", checkpoint.Record.ID).Scan(&recorded); err != nil || recorded != 0 {
			t.Fatal("failed page advanced", recorded, err)
		}
		bad := ref
		bad.ProtectionDigest[0]++
		if _, err = worker.ReconcileRetentionPage(ctx, bad, 1); err == nil {
			t.Fatal("replacement protection accepted")
		}
		if _, err = worker.ReconcileRetentionPage(ctx, ref, 17); err == nil {
			t.Fatal("unbounded page accepted")
		}
		if _, err = admin.Exec(ctx, "UPDATE retention_source SET recovery_blocked=true WHERE root_id=$1", s.a.RootID); err != nil {
			t.Fatal(err)
		}
		if _, err = worker.ReconcileRetentionPage(ctx, ref, 1); err == nil {
			t.Fatal("unqualified restored source processed")
		}
	})
}
