package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/privacy"
	"github.com/jackc/pgx/v5/pgxpool"
)

func qualifyRetentionObservation(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, setup func(*testing.T) (*postgres.RetentionSources, *postgres.RetentionSources, app.RetentionTransition)) {
	readPool := poolFor("retention_source_read_runtime", "synthetic-retention-source-read")
	defer readPool.Close()
	catchupPool := poolFor("retention_catchup_runtime", "synthetic-retention-catchup")
	defer catchupPool.Close()
	for _, q := range []string{"UPDATE retention_source SET fresh_until=clock_timestamp()", "UPDATE retention_catchup SET completed_at=clock_timestamp()", "UPDATE retention_checkpoint SET audit_acknowledged_at=clock_timestamp()", "UPDATE retention_decision SET audit_acknowledged_at=clock_timestamp()"} {
		if _, err := readPool.Exec(ctx, q); err == nil {
			t.Fatal("reader can forge readiness", q)
		}
	}
	t.Run("retention-ready-requires-watermark-catchup-and-audit", func(t *testing.T) {
		s, auditor, req := setup(t)
		cp, err := s.AcceptRetention(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		f := req.Fence
		f.Sequence = cp.Record.Sequence
		reader, err := postgres.NewRetentionSources(ctx, readPool, f.RootID)
		if err != nil {
			t.Fatal(err)
		}
		worker, err := postgres.NewRetention(ctx, catchupPool, f.RootID)
		if err != nil {
			t.Fatal(err)
		}
		publisher := app.RetentionAcceptancePublisher{Journal: auditor, Writer: &objectstore.RetentionAcceptanceObjects{Store: store, Seal: keys, Open: keys}}
		observe := func(rv string, lifetime time.Duration) app.RetentionObservation {
			// Real LIST/guard observations carry nanoseconds; native75-77 refused
			// every one when only part of the bound was truncated.
			now := time.Now().UTC().Truncate(time.Microsecond).Add(789 * time.Nanosecond)
			list := cp.Transition.List
			list.ResourceVersion = rv
			list.Snapshot.ObservedAt, list.Snapshot.FreshUntil = now, now.Add(lifetime)
			return app.RetentionObservation{Fence: f, List: list, Protection: privacy.SourceProtection{SourceClusterID: f.Source.ClusterID, ControlNamespaceUID: f.Source.ControlNamespaceUID, Digest: f.Source.ProtectionDigest, ObservedAt: now, FreshUntil: now.Add(lifetime)}}
		}
		unavailable := func() {
			t.Helper()
			if _, err := reader.AcceptedRetentionSource(ctx, f.RootID, f.Source); err == nil {
				t.Fatal("incomplete source became Ready")
			}
		}
		ready := func() privacy.AcceptedSource {
			t.Helper()
			out, err := reader.AcceptedRetentionSource(ctx, f.RootID, f.Source)
			if err != nil || !out.Ready || !out.Valid(time.Now()) || out.Acceptance.UID != cp.Record.ID || out.Acceptance.Generation != f.Sequence {
				t.Fatal("qualified source unavailable", out, err)
			}
			return out
		}
		unavailable()
		if err = s.ObserveRetention(ctx, observe("100", 5*time.Second)); err != nil {
			t.Fatal(err)
		}
		unavailable()
		if err = publisher.Publish(ctx, 64); err != nil {
			t.Fatal(err)
		}
		unavailable() // audit alone does not finish retained-evidence application
		if page, err := worker.ReconcileRetentionPage(ctx, f.Source, 1); err != nil || !page.Complete {
			t.Fatal("empty scan", page, err)
		}
		before := ready()
		// ADR-200 revision (2026-10-23, migration 00075): the accepted
		// observation lives 30 seconds after its original LIST/guard start.
		if before.FreshUntil.Sub(before.ObservedAt) != privacy.RetentionSourceInterval {
			t.Fatal("accepted retention observation lifetime", before.FreshUntil.Sub(before.ObservedAt))
		}
		if err = s.AdvanceRetentionCursor(ctx, f, "101"); err != nil {
			t.Fatal(err)
		}
		after := ready()
		if !before.FreshUntil.Equal(after.FreshUntil) || !before.ObservedAt.Equal(after.ObservedAt) {
			t.Fatal("bookmark extended observation")
		}
		// A final list can look identical after an unseen ADDED -> DELETED pair.
		// Per-object versions and the semantic hash cannot detect this gap.
		o := observe("104", 5*time.Second)
		if err = s.ObserveRetention(ctx, o); !errors.Is(err, value.ErrRetentionHistoryBehind) {
			t.Fatal("transient policy history skipped", err)
		}
		previous := ready()
		if !previous.FreshUntil.Equal(before.FreshUntil) {
			t.Fatal("waiting for history extended the prior observation")
		}
		apply := func(e app.PolicyEvent) {
			t.Helper()
			j, err := app.ResumeRetentionJournal(cp.Transition.List)
			if err != nil {
				t.Fatal(err)
			}
			if err = j.Apply(e); err != nil {
				t.Fatal(err)
			}
			list, err := j.HistoricalCheckpoint()
			if err != nil {
				t.Fatal(err)
			}
			cp, err = s.AcceptRetention(ctx, app.RetentionTransition{ID: custodyID(), Fence: f, List: list, Event: &e})
			if err != nil {
				t.Fatal(err)
			}
			f.Sequence = cp.Record.Sequence
		}
		p := cp.Transition.List.Snapshot.Policies[0]
		p.Name, p.Policy.Revision.UID, p.Policy.Baseline = "temporary", "temporary", false
		p.Scope.ClusterIDs = []string{f.Source.ClusterID}
		p.Policy.MaximumSeconds, p.Policy.Revision.Digest = 600, artifact.Digest{17}
		apply(app.PolicyEvent{Type: "ADDED", ResourceVersion: "102", Policy: &p})
		unavailable() // every data event invalidates an earlier complete observation
		apply(app.PolicyEvent{Type: "DELETED", ResourceVersion: "103", Policy: &p})
		o.Fence = f
		if err = s.ObserveRetention(ctx, o); !errors.Is(err, value.ErrRetentionHistoryBehind) {
			t.Fatal("list watermark not reached", err)
		}
		if err = s.AdvanceRetentionCursor(ctx, f, "104"); err != nil {
			t.Fatal(err)
		}
		if err = s.ObserveRetention(ctx, o); err != nil {
			t.Fatal("original finite list could not complete", err)
		}
		if err = publisher.Publish(ctx, 64); err != nil {
			t.Fatal(err)
		}
		unavailable()
		for range 2 {
			if page, err := worker.ReconcileRetentionPage(ctx, f.Source, 1); err != nil || !page.Complete {
				t.Fatal(page, err)
			}
		}
		ready()
		changed := observe("105", 5*time.Second)
		changed.List.Snapshot.Policies = append([]privacy.ScopedPolicy(nil), changed.List.Snapshot.Policies...)
		changed.List.Snapshot.Policies[0].Policy.MaximumSeconds = 600
		changed.List.Snapshot.Policies[0].Policy.Revision.Generation++
		changed.List.Snapshot.Policies[0].Policy.Revision.Digest = artifact.Digest{18}
		changed.List.Snapshot.Revision.Digest = app.RetentionSnapshotDigest(changed.List.Snapshot)
		changed.List.Versions = map[string]string{"baseline-uid": "105"}
		if err = s.ObserveRetention(ctx, changed); !errors.Is(err, value.ErrRetentionHistoryBehind) {
			t.Fatal("known changed rules", err)
		}
		unavailable()
		if err = s.ObserveRetention(ctx, observe("104", 5*time.Second)); err == nil {
			t.Fatal("old delayed observation revived a known changed source")
		}
		if _, err = admin.Exec(ctx, "UPDATE retention_source SET list_cursor='100' WHERE root_id=$1", f.RootID); err == nil {
			t.Fatal("SQL watermark rewound")
		}
		apply(app.PolicyEvent{Type: "MODIFIED", ResourceVersion: "105", Policy: &changed.List.Snapshot.Policies[0]})
		if err = publisher.Publish(ctx, 64); err != nil {
			t.Fatal(err)
		}
		if _, err = worker.ReconcileRetentionPage(ctx, f.Source, 1); err != nil {
			t.Fatal(err)
		}
		if err = s.ObserveRetention(ctx, observe("105", 5*time.Second)); err != nil {
			t.Fatal(err)
		}
		ready()
		bad := observe("opaque", 5*time.Second)
		if err = s.ObserveRetention(ctx, bad); err == nil {
			t.Fatal("unqualified resource version ordering")
		}
		// Arbitrary precision: no signed/unsigned fixed-width conversion.
		const large = "1234567890123456789012345678901234567890"
		if err = s.AdvanceRetentionCursor(ctx, f, large); err != nil {
			t.Fatal(err)
		}
		if err = s.ObserveRetention(ctx, observe(large, 5*time.Second)); err != nil {
			t.Fatal(err)
		}
		ready()
		// A lock wait must consume the original observation's validity budget.
		o = observe(large, 100*time.Millisecond)
		tx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err = tx.Exec(ctx, "SELECT id FROM permission_stream WHERE id=$1 FOR UPDATE", f.RootID); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- s.ObserveRetention(ctx, o) }()
		time.Sleep(150 * time.Millisecond)
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err = <-done; err == nil {
			t.Fatal("expired observation accepted after lock")
		}
		o = observe(large, 100*time.Millisecond)
		if err = s.ObserveRetention(ctx, o); err != nil {
			t.Fatal(err)
		}
		time.Sleep(150 * time.Millisecond)
		// Migration 00075: the stored observation outlives its short input LIST
		// and guard proof by the relaxed 30-second rule.
		if late := ready(); late.FreshUntil.Sub(late.ObservedAt) != privacy.RetentionSourceInterval {
			t.Fatal("accepted retention observation lifetime", late.FreshUntil.Sub(late.ObservedAt))
		}
		if err = s.ObserveRetention(ctx, observe(large, 5*time.Second)); err != nil {
			t.Fatal(err)
		}
		if err = s.SuspendRetention(ctx, f); err != nil {
			t.Fatal(err)
		}
		unavailable()
		start, err := s.BeginRetention(ctx, f.RootID, f.Source, custodyID())
		if err != nil {
			t.Fatal(err)
		}
		f = start.Fence
		unavailable() // restart must obtain its own complete observation
		if err = s.ObserveRetention(ctx, observe(large, 5*time.Second)); err != nil {
			t.Fatal(err)
		}
		ready()
		if _, err = admin.Exec(ctx, "UPDATE retention_source SET recovery_blocked=true WHERE root_id=$1", f.RootID); err != nil {
			t.Fatal(err)
		}
		unavailable()
	})
}
