package integration

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Reuse the existing actual initialized/restricted SQL fixture. Only the
// privacy-operator/source roots are synthetic; grants come from the compiled
// shared hub role that owns the processing duty, without an extra table grant.
func qualifyProcessingInventory(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, s captureAdmissionScenario, e artifact.ContextExpectation, f *processingTestFixture, change value.ProcessingChange) {
	t.Helper()
	const password = "synthetic-inventory"
	role := narrowRole(t, ctx, admin, "processing_inventory_", password, func(name string) []string {
		grants, ok := postgres.PublicRuntimeRoleGrantSQL("hub-runtime", name)
		if !ok {
			t.Fatal("compiled hub processing grants")
		}
		return grants
	})
	pool := poolFor(role, password)
	defer pool.Close()
	reader, err := postgres.NewProcessingInventory(ctx, pool, s.a.RootID, s.recovery.guard)
	if err != nil {
		t.Fatal("compiled processing inventory constructor", err)
	}
	authority := func() value.ProcessingAuthority {
		t.Helper()
		start := time.Now().UTC().Truncate(time.Microsecond)
		i, err := f.actor.ResolveIdentity(ctx)
		if err != nil {
			t.Fatal(err)
		}
		p, err := f.policy.DownloadPolicy(ctx)
		if err != nil {
			t.Fatal(err)
		}
		r, err := s.recovery.reader.RecoveryState(ctx)
		if err != nil {
			t.Fatal(err)
		}
		until := identity.Earlier(start.Add(5*time.Second), identity.Earlier(i.ValidUntil, identity.Earlier(p.FreshUntil, r.FreshUntil)))
		a := value.ProcessingAuthority{Identity: i, Policy: p, Recovery: r, ObservedAt: start, ValidUntil: until}
		if !a.Valid(time.Now()) {
			t.Fatal("current synthetic operator roots unavailable")
		}
		return a
	}
	q := value.ProcessingInventoryQuery{Limit: 1}
	before := func() string {
		t.Helper()
		var raw string
		if err := admin.QueryRow(ctx, `SELECT jsonb_build_object('root',to_jsonb(p),'rules',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM processing_rule r WHERE r.root_id=p.root_id))::text FROM processing_root p WHERE p.root_id=$1`, s.a.RootID).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		return raw
	}()
	page, err := reader.ReadProcessingInventory(ctx, authority(), q)
	if err != nil || !page.Initialized || len(page.Rules) != 1 || page.Rules[0].ID != change.RuleID || page.Rules[0].Revision != 1 || page.Rules[0].State != "restricted" || page.Rules[0].Scope != change.Scope {
		t.Fatal("compiled rule inventory while ordinary reads denied", err)
	}
	empty, err := reader.ReadProcessingInventory(ctx, authority(), value.ProcessingInventoryQuery{After: change.RuleID, Limit: 1})
	if err != nil || len(empty.Rules) != 0 || empty.NextCursor != "" {
		t.Fatal("bounded inventory cursor", err)
	}
	scope, err := reader.ResolveProcessingArtifactScope(ctx, authority(), e.Registration.Location.ArtifactID)
	if err != nil || scope.Kind != "artifact" || scope.Location != e.Registration.Location {
		t.Fatal("operator artifact scope under restriction", err)
	}
	if _, err = reader.ResolveProcessingArtifactScope(ctx, authority(), custodyID()); err == nil {
		t.Fatal("unknown artifact invented an immutable scope")
	}
	for _, mode := range []string{"source", "guard", "recovery"} {
		a := authority()
		switch mode {
		case "source":
			a.Policy.Revision.UID = custodyID()
		case "guard":
			a.Policy.ProtectionDigest[0]++
		case "recovery":
			a.Recovery.Revision.Digest[0]++
		}
		if result, err := reader.ReadProcessingInventory(ctx, a, q); err == nil || len(result.Rules) != 0 {
			t.Fatal("inventory ignored SQL fence", mode, err)
		}
	}
	// A held serialization lock must spend the same original observation,
	// rather than obtaining a new five-second window after it is released.
	a := authority()
	a.ValidUntil = time.Now().UTC().Add(100 * time.Millisecond)
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(ctx, `SELECT id FROM permission_stream WHERE id=$1 FOR UPDATE`, s.a.RootID); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := reader.ReadProcessingInventory(ctx, a, q); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("inventory survived original deadline behind serialization lock")
		}
	case <-time.After(time.Second):
		t.Fatal("inventory did not cancel its original bound")
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var after string
	if err = admin.QueryRow(ctx, `SELECT jsonb_build_object('root',to_jsonb(p),'rules',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM processing_rule r WHERE r.root_id=p.root_id))::text FROM processing_root p WHERE p.root_id=$1`, s.a.RootID).Scan(&after); err != nil || after != before {
		t.Fatal("inventory changed retained rules or authority", err)
	}
	t.Log("compiled hub role with processing duty: operator rule/scope read, cursor, current SQL fences and original lock-wait expiry; no state changes")
}
