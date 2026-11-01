package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

// Reuses the existing initial activation/paired capacity fixture. All target,
// protection and physical qualification facts remain explicitly synthetic;
// PostgreSQL acceptance, role locks, monotonicity and storage charges are real.
func TestCapacitySourceResourcesWithRealPostgres(t *testing.T) {
	withCapacityProducerFixture(t, qualifyCapacitySourceResourcesSQL)
}

func qualifyCapacitySourceResourcesSQL(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope fleet.InstallationWitnessScope, claim string, administration fleet.Administration, objects *objectstore.AuthorityObjects) {
	f := newCapacitySQLFixture(t, ctx, admin, address, tlsConfig, scope, claim, administration, objects)
	if _, err := f.producer.InitializeCapacity(ctx, f.input, f.protection); err != nil {
		t.Fatal("actual paired setup", err)
	}
	f.open(t)
	// Establish actual storage commitments before the projection-only upgrade.
	o := f.rootObservation(t)
	root, err := f.roots.ReserveCapacityRoot(ctx, o)
	if err != nil {
		t.Fatal("root reserve", err)
	}
	root, err = f.captureRoots.BackCapacityRoot(ctx, o, root)
	if err != nil {
		t.Fatal("root capture backing", err)
	}
	if _, err = f.roots.PublishCapacityRoot(ctx, o, root); err != nil {
		t.Fatal("root publication", err)
	}
	before := f.accounting(t)
	original, _ := f.fresh(t)
	policy := original.Observation.Snapshot.Policies[0].Resource.Name
	poolName := original.Observation.Snapshot.Pools[0].Resource.Name
	poolBefore, _, err := capacity.CanonicalProtectedPoolPlan(original.Observation.Snapshot, poolName)
	if err != nil {
		t.Fatal(err)
	}
	selectedBefore, err := capacity.SelectedCapacitySourceDigest(original.Observation.Snapshot, poolName)
	if err != nil {
		t.Fatal(err)
	}

	if limits, err := original.CurrentSourceResources(time.Now(), policy); err != nil || limits != (capacity.SourceResourceLimits{}) {
		t.Fatal("original eight-field accepted budget", limits, err)
	}
	// The old decoder omitted these lowering fields from its typed Budget. The
	// unchanged synthetic complete SpecDigest pins the same original declaration.
	limits := capacity.SourceResourceLimits{Node: collector.PolicyLimits{RingBytes: 64 << 20, FrozenBytes: 32 << 20, SourceLimits: collector.SourceLimits{MaxActiveSources: 4, InputBytesPerSecond: 2 << 20, InputBurstBytes: 1 << 20}}, Workload: collector.SourceLimits{MaxActiveSources: 2}}
	f.template.Policies[0].SourceResources = &limits
	enriched, _ := f.fresh(t)
	if enriched.Revision != original.Revision+1 {
		t.Fatal("enrichment must advance exactly once", original.Revision, enriched.Revision)
	}
	oldResource := original.Observation.Snapshot.Policies[0].Resource
	newResource := enriched.Observation.Snapshot.Policies[0].Resource
	if oldResource.UID != newResource.UID || oldResource.Generation != newResource.Generation || oldResource.SpecDigest != newResource.SpecDigest {
		t.Fatal("fixture changed original source identity")
	}
	if got, err := enriched.CurrentSourceResources(time.Now(), policy); err != nil || got != limits {
		t.Fatal("actual accepted current projection", got, err)
	}

	poolAfter, _, err := capacity.CanonicalProtectedPoolPlan(enriched.Observation.Snapshot, poolName)
	if err != nil {
		t.Fatal(err)
	}
	selectedAfter, err := capacity.SelectedCapacitySourceDigest(enriched.Observation.Snapshot, poolName)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(poolBefore, poolAfter) || selectedBefore != selectedAfter {
		t.Fatal("resource enrichment changed stored pool/selected source bytes")
	}
	currentRoot := f.rootObservation(t)
	if existing, err := f.roots.ReadCapacityRoot(ctx, currentRoot); err != nil || existing == nil || !existing.AdmissionReady(time.Now()) {
		t.Fatal("existing finite root unavailable after resource enrichment", err)
	}
	stable, _ := f.fresh(t)
	if stable.Revision != enriched.Revision {
		t.Fatal("identical projection advanced revision")
	}
	if before != f.accounting(t) {
		t.Fatal("resource projection changed stored amounts/charges")
	}
	t.Log("same original UID/generation/spec: eight-field -> enriched revision+1 -> stable revision; real storage commitments unchanged")

	oldJSON, _ := json.Marshal(original.Observation)
	typedJSON, _ := json.Marshal(stable.Observation)
	getPolicy := func(v map[string]any) map[string]any {
		return v["Snapshot"].(map[string]any)["Policies"].([]any)[0].(map[string]any)
	}
	getBudget := func(v map[string]any) map[string]any {
		return v["Snapshot"].(map[string]any)["Policies"].([]any)[0].(map[string]any)["Budget"].(map[string]any)
	}
	clone := func() map[string]any {
		var v map[string]any
		if json.Unmarshal(typedJSON, &v) != nil {
			t.Fatal("clone")
		}
		return v
	}
	check := func(t *testing.T, oldRaw, newRaw []byte, wantValid, wantMonotonic bool) {
		t.Helper()
		var valid, monotonic bool
		if err := admin.QueryRow(ctx, `SELECT capacity_source_observation_valid($2::jsonb),capacity_source_monotonic($1::jsonb,$2::jsonb)`, oldRaw, newRaw).Scan(&valid, &monotonic); err != nil || valid != wantValid || monotonic != wantMonotonic {
			t.Fatal("actual closed SQL validator/monotonic result", valid, monotonic, err)
		}
	}
	t.Run("one-way-lowering-projection", func(t *testing.T) { check(t, oldJSON, typedJSON, true, true) })
	for _, tc := range []struct {
		name  string
		edit  func(map[string]any)
		valid bool
	}{
		{"typed-removal", func(v map[string]any) { delete(getPolicy(v), "SourceResources") }, true},
		{"typed-mutation", func(v map[string]any) {
			getPolicy(v)["SourceResources"].(map[string]any)["Node"].(map[string]any)["maxActiveSources"] = 3
		}, true},
		{"old-storage-mutation", func(v map[string]any) { getBudget(v)["Protected"].(map[string]any)["Bytes"] = 17 }, true},
		{"unknown-authority-field", func(v map[string]any) {
			getPolicy(v)["SourceResources"].(map[string]any)["Node"].(map[string]any)["ObservedCredit"] = 1
		}, false},

		{"unknown-resource-key", func(v map[string]any) { getPolicy(v)["SourceResources"].(map[string]any)["GrantID"] = "not-authority" }, false},
		{"unknown-workload-key", func(v map[string]any) {
			getPolicy(v)["SourceResources"].(map[string]any)["Workload"].(map[string]any)["RawAllowed"] = true
		}, false},
		{"null-resources", func(v map[string]any) { getPolicy(v)["SourceResources"] = nil }, false},
		{"fraction", func(v map[string]any) {
			getPolicy(v)["SourceResources"].(map[string]any)["Workload"].(map[string]any)["maxActiveSources"] = 1.5
		}, false},
		{"negative", func(v map[string]any) {
			getPolicy(v)["SourceResources"].(map[string]any)["Node"].(map[string]any)["RingBytes"] = -1
		}, false},
		{"overflow", func(v map[string]any) {
			getPolicy(v)["SourceResources"].(map[string]any)["Node"].(map[string]any)["inputBytesPerSecond"] = float64(1 << 50)
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := clone()
			tc.edit(candidate)
			raw, _ := json.Marshal(candidate)
			check(t, typedJSON, raw, tc.valid, false)
		})
	}
	// An enrichment cannot smuggle a change to an old quantity, scope or spec.
	t.Run("enrichment-preserves-old-claims", func(t *testing.T) {
		v := clone()
		getBudget(v)["Protected"].(map[string]any)["Bytes"] = 17
		raw, _ := json.Marshal(v)
		check(t, oldJSON, raw, true, false)
	})

	t.Run("enrichment-preserves-scope", func(t *testing.T) {
		v := clone()
		getPolicy(v)["Scope"].(map[string]any)["NamespaceLabels"].(map[string]any)["team"] = "different"
		raw, _ := json.Marshal(v)
		check(t, oldJSON, raw, true, false)
	})
	t.Run("enrichment-preserves-spec", func(t *testing.T) {
		v := clone()
		versions := v["Versions"].([]any)
		for _, x := range versions {
			item := x.(map[string]any)
			if item["Kind"] == "EvidenceBudgetPolicy" {
				item["Spec"].([]any)[0] = float64(99)
			}
		}
		raw, _ := json.Marshal(v)
		check(t, oldJSON, raw, false, false)
	})

	t.Run("bounded64-policy-projection-check", func(t *testing.T) {
		// Synthetic maximum-size metadata only; no storage/source admission for
		// these extra rows. Measures the complete pinned SQL validator/monotonic path.
		oldWide, newWide := original.Observation.Snapshot, stable.Observation.Snapshot
		oldWide.Policies, newWide.Policies = nil, nil
		for i := 0; i < capacity.CapacityPolicyLimit; i++ {
			p := original.Observation.Snapshot.Policies[0]
			p.Resource.Name, p.Resource.UID = "bounded-"+strconv.Itoa(i), "bounded-policy-"+strconv.Itoa(i)
			budget := *p.Budget
			budget.Name = p.Resource.Name
			p.Budget = &budget
			oldWide.Policies = append(oldWide.Policies, p)
			p.SourceResources = &limits
			newWide.Policies = append(newWide.Policies, p)
		}
		n := time.Now().UTC().Truncate(time.Microsecond)
		oldValue := capacityNativeSource(t, oldWide, n, n.Add(5*time.Second))
		newValue := capacityNativeSource(t, newWide, n, n.Add(5*time.Second))
		oldBytes, _ := json.Marshal(oldValue)
		newBytes, _ := json.Marshal(newValue)
		started := time.Now()
		check(t, oldBytes, newBytes, true, true)
		elapsed := time.Since(started)
		if elapsed >= capacity.CapacitySourceInterval {
			t.Fatal("bounded metadata checks exhausted original source interval", elapsed)
		}
		t.Logf("synthetic metadata only:64 policy validator+one-way checks %s; no source arm/kernel/CPU qualification", elapsed)
	})
	// Exercise the real adapter, SQL role/locks and persistent restrictive result,
	// rather than only immutable helper predicates. A fresh time is not permission
	// to change an already typed cap at the same original source generation.
	t.Run("actual-typed-mutation-fences-without-refund", func(t *testing.T) {
		f.refreshBase(t)
		recovery, err := f.source.RecoveryState(ctx)
		if err != nil {
			t.Fatal(err)
		}
		revision, err := f.source.ReadCapacitySourceRevision(ctx, recovery)
		if err != nil {
			t.Fatal(err)
		}
		protection, err := f.protection.CapacityProtection(ctx)
		if err != nil {
			t.Fatal(err)
		}
		altered := limits
		altered.Node.MaxActiveSources = 3
		f.template.Policies[0].SourceResources = &altered
		n := time.Now().UTC().Truncate(time.Microsecond)
		observation := capacityNativeSource(t, f.template, n, identity.Earlier(n.Add(5*time.Second), recovery.FreshUntil))
		in := capacity.CapacitySourceAcceptance{RootID: f.input.PermissionRootID, InstallationID: f.input.InstallationID, QualificationID: f.qualification.ID, QualificationDigest: f.qualification.Digest, ExpectedRevision: revision, Observation: observation, Protection: protection, Recovery: recovery}
		if _, err = f.source.AcceptCapacitySource(ctx, in); err == nil {
			t.Fatal("typed mutation accepted")
		}
		var suspended bool
		var persisted int64
		if err = admin.QueryRow(ctx, `SELECT suspended,accepted_revision FROM capacity_source WHERE root_id=$1`, f.input.PermissionRootID).Scan(&suspended, &persisted); err != nil || !suspended || persisted != revision+1 {
			t.Fatal("restrictive watermark not committed", suspended, persisted, err)
		}
		if before != f.accounting(t) {
			t.Fatal("refusal refunded or changed storage commitments")
		}
		// Reusing the same original proof after its real expiry cannot clear fence.
		capacityWaitUntil(t, ctx, in.Observation.Snapshot.FreshUntil.Add(time.Millisecond))
		if _, err = f.source.AcceptCapacitySource(ctx, in); err == nil {
			t.Fatal("expired original acceptance succeeded")
		}
		if before != f.accounting(t) {
			t.Fatal("expiry changed charges")
		}
		t.Log("actual same-generation typed mutation committed suspension; original expired proof refused; no storage refund")
	})
	t.Run("typed-rows-preserved-through-down-up", func(t *testing.T) {
		const stateSQL = `SELECT to_jsonb(s)::text FROM capacity_source s WHERE root_id=$1`
		var beforeState string
		if err := admin.QueryRow(ctx, stateSQL, f.input.PermissionRootID).Scan(&beforeState); err != nil {
			t.Fatal(err)
		}
		db := stdlib.OpenDB(*admin.Config().ConnConfig)
		defer db.Close()
		provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.Files(), goose.WithDisableGlobalRegistry(true))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = provider.DownTo(ctx, 103); err != nil {
			t.Fatal("Down104", err)
		}
		var afterState string
		var typedValid bool
		if err = admin.QueryRow(ctx, stateSQL, f.input.PermissionRootID).Scan(&afterState); err != nil || afterState != beforeState {
			t.Fatal("Down rewrote accepted state", err)
		}
		if err = admin.QueryRow(ctx, `SELECT capacity_source_observation_valid($1::jsonb)`, typedJSON).Scan(&typedValid); err != nil || typedValid {
			t.Fatal("old decoder claimed typed compatibility", typedValid, err)
		}
		if _, err = provider.Up(ctx); err != nil {
			t.Fatal("Up104", err)
		}
		if err = admin.QueryRow(ctx, stateSQL, f.input.PermissionRootID).Scan(&afterState); err != nil || afterState != beforeState {
			t.Fatal("Up rewrote accepted state", err)
		}
		if before != f.accounting(t) {
			t.Fatal("Down/Up changed storage amounts")
		}
		t.Log("typed accepted/negative snapshots and charges retained; Down correctly refuses new shape; Up restores schema without erasing fence")
	})

}
