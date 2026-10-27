package integration

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	app "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Real purpose-separated SQL enrollment and custody, with the existing synthetic
// administrator/source/history fixture. This qualifies migration arithmetic and
// preserved uncertain reservations, not installed collection or object output.
func TestPacketEvidenceBackingMigrationWithRealPostgres(t *testing.T) {
	withCapacityProducerFixture(t, qualifyPacketEvidenceMigration)
}

func packetEvidenceMigration(ctx context.Context, admin *pgxpool.Pool, up bool) error {
	raw, err := os.ReadFile("../../migrations/00100_packet_evidence_backing.sql")
	if err != nil {
		return err
	}
	parts := strings.Split(string(raw), "-- +goose Down")
	body := parts[0]
	if !up {
		body = parts[1]
	}
	tx, err := admin.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, body); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func qualifyPacketEvidenceMigration(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope fleet.InstallationWitnessScope, claim string, administration fleet.Administration, objects *objectstore.AuthorityObjects) {
	// Exercise the actual Down SQL to restore the historical formula before
	// creating legacy rows. The harness's schema ledger remains owned by goose;
	// this test explicitly executes the two transactional migration bodies.
	if err := packetEvidenceMigration(ctx, admin, false); err != nil {
		t.Fatal("historical formula", err)
	}
	smallUnit := (artifact.Registration{NativeLimit: artifact.MaxContextBytes}).ReservedBytes()
	packetUnit := (artifact.Registration{NativeLimit: artifact.RecordingNativeLimit}).ReservedBytes()
	f := newCapacitySQLFixture(t, ctx, admin, address, tlsConfig, scope, claim, administration, objects, func(f *capacitySQLFixture) {
		configurePacketEvidenceLegacySource(f, scope.ClusterID, packetUnit)
	})
	if _, err := f.producer.InitializeCapacity(ctx, f.input, f.protection); err != nil {
		t.Fatal("capacity setup", err)
	}
	f.open(t)
	o := f.rootObservation(t)
	root, err := f.roots.ReserveCapacityRoot(ctx, o)
	if err == nil {
		root, err = f.captureRoots.BackCapacityRoot(ctx, o, root)
	}
	if err == nil {
		root, err = f.roots.PublishCapacityRoot(ctx, o, root)
	}
	if err != nil {
		t.Fatal("root", err)
	}
	enroll := func(index int) app.Enrollment {
		t.Helper()
		co := app.EnrollmentCoordinator{Store: f.enrollments, Capture: f.captureEnrollments, Accounts: f.accounts, Now: time.Now}
		e, err := co.Reconcile(ctx, f.workloadObservation(t, index))
		if err != nil {
			t.Fatal("legacy enrollment", index, err)
		}
		return e
	}
	small := enroll(0)
	f.assertLegacyAdmission(t, small, true) // retain an actual uncertain reservation
	packetNamespace := cfg.NamespaceRef{Name: "packet-apps", UID: custodyID()}
	f.addPermissionScope(t, scope.ClusterID, packetNamespace)
	source, recovery := f.fresh(t)
	permissions, err := f.permissionRead.ReadCapacityPermissions(ctx, recovery)
	if err != nil {
		t.Fatal("packet permission scope", err)
	}
	n := time.Now().UTC().Truncate(time.Microsecond)
	until := identity.Earlier(n.Add(5*time.Second), recovery.FreshUntil)
	guard := app.CapacityNamespaceProtection{ClusterID: scope.ClusterID, Digest: f.qualification.NamespaceGuards[0].Digest, Keys: []string{"team"}, ObservedAt: n, FreshUntil: until}
	workload := capacityNativeWorkload(scope.ClusterID, packetNamespace, f.workloads[1], n, until)
	workload.Namespace.Labels["team"] = "packet"
	packetObservation, _, err := app.ComposeEnrollmentObservation(source, guard, workload, permissions, recovery, f.input.AccountVersion, time.Now())
	if err != nil {
		t.Fatal("packet observation", err)
	}
	co := app.EnrollmentCoordinator{Store: f.enrollments, Capture: f.captureEnrollments, Accounts: f.accounts, Now: time.Now}
	packet, err := co.Reconcile(ctx, packetObservation)
	if err != nil {
		t.Fatal("legacy packet enrollment", err)
	}
	snapshot := func() string {
		t.Helper()
		var raw string
		err := admin.QueryRow(ctx, `SELECT jsonb_build_object(
   'allocations',(SELECT jsonb_agg(to_jsonb(a) ORDER BY a.id) FROM custody_allocation a JOIN capacity_workload w ON w.allocation_id=a.id WHERE w.root_id=$1),
   'pools',(SELECT jsonb_agg(to_jsonb(p) ORDER BY p.id) FROM custody_pool p JOIN capacity_pool c ON c.id=p.id WHERE c.root_id=$1),
   'workloads',(SELECT jsonb_agg(to_jsonb(w) ORDER BY w.id) FROM capacity_workload w WHERE root_id=$1),
   'control',(SELECT jsonb_agg(to_jsonb(c) ORDER BY c.allocation_id) FROM context_control_account c WHERE root_id=$1))::text`, f.input.PermissionRootID).Scan(&raw)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	bytes := func(e app.Enrollment) int64 {
		t.Helper()
		var n int64
		if err := admin.QueryRow(ctx, "SELECT byte_limit FROM custody_allocation WHERE id=$1", e.AllocationID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if bytes(small) != 3*smallUnit || bytes(packet) != 3*smallUnit {
		t.Fatal("historical child not reproduced")
	}
	// Malformed retained accounting must abort before any child or function change.
	if _, err := admin.Exec(ctx, "UPDATE custody_pool SET allocated_bytes=allocated_bytes+1 WHERE id=(SELECT pool_id FROM custody_allocation WHERE id=$1)", packet.AllocationID); err != nil {
		t.Fatal(err)
	}
	corrupt := snapshot()
	if err := packetEvidenceMigration(ctx, admin, true); err == nil {
		t.Fatal("nonexact graph migrated")
	}
	if snapshot() != corrupt {
		t.Fatal("failed migration partially changed graph")
	}
	if _, err := admin.Exec(ctx, "UPDATE custody_pool SET allocated_bytes=allocated_bytes-1 WHERE id=(SELECT pool_id FROM custody_allocation WHERE id=$1)", packet.AllocationID); err != nil {
		t.Fatal(err)
	}
	before := snapshot()
	if err := packetEvidenceMigration(ctx, admin, true); err != nil {
		t.Fatal("legacy upgrade", err)
	}
	if bytes(small) != 3*smallUnit || bytes(packet) != 3*packetUnit {
		t.Fatal("authored child funding not projected exactly")
	}
	after := snapshot()
	var original, upgraded map[string]any
	if json.Unmarshal([]byte(before), &original) != nil || json.Unmarshal([]byte(after), &upgraded) != nil {
		t.Fatal("snapshot")
	}
	for _, collection := range []string{"allocations", "pools"} {
		field := "byte_limit"
		if collection == "pools" {
			field = "allocated_bytes"
		}
		for _, state := range []map[string]any{original, upgraded} {
			for _, row := range state[collection].([]any) {
				delete(row.(map[string]any), field)
			}
		}
	}
	a, _ := json.Marshal(original)
	b, _ := json.Marshal(upgraded)
	if string(a) != string(b) {
		t.Fatal("upgrade changed identity, revisions, spend, object caps or deadlines")
	}
	if err := packetEvidenceMigration(ctx, admin, false); err != nil {
		t.Fatal("unspent rollback", err)
	}
	if snapshot() != before {
		t.Fatal("rollback failed to restore exact prior graph")
	}
	if err := packetEvidenceMigration(ctx, admin, true); err != nil {
		t.Fatal("repeat upgrade", err)
	}
	// An actual custody registration consumes the enlarged child. It writes no
	// evidence; the full packet reservation stays charged and cannot be refunded.
	now := time.Now().UTC().Truncate(time.Microsecond)
	r := artifact.Registration{Location: artifact.Location{ClusterID: packet.Key.ClusterID, ArtifactID: custodyID(), AttemptID: custodyID()}, StoreID: f.qualification.Backends[0].EvidenceStoreID, AllocationID: packet.AllocationID, NativeLimit: artifact.RecordingNativeLimit, AnchorAt: now, WriteUntil: now.Add(time.Second), ExpiresAt: now.Add(time.Minute), DeleteBy: now.Add(2 * time.Minute)}
	if err := admin.QueryRow(ctx, `SELECT p.revision,a.revision FROM custody_allocation a JOIN custody_pool p ON p.id=a.pool_id WHERE a.id=$1`, packet.AllocationID).Scan(&r.PoolRevision, &r.AllocationRevision); err != nil {
		t.Fatal(err)
	}
	if _, err := f.legacy.Register(ctx, r); err != nil {
		t.Fatal("funded packet custody reservation", err)
	}
	charged := snapshot()
	if err := packetEvidenceMigration(ctx, admin, false); err == nil {
		t.Fatal("rollback discarded uncertain packet charge")
	}
	if snapshot() != charged {
		t.Fatal("refused rollback changed graph")
	}
}

func configurePacketEvidenceLegacySource(f *capacitySQLFixture, cluster string, packetUnit int64) {
	// Both immutable policies are present before root/child enrollment.
	// Replacing an enrolled policy would test an unrelated source refusal.
	budget := *f.template.Policies[0].Budget
	budget.Name = "packet-applications"
	budget.Context.Bytes = 3 * packetUnit
	budget.Protected.Bytes, budget.Hard.Bytes = 3*packetUnit, 3*packetUnit
	budget.NamespaceMaximum.Bytes = int64(capacityNativeAccounts) * budget.Protected.Bytes
	policy := f.template.Policies[0]
	policy.Budget = &budget
	policy.Resource.Name, policy.Resource.UID = budget.Name, custodyID()
	policy.Resource.SpecDigest = artifact.Digest{77}
	policy.Scope = &app.BudgetScope{ClusterID: cluster, NamespaceLabels: map[string]string{"team": "packet"}}
	f.template.Policies = append(f.template.Policies, policy)
	f.template.Pools[0].Budget.Slots = append(f.template.Pools[0].Budget.Slots,
		app.ProtectedSlotInput{Policy: budget.Name, Workloads: 1, Protected: budget.Protected})
}

func TestPacketEvidenceMigrationSourceShape(t *testing.T) {
	root := "30000000-0000-4000-8000-000000000001"
	q, source := capacityNativeQualification(t, root, root, root, root, "synthetic-v1")
	f := &capacitySQLFixture{template: source}
	configurePacketEvidenceLegacySource(f, root, (artifact.Registration{NativeLimit: artifact.RecordingNativeLimit}).ReservedBytes())
	p, err := app.CompileProtectedPoolPlan(f.template, "capacity")
	if err != nil {
		t.Fatal("two preauthored immutable slices", err)
	}
	if _, err = app.CompileQualifiedRootBacking(q, p); err != nil {
		t.Fatal("existing root qualification", err)
	}
	if len(p.Policies) != 2 {
		t.Fatal("missing separate small and packet policy")
	}
}
