package integration

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// qualifyRegionalExtension runs after the renewal stage on the same root
// (ADR-197, migration 00065): the hub-api's write-once regional cluster
// qualification, an additive regional budget policy that existing hub
// enrollments survive before and after the root read adopts it, and the
// refusal of a non-additive change. Values are synthetic; no regional
// workload is reserved here (the native run covers that).
func (f *capacitySQLFixture) qualifyRegionalExtension(t *testing.T, first app.Enrollment) {
	t.Helper()
	root, hub := f.input.PermissionRootID, f.input.ControlClusterID
	regional, peer, epoch := custodyID(), custodyID(), custodyID()
	keys, _ := json.Marshal([]string{"team"})
	qualify := func(cluster string, digest artifact.Digest) (bool, error) {
		var inserted bool
		err := f.admin.QueryRow(f.ctx, `SELECT qualify_capacity_cluster($1,$2,$3,$4,$5,$6)`, root, cluster, peer, epoch, digest[:], keys).Scan(&inserted)
		return inserted, err
	}
	if !t.Run("write-once-regional-qualification", func(t *testing.T) {
		if inserted, err := qualify(regional, artifact.Digest{21}); err != nil || !inserted {
			t.Fatal("first regional qualification", err)
		}
		if inserted, err := qualify(regional, artifact.Digest{21}); err != nil || inserted {
			t.Fatal("exact replay was not read-only", err)
		}
		if _, err := qualify(regional, artifact.Digest{22}); err == nil {
			t.Fatal("changed regional qualification accepted")
		}
		if _, err := qualify(hub, artifact.Digest{21}); err == nil {
			t.Fatal("regional row shadowed the hub's original pin")
		}
		if _, err := f.admin.Exec(f.ctx, `DELETE FROM capacity_cluster_qualification WHERE root_id=$1`, root); err == nil {
			t.Fatal("regional qualification deleted")
		}
		read, err := postgres.NewCapacityClusterQualifications(f.ctx, f.roles["capacity"], root)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := read.ReadCapacityClusterQualifications(f.ctx)
		if err != nil || len(rows) != 1 || rows[0].ClusterID != regional || rows[0].Digest != (artifact.Digest{21}) || !slices.Equal(rows[0].Keys, []string{"team"}) {
			t.Fatal("capacity login regional pins", rows, err)
		}
	}) {
		return
	}
	// An additive revision: the regional policy, its slot and a later pool
	// generation; the hub policy and cluster entries are unchanged.
	extended := f.template
	extended.Pools = slices.Clone(f.template.Pools)
	extended.Policies = slices.Clone(f.template.Policies)
	pool := *extended.Pools[0].Budget
	hubPolicy := *extended.Policies[0].Budget
	policy := hubPolicy
	policy.Name, policy.Cluster = "regional", regional
	pool.Slots = append(slices.Clone(pool.Slots), app.ProtectedSlotInput{Policy: policy.Name, Workloads: 1, Protected: policy.Protected})
	extended.Pools[0].Budget = &pool
	extended.Pools[0].Resource.Generation, extended.Pools[0].Resource.SpecDigest = 2, artifact.Digest{31}
	resource := extended.Policies[0].Resource
	resource.Name, resource.UID = policy.Name, custodyID()
	extended.Policies = append(extended.Policies, app.BudgetPolicyObservation{Resource: resource, Pool: pool.Name, Scope: &app.BudgetScope{ClusterID: regional, NamespaceLabels: map[string]string{"team": "synthetic"}}, Budget: &policy})
	f.template = extended
	read := func(t *testing.T, stage string) {
		t.Helper()
		o := f.workloadObservation(t, 0)
		current, err := f.enrollments.ReadCapacityEnrollment(f.ctx, o)
		if err != nil || current == nil || current.ID != first.ID || current.AllocationID != first.AllocationID || current.PlanDigest != o.PlanDigest || current.SourceDigest != o.SourceDigest || current.PlanDigest == first.PlanDigest {
			t.Fatal(stage+": hub enrollment under the extended pool", err)
		}
		if err = f.enrollments.RefreshCapacityEnrollment(f.ctx, f.workloadObservation(t, 0), *current); err != nil {
			t.Fatal(stage+": hub binding refresh under the extended pool", err)
		}
		f.assertAdmission(t, 0, *current, true)
	}
	if !t.Run("pending-extension-keeps-hub-bindings", func(t *testing.T) {
		read(t, "pending")
		var revisions int
		if err := f.admin.QueryRow(f.ctx, `SELECT count(*) FROM capacity_pool_revision WHERE root_id=$1`, root).Scan(&revisions); err != nil || revisions != 0 {
			t.Fatal("a workload read adopted the extension", revisions, err)
		}
	}) {
		return
	}
	if !t.Run("root-read-adopts-the-additive-revision", func(t *testing.T) {
		if _, err := f.roots.ReadCapacityRoot(f.ctx, f.rootObservation(t)); err != nil {
			t.Fatal("root read with a pending extension", err)
		}
		var revisions, clusters int
		var limit, protected, burst int64
		if err := f.admin.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM capacity_pool_revision WHERE root_id=$1),(SELECT count(*) FROM capacity_cluster WHERE root_id=$1 AND cluster_id=$2),
			c.byte_limit,p.protected_bytes,p.shared_bytes FROM capacity_pool p JOIN custody_pool c ON c.id=p.id WHERE p.root_id=$1`, root, regional).Scan(&revisions, &clusters, &limit, &protected, &burst); err != nil ||
			revisions != 1 || clusters != 1 || limit != protected+burst || protected != (capacityNativeAccounts+1)*hubPolicy.Protected.Bytes {
			t.Fatal("extension rows", revisions, clusters, limit, protected, err)
		}
		if _, err := f.roots.ReadCapacityRoot(f.ctx, f.rootObservation(t)); err != nil {
			t.Fatal("root read after the extension", err)
		}
		if err := f.admin.QueryRow(f.ctx, `SELECT count(*) FROM capacity_pool_revision WHERE root_id=$1`, root).Scan(&revisions); err != nil || revisions != 1 {
			t.Fatal("a second root read revised the pool again", revisions, err)
		}
		read(t, "adopted")
	}) {
		return
	}
	// A regional workload composes under the adopted extension and spends the
	// root's qualified accounts like any other: this fixture's earlier stages
	// hold all of them, so the reservation is refused without a row. The
	// native run enrolls one with accounts to spare.
	if !t.Run("regional-workload-shares-the-qualified-accounts", func(t *testing.T) {
		namespace := cfg.NamespaceRef{Name: "regional-apps", UID: custodyID()}
		f.addPermissionScope(t, regional, namespace)
		workload := cfg.WorkloadRef{Kind: "Deployment", Name: "regional-app", UID: custodyID()}
		o := f.regionalObservation(t, regional, artifact.Digest{21}, namespace, workload)
		count := func() (n int) {
			if err := f.admin.QueryRow(f.ctx, `SELECT count(*) FROM capacity_workload WHERE root_id=$1`, root).Scan(&n); err != nil {
				t.Fatal(err)
			}
			return n
		}
		before := count()
		_, err := (&app.EnrollmentCoordinator{Store: f.enrollments, Capture: f.captureEnrollments, Accounts: f.accounts, Now: time.Now}).Reconcile(f.ctx, o)
		var step interface{ FixedStep() string }
		if before != capacityNativeAccounts || !errors.As(err, &step) || step.FixedStep() != "reserve" || count() != before {
			t.Fatal("regional workload beyond the qualified accounts", before, err)
		}
	}) {
		return
	}
	// ADR-200: a refresh demand is recorded only for an enrolled, ready
	// workload, and only the capacity writer reads demands back.
	if !t.Run("refresh-demand-names-only-ready-workloads", func(t *testing.T) {
		var cluster, nsUID, workloadUID string
		if err := f.admin.QueryRow(f.ctx, `SELECT cluster_id::text,namespace_uid,workload_uid FROM capacity_workload WHERE root_id=$1 AND ready_at IS NOT NULL ORDER BY workload_uid LIMIT 1`, root).Scan(&cluster, &nsUID, &workloadUID); err != nil {
			t.Fatal("ready workload", err)
		}
		demand := func(kind, workload string) error {
			_, err := f.admin.Exec(f.ctx, `SELECT demand_capacity_refresh($1,$2,$3,'payments',$4,'api',$5)`, root, cluster, nsUID, kind, workload)
			return err
		}
		if err := demand("Deployment", workloadUID); err != nil {
			t.Fatal("demand for a ready workload", err)
		}
		if err := demand("Deployment", custodyID()); err != nil {
			t.Fatal("an unknown workload must be a silent no-op", err)
		}
		if err := demand("CronJob", workloadUID); err == nil {
			t.Fatal("an unsupported kind was accepted")
		}
		reader, err := postgres.NewCapacityRefreshDemands(f.ctx, f.roles["capacity"], root)
		if err != nil {
			t.Fatal(err)
		}
		got, err := reader.ReadCapacityRefreshDemands(f.ctx)
		if err != nil || len(got) != 1 || got[0].ClusterID != cluster || got[0].Workload.UID != workloadUID || got[0].Namespace.Name != "payments" || got[0].Workload.Name != "api" {
			t.Fatal("capacity writer demand read", got, err)
		}
		// A download re-arms the demand recorded for the workload behind its
		// download allocation; an unknown allocation changes nothing.
		var allocation string
		var before time.Time
		if err := f.admin.QueryRow(f.ctx, `SELECT w.download_allocation_id::text,d.requested_at FROM capacity_workload w JOIN capacity_refresh_demand d ON d.root_id=w.root_id AND d.workload_uid=w.workload_uid WHERE w.root_id=$1 AND w.workload_uid=$2`, root, workloadUID).Scan(&allocation, &before); err != nil {
			t.Fatal("demand row", err)
		}
		if _, err := f.admin.Exec(f.ctx, `SELECT demand_capacity_refresh_for_download($1,$2)`, root, custodyID()); err != nil {
			t.Fatal("unknown allocation", err)
		}
		if _, err := f.admin.Exec(f.ctx, `SELECT demand_capacity_refresh_for_download($1,$2)`, root, allocation); err != nil {
			t.Fatal("download demand", err)
		}
		var after time.Time
		var rows int
		if err := f.admin.QueryRow(f.ctx, `SELECT max(requested_at),count(*) FROM capacity_refresh_demand WHERE root_id=$1`, root).Scan(&after, &rows); err != nil || !after.After(before) || rows != 1 {
			t.Fatal("download did not re-arm exactly the existing demand", before, after, rows, err)
		}
		other, err := postgres.NewCapacityRefreshDemands(f.ctx, f.roles["capacity-capture"], root)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := other.ReadCapacityRefreshDemands(f.ctx); err == nil {
			t.Fatal("a non-writer capacity role read demands")
		}
	}) {
		return
	}
	t.Run("non-additive-change-is-refused", func(t *testing.T) {
		changed := f.template
		changed.Policies = slices.Clone(f.template.Policies)
		budget := *changed.Policies[0].Budget
		budget.Hard.Bytes++
		changed.Policies[0].Budget = &budget
		changed.Policies[0].Resource.Generation, changed.Policies[0].Resource.SpecDigest = 2, artifact.Digest{32}
		f.template = changed
		o := f.workloadObservation(t, 0)
		if _, err := f.enrollments.ReadCapacityEnrollment(f.ctx, o); err == nil {
			t.Fatal("an edited hub policy kept the original enrollment")
		}
	})
}
