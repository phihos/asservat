package integration

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	capacity "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

// These are explicit fixture inputs for a newly qualified graph. Historical
// roots never acquire this marker or larger funding through a schema upgrade.
func profileCapacityFixtureFunding(q *capacity.CapacityQualification, source *capacity.CapacitySnapshot) {
	in := &q.RootBacking
	in.ContextHistory.ProfileProtocol = capacity.ProfileProtocolVersion
	in.RecordsPerAccount = 6
	in.Capture.RecordsPerAccount = 6
	in.Capture.Policy.MetadataSlots = in.Capture.Accounts * 6
	perBackup, perWAL := in.ContextHistory.Capture.SlotBacking(in.ContextHistory.CapturePurgeLeases)
	in.Capture.Policy.BackupReservedBytes = in.Capture.Policy.MetadataSlots * perBackup
	in.Capture.Policy.WALReservedBytes = in.Capture.Policy.MetadataSlots * perWAL
	in.ProcessingState.MaxCaptures = in.Accounts * 6
	in.ProcessingState.BackupBytes, in.ProcessingState.WALBytes, _ = in.ProcessingState.RequiredBytes()
	r := artifact.Registration{NativeLimit: artifact.MaxGoTraceBytes}
	stream := artifact.StreamingPlan{Registration: r}
	budget := capacity.BudgetAmount{Bytes: r.ReservedBytes() + stream.TemporaryBytes(), Objects: int64(5 + stream.PartLimit())}
	p := source.Policies[0].Budget
	p.Context, p.Protected, p.Hard = budget, budget, budget
	p.NamespaceMaximum = capacity.BudgetAmount{Bytes: in.Accounts * budget.Bytes, Objects: in.Accounts * budget.Objects}
	source.Pools[0].Budget.Slots[0].Protected = budget
}

func TestProfileCapacityProducerInputs(t *testing.T) {
	const id = "10000000-0000-4000-8000-000000000001"
	q, s := capacityNativeQualification(t, id, id, id, id, "profile-fixture")
	profileCapacityFixtureFunding(&q, &s)
	pool, err := capacity.CompileProtectedPoolPlan(s, s.Pools[0].Budget.Name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = capacity.CompileQualifiedRootBacking(q, pool); err != nil {
		t.Fatal("new profile root not funded", err)
	}
}

func TestProfileCapacityProducerWithRealPostgres(t *testing.T) {
	withCapacityProducerFixture(t, func(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope fleet.InstallationWitnessScope, claim string, administration fleet.Administration, objects *objectstore.AuthorityObjects) {
		f := newCapacitySQLFixture(t, ctx, admin, address, tlsConfig, scope, claim, administration, objects, func(f *capacitySQLFixture) { profileCapacityFixtureFunding(&f.qualification, &f.template) })
		if _, err := f.producer.InitializeCapacity(ctx, f.input, f.protection); err != nil {
			t.Fatal("profile root setup", err)
		}
		f.open(t)
		o := f.rootObservation(t)
		root, err := f.roots.ReserveCapacityRoot(ctx, o)
		if err != nil {
			t.Fatal("profile root reserve", err)
		}
		root, err = f.captureRoots.BackCapacityRoot(ctx, o, root)
		if err != nil {
			t.Fatal("profile capture backing", err)
		}
		if _, err = f.roots.PublishCapacityRoot(ctx, o, root); err != nil {
			t.Fatal("profile root publish", err)
		}
		observation := f.workloadObservation(t, 0)
		enrollment, err := (&capacity.EnrollmentCoordinator{Store: f.enrollments, Capture: f.captureEnrollments, Accounts: f.accounts, Now: time.Now}).Reconcile(ctx, observation)
		if err != nil {
			t.Fatal("profile workload graph", err)
		}
		expected, err := capacity.CompileContextProtocolBacking(f.template.Policies[0].Budget.Context, f.qualification.RootBacking.ContextHistory)
		if err != nil {
			t.Fatal(err)
		}
		var evidenceBytes, evidenceObjects, output, read, windows, keys, transitions int64
		if err = admin.QueryRow(ctx, `SELECT a.byte_limit,a.object_limit,d.output_limit,d.read_limit,c.window_limit,n.keys_limit,n.transitions_per_row FROM custody_allocation a JOIN download_allocation d ON d.id=$2 JOIN download_control_allocation c ON c.id=d.id JOIN download_native_backing n ON n.allocation_id=d.id WHERE a.id=$1`, enrollment.AllocationID, enrollment.DownloadAllocationID).Scan(&evidenceBytes, &evidenceObjects, &output, &read, &windows, &keys, &transitions); err != nil {
			t.Fatal(err)
		}
		if evidenceBytes != expected.Evidence.Bytes || evidenceObjects != expected.Evidence.Objects || output != expected.OutputBytes || read != expected.ReadBytes || windows != expected.Windows || keys != expected.NativeKeys || transitions != artifact.ProfileDownloadNativeTransitions {
			t.Fatalf("persisted graph underfunded: %d/%d output%d read%d windows%d keys%d transitions%d expected%+v", evidenceBytes, evidenceObjects, output, read, windows, keys, transitions, expected)
		}
		// Reserve an ordinary custody obligation without writing an object. Its
		// uncertain spend must survive the refused downgrade as well.
		f.assertLegacyAdmission(t, enrollment, true)
		// An actual Down must refuse the retained marked qualification atomically.
		snapshot := func() string {
			var raw []byte
			if err := admin.QueryRow(ctx, `SELECT jsonb_build_object('source',to_jsonb(s),'custody',to_jsonb(a),'download',to_jsonb(d),'native',to_jsonb(n)) FROM capacity_source s JOIN custody_allocation a ON a.id=$2 JOIN download_allocation d ON d.id=$3 JOIN download_native_backing n ON n.allocation_id=d.id WHERE s.root_id=$1`, f.input.PermissionRootID, enrollment.AllocationID, enrollment.DownloadAllocationID).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			var v any
			if json.Unmarshal(raw, &v) != nil {
				t.Fatal("snapshot unavailable")
			}
			return string(raw)
		}
		before := snapshot()
		db := stdlib.OpenDB(*admin.Config().ConnConfig)
		defer db.Close()
		provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.Files(), goose.WithDisableGlobalRegistry(true))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = provider.DownTo(ctx, 124); err == nil || !strings.Contains(err.Error(), "profile capacity rollback requires retirement of marked roots") {
			t.Fatal("retained profile graph did not refuse rollback at its exact guard", err)
		}
		if after := snapshot(); after != before {
			t.Fatal("refused rollback mutated identity, limits, spend or dates")
		}
		var head int64
		if err = admin.QueryRow(ctx, `SELECT max(version_id) FROM goose_db_version WHERE is_applied`).Scan(&head); err != nil || head != 125 {
			t.Fatal("rollback changed schema head", head, err)
		}
	})
}
