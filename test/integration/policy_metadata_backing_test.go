//go:build cgo && libpcap

package integration

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/pcap"
	app "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/privacy"
	"github.com/jackc/pgx/v5/pgxpool"
)

// One fresh, owned protected fixture for both admitted shapes. This qualifies only
// admission/permit/stored graph samples; no publication/native/physical-bloat/
// backup result is inferred, nor is the synthetic guard a native installer.
func TestPolicyMetadataBackingWithRealPostgres(t *testing.T) {
	withCapacityProducerFixture(t, func(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope fleet.InstallationWitnessScope, claim string, administration fleet.Administration, objects *objectstore.AuthorityObjects) {
		profile := nativeCapacityProfile()
		f := newCapacitySQLFixture(t, ctx, admin, address, tlsConfig, scope, claim, administration, objects, func(f *capacitySQLFixture) {
			policyMetadataProfile(&f.qualification, &f.template)
		})
		if _, err := f.producer.InitializeCapacity(ctx, f.input, f.protection); err != nil {
			t.Fatal("protected setup", err)
		}
		f.open(t)
		stop := f.keepFleetCurrent()
		defer func() {
			if err := stop(); err != nil {
				t.Error(err)
			}
		}()
		root, err := (&app.RootBackingCoordinator{Store: f.roots, Capture: f.captureRoots, Now: time.Now}).Reconcile(ctx, f.rootObservation(t))
		if err != nil {
			t.Fatal("protected root", err)
		}
		f.initializeManagedProcessing(t, root)
		enrollment, err := (&app.EnrollmentCoordinator{Store: f.enrollments, Capture: f.captureEnrollments, Accounts: f.accounts, Now: time.Now}).Reconcile(ctx, f.workloadObservation(t, 0))
		if err != nil {
			t.Fatal("protected workload", err)
		}
		var metadata app.RootMetadataQualification
		var raw []byte
		if err = admin.QueryRow(ctx, "SELECT qualification->'RootBacking'->'Metadata' FROM capacity_source WHERE root_id=$1", f.input.PermissionRootID).Scan(&raw); err != nil || json.Unmarshal(raw, &metadata) != nil {
			t.Fatal("accepted profile readback", err)
		}
		if metadata != f.qualification.RootBacking.Metadata || metadata.RecordRowBytes != profile.Metadata.RecordRowBytes || metadata.RecordWALBytes != profile.Metadata.RecordWALBytes || metadata.BackupCopies != profile.Backup.BackupCopies || metadata.WALCopies != profile.Backup.WALCopies {
			t.Fatal("actual protected metadata profile differs")
		}
		additional := []privacy.ScopedPolicy{}
		for i := 1; i < 64; i++ {
			p := capacityNativeRetentionPolicy()
			p.Name = fmt.Sprintf("retention-%054d", i)
			p.Policy.Revision.UID = p.Name
			p.Policy.Baseline = false
			p.Policy.Revision.Generation = 2147483647
			additional = append(additional, p)
		}
		seed, publisher, _ := f.prepareManagedContext(t, root, enrollment, 3600, additional...)
		for _, shape := range policyMetadataShapes(t) {
			t.Run(shape.name, func(t *testing.T) {
				s := seed
				s.batch = f.batch
				s.a.Plan.Input.CaptureID = custodyID()
				s.a.CaseID = custodyID()
				s.a.OccurrenceID = custodyID()
				s.a.Registration.Location.ArtifactID = custodyID()
				s.a.Registration.Location.AttemptID = custodyID()

				subjects := []cfg.Subject{{Kind: "Group", Issuer: "https://id.example.test", ID: "maintainers"}}
				for i := 1; i < shape.audience; i++ {
					subjects = append(subjects, cfg.Subject{Kind: "Group", Issuer: "https://id.example.test/" + policyMetadataText(900, "issuer"), ID: policyMetadataText(256, fmt.Sprint(i))})
				}
				opt := policyRecorderProtectedCase{Hub: f.roles["hub-runtime"], Admissions: s.s, Filters: pcap.NewCompiler(), Expression: shape.expression, Subjects: subjects, Intent: func(ctx context.Context, id string) error {
					_, err := publisher.AcknowledgedCaptureIntent(ctx, id)
					return err
				}}
				opt.Stored = func(in policyObservationRetirementInput) {
					e := in.Accepted.Expectation
					f.batch = in.Scenario.batch
					if e.Validate() != nil || len(e.Audience) != shape.audience || len(e.RetentionRules) != 64 {
						t.Fatal("actual SQL shape differs", len(e.Audience), len(e.RetentionRules))
					}
					b, _ := json.Marshal(e)
					ident, _ := json.Marshal(s.a.Eligibility.VerifiedIdentity)
					program, _ := json.Marshal(e.Recording.Filter.Program)
					var scopeBytes int
					if err := admin.QueryRow(ctx, "SELECT octet_length(scope_json) FROM context_capture WHERE root_id=$1 AND id=$2", s.a.RootID, in.Accepted.CaptureID).Scan(&scopeBytes); err != nil {
						t.Fatal("stored scope", err)
					}
					var stored []byte
					if err := admin.QueryRow(ctx, "SELECT expectation_json FROM context_capture WHERE root_id=$1 AND id=$2", s.a.RootID, in.Accepted.CaptureID).Scan(&stored); err != nil {
						t.Fatal("stored expectation", err)
					}
					var persisted artifact.ContextExpectation
					if json.Unmarshal(stored, &persisted) != nil {
						t.Fatal("stored expectation decode")
					}
					actual, _ := json.Marshal(persisted)
					if string(actual) != string(b) {
						t.Fatal("stored expectation differs from accepted output")
					}
					after := samplePolicyObservationGraph(t, ctx, admin, s.a.RootID, e.Registration.AllocationID, s.poolID)
					var recordBytes, accountBytes, fixedBytes int64
					for _, row := range after.Tables {
						lane := "separate-purpose/pending"
						switch row.Table {
						case "context_preview", "context_capture", "context_execution", "context_writer_completion", "policy_observation_session", "context_control_charge", "context_verification", "context_catalog", "context_case_locator", "capture_history_parameter", "retention_decision", "context_deletion_checkpoint":
							lane = "ordinary-record"
							recordBytes += row.TupleBytes
						case "policy_source", "policy_acceptance", "access_grant", "policy_grant_attachment", "policy_occurrence", "policy_pod_watermark", "policy_workload_window", "policy_suppression", "context_storage_binding", "context_control_account", "capture_history_quota":
							lane = "ordinary-account"
							accountBytes += row.TupleBytes
						case "permission_stream", "context_control_pool", "policy_grant_settings":
							lane = "ordinary-fixed"
							fixedBytes += row.TupleBytes
						case "authority_audit":
							lane = "authority-audit"
						case "custody_attempt", "custody_copy", "custody_event":
							lane = "evidence-custody"
						}
						t.Logf("shape=%s paidBy=%s table=%s rows=%d tuple=%d wholeRelationHeap=%d index=%d toast=%d", shape.name, lane, row.Table, row.Rows, row.TupleBytes, row.HeapBytes, row.IndexBytes, row.ToastBytes)
					}
					if recordBytes > metadata.RecordRowBytes || accountBytes > metadata.AccountRowBytes || fixedBytes > metadata.FixedRowBytes {
						t.Fatal("sampled ordinary tuple footprint exceeds accepted profile", recordBytes, accountBytes, fixedBytes)
					}
					var wal int64
					if err := admin.QueryRow(ctx, "SELECT pg_wal_lsn_diff($1::pg_lsn,$2::pg_lsn)::bigint", after.WAL, in.Before.WAL).Scan(&wal); err != nil || wal < 0 {
						t.Fatal("WAL sample", err)
					}
					t.Logf("shape=%s acceptedScope=%d acceptedExpectation=%d authorIdentity=%d programJSON=%d instructions=%d recordTuple=%d/%d accountTuple=%d/%d fixedTuple=%d/%d GLOBAL_FIXTURE_WAL=%d primaryRecordWALAllowance=%d backupCopies=%d WALCopies=%d; no lane subtraction, no publication/native/physical/bloat/backups proof", shape.name, scopeBytes, len(b), len(ident), len(program), len(e.Recording.Filter.Program), recordBytes, metadata.RecordRowBytes, accountBytes, metadata.AccountRowBytes, fixedBytes, metadata.FixedRowBytes, wal, metadata.RecordWALBytes, metadata.BackupCopies, metadata.WALCopies)
				}
				qualifyPolicyRecorderAdmission(t, ctx, admin, f.fixturePool, f.store, f.keys, func(*testing.T) captureAdmissionScenario { return s }, opt)
			})
		}
	})
}

func policyMetadataProfile(q *app.CapacityQualification, snapshot *app.CapacitySnapshot) {
	profile := nativeCapacityProfile()
	// Match the actual installed metadata/copy profile. The pre-existing
	// fixture still has THREE incident slots, explicitly not native's FOUR.
	(*q).RootBacking.AdmissionSeconds = profile.AdmissionSeconds
	metadata := &q.RootBacking.Metadata
	metadata.WALCopies = profile.Backup.WALCopies
	metadata.ConfigurationTransitions = profile.Metadata.ConfigurationTransitions
	// Keep exactly three records/native children. Bytes can cover PCAPNG;
	// objects remain the independent three-record ceiling (no row increase).
	bytes := (artifact.Registration{NativeLimit: artifact.RecordingNativeLimit}).ReservedBytes() * 3
	budget := (*snapshot).Policies[0].Budget
	budget.Protected.Bytes = bytes
	budget.Hard.Bytes = bytes
	budget.Context.Bytes = bytes
	budget.NamespaceMaximum.Bytes = bytes * budget.NamespaceAccounts
	(*snapshot).Pools[0].Budget.Slots[0].Protected.Bytes = bytes
}
