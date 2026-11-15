//go:build cgo && libpcap

package integration

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"testing"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/pcap"
	app "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/capture"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"github.com/jackc/pgx/v5/pgxpool"
)

// One fresh, owned protected fixture for both admitted shapes. This qualifies only
// admission/permit/stored graph samples; no publication/native/physical-bloat/
// backup result is inferred, nor is the synthetic guard a native installer.
func TestPolicyMetadataBackingWithRealPostgres(t *testing.T) {
	withCapacityProducerFixture(t, func(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope fleet.InstallationWitnessScope, claim string, administration fleet.Administration, objects *objectstore.AuthorityObjects) {
		profile := installedMetadataProfile
		f := newCapacitySQLFixture(t, ctx, admin, address, tlsConfig, scope, claim, administration, objects, func(f *capacitySQLFixture) {
			policyMetadataProfile(&f.qualification, &f.values)
		})
		root, enrollment := f.setup(t)
		stop := f.keepFleetCurrent()
		defer func() {
			if err := stop(); err != nil {
				t.Error(err)
			}
		}()
		var metadata app.RootMetadataQualification
		var raw []byte
		if err := admin.QueryRow(ctx, "SELECT qualification->'RootBacking'->'Metadata' FROM capacity_settings WHERE root_id=$1", f.input.PermissionRootID).Scan(&raw); err != nil || json.Unmarshal(raw, &metadata) != nil {
			t.Fatal("accepted profile readback", err)
		}
		if metadata != f.qualification.RootBacking.Metadata || metadata.RecordRowBytes != profile.RecordRowBytes || metadata.RecordWALBytes != profile.RecordWALBytes || metadata.BackupCopies != profile.BackupCopies || metadata.WALCopies != profile.WALCopies {
			t.Fatal("actual protected metadata profile differs")
		}
		additional := policyMetadataRetention(t, f.input.ControlClusterID, 63)
		seed, publisher, _ := f.prepareManagedContext(t, root, enrollment, 3600, additional...)
		for _, shape := range policyMetadataShapes(t) {
			if !t.Run(shape.name, func(t *testing.T) {
				s := seed
				s.batch = policyRecorderCloneBatch(f.batch)
				s.a = policyMetadataRecorderAdmission(s.a)

				subjects := []cfg.Subject{{Kind: "Group", Issuer: "https://id.example.test", ID: "maintainers"}}
				for i := 1; i < shape.audience; i++ {
					subjects = append(subjects, cfg.Subject{Kind: "Group", Issuer: "https://id.example.test/" + policyMetadataText(900, "issuer"), ID: policyMetadataText(256, fmt.Sprint(i))})
				}
				opt := policyRecorderProtectedCase{Hub: f.roles["hub-runtime"], Admissions: s.s, Filters: pcap.NewCompiler(), Expression: shape.expression, Subjects: subjects, Intent: func(ctx context.Context, id string) error {
					_, err := publisher.AcceptedCaptureIntent(ctx, id)
					return err
				}}
				opt.PermissionsAccepted = func(batch cfg.PermissionBatch) { f.batch = batch }
				opt.Stored = func(in policyObservationRetirementInput) {
					e := in.Accepted.Expectation
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
					var recordBytes, recordDelta, occupied, accountBytes, fixedBytes int64
					before := map[string]policyObservationGraphTable{}
					for _, row := range in.Before.Tables {
						before[row.Table] = row
					}
					for _, row := range after.Tables {
						lane := "separate-purpose/pending"
						switch row.Table {
						case "policy_occurrence", "context_preview", "context_capture", "context_execution", "context_writer_completion", "policy_observation_session", "context_control_charge", "context_verification", "context_catalog", "context_case_locator", "capture_history_parameter", "retention_decision", "context_deletion_checkpoint":
							lane = "ordinary-record"
							recordBytes += row.TupleBytes
							delta := row.TupleBytes - before[row.Table].TupleBytes
							if delta < 0 {
								t.Fatal("ordinary record tuple sample moved backwards", row.Table)
							}
							recordDelta += delta
							if row.Table == "context_capture" {
								occupied = row.Rows
							}
						case "policy_source", "policy_acceptance", "access_grant", "policy_grant_attachment", "policy_pod_watermark", "policy_workload_window", "policy_suppression", "context_storage_binding", "context_control_account", "capture_history_quota":
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
					if occupied < 1 || recordDelta > metadata.RecordRowBytes || recordBytes > occupied*metadata.RecordRowBytes || accountBytes > metadata.AccountRowBytes || fixedBytes > metadata.FixedRowBytes {
						t.Fatal("sampled ordinary tuple footprint exceeds accepted profile", recordBytes, accountBytes, fixedBytes)
					}
					var wal int64
					if err := admin.QueryRow(ctx, "SELECT pg_wal_lsn_diff($1::pg_lsn,$2::pg_lsn)::bigint", after.WAL, in.Before.WAL).Scan(&wal); err != nil || wal < 0 {
						t.Fatal("WAL sample", err)
					}
					t.Logf("shape=%s acceptedScope=%d acceptedExpectation=%d authorIdentity=%d programJSON=%d instructions=%d newRecordTuple=%d/%d cumulativeRecordTuple=%d/%d occupiedRecords=%d accountTuple=%d/%d fixedTuple=%d/%d GLOBAL_FIXTURE_WAL=%d primaryRecordWALAllowance=%d backupCopies=%d WALCopies=%d; no lane subtraction, no publication/native/physical/bloat/backups proof", shape.name, scopeBytes, len(b), len(ident), len(program), len(e.Recording.Filter.Program), recordDelta, metadata.RecordRowBytes, recordBytes, occupied*metadata.RecordRowBytes, occupied, accountBytes, metadata.AccountRowBytes, fixedBytes, metadata.FixedRowBytes, wal, metadata.RecordWALBytes, metadata.BackupCopies, metadata.WALCopies)
				}
				qualifyPolicyRecorderAdmission(t, ctx, admin, f.fixturePool, f.store, f.keys, func(*testing.T) captureAdmissionScenario { return s }, opt)
			}) {
				return
			}
		}
	})
}

// installedMetadataProfile holds the installed metadata/copy values.
var installedMetadataProfile = struct {
	AdmissionSeconds, RecordRowBytes, RecordWALBytes, BackupCopies, WALCopies, ConfigurationTransitions int64
}{AdmissionSeconds: 86400, RecordRowBytes: 128 << 10, RecordWALBytes: 8 << 20, BackupCopies: 2, WALCopies: 3, ConfigurationTransitions: 4096}

func policyMetadataProfile(q *app.CapacityQualification, values *app.CapacityValues) {
	profile := installedMetadataProfile
	// Match the actual installed metadata/copy profile. The pre-existing
	// fixture still has THREE incident slots, explicitly not native's FOUR.
	(*q).RootBacking.AdmissionSeconds = profile.AdmissionSeconds
	metadata := &q.RootBacking.Metadata
	metadata.WALCopies = profile.WALCopies
	metadata.ConfigurationTransitions = profile.ConfigurationTransitions
	// Keep exactly three records/native children. Bytes can cover PCAPNG;
	// objects remain the independent three-record ceiling (no row increase).
	bytes := (artifact.Registration{NativeLimit: artifact.RecordingNativeLimit}).ReservedBytes() * 3
	values.ShareBytes, values.LimitBytes = bytes, bytes
	values.EvidenceBytes = max(values.EvidenceBytes, values.ReserveBytes+capacityNativeAccounts*bytes)
}

// Convert one NEW pod-status seed into a NEW packet case before compilation.
// The enrolled allocation and original anchor/retention remain unchanged.
func policyMetadataRecorderAdmission(a capture.Admission) capture.Admission {
	a.Registration.NativeLimit = artifact.RecordingNativeLimit
	a.Plan.Input.CaptureID = custodyID()
	a.CaseID = custodyID()
	a.OccurrenceID = custodyID()
	a.Registration.Location.ArtifactID = custodyID()
	a.Registration.Location.AttemptID = custodyID()
	return a
}
