//go:build cgo && libpcap

package integration

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/pcap"
	"asservat.local/asservat/internal/adapters/postgres"
	capacity "asservat.local/asservat/internal/application/capacity"
	captureapp "asservat.local/asservat/internal/application/capture"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/collector"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Actual protected capacity/account setup, encrypted policy acceptance audit,
// current SQL permission/retention/recovery and exact installed hub SQL grants.
// Workload/collector/administrator/native guard observations remain synthetic;
// this does not start a collector or establish installed source/Save acceptance.
func TestPolicySourceLedgerWithRealPostgres(t *testing.T) {
	withCapacityProducerFixture(t, func(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope fleet.InstallationWitnessScope, claim string, administration fleet.Administration, objects *objectstore.AuthorityObjects) {
		f := newCapacitySQLFixture(t, ctx, admin, address, tlsConfig, scope, claim, administration, objects)
		f.template.Policies[0].SourceResources = &capacity.SourceResourceLimits{Node: collector.PolicyLimits{SourceLimits: collector.SourceLimits{MaxActiveSources: 4, InputBytesPerSecond: 4 << 20, InputBurstBytes: 4 << 20}}, Workload: collector.SourceLimits{MaxActiveSources: 4, InputBytesPerSecond: 4 << 20, InputBurstBytes: 4 << 20}}
		if _, err := f.producer.InitializeCapacity(ctx, f.input, f.protection); err != nil {
			t.Fatal("actual protected setup", err)
		}
		f.open(t)
		stop := f.keepFleetCurrent()
		defer func() {
			if err := stop(); err != nil {
				t.Error(err)
			}
		}()
		root, err := (&capacity.RootBackingCoordinator{Store: f.roots, Capture: f.captureRoots, Now: time.Now}).Reconcile(ctx, f.rootObservation(t))
		if err != nil {
			t.Fatal("root backing", err)
		}
		f.initializeManagedProcessing(t, root)
		enrollment, err := (&capacity.EnrollmentCoordinator{Store: f.enrollments, Capture: f.captureEnrollments, Accounts: f.accounts, Now: time.Now}).Reconcile(ctx, f.workloadObservation(t, 0))
		if err != nil {
			t.Fatal("workload backing", err)
		}
		seed, _, _ := f.prepareManagedContext(t, root, enrollment, 3600)
		option := policyRecorderProtectedCase{Hub: f.roles["hub-runtime"], Admissions: seed.s, Filters: pcap.NewCompiler(), Expression: "tcp dst port 80", Subjects: []cfg.Subject{{Kind: "Group", Issuer: "https://id.example.test", ID: "maintainers"}}, Ongoing: true, PermissionsAccepted: func(batch cfg.PermissionBatch) { f.batch = policyRecorderCloneBatch(batch) }}
		option.SourceAccepted = func(t *testing.T, accepted policySourceAcceptedFixture) {
			s := accepted.Scenario
			ledger, err := postgres.NewPolicySources(ctx, f.roles["hub-runtime"], s.a.RootID, s.recovery.installation, postgres.EffectTransactionGuards{Recovery: s.recovery.guard, Retention: s.retention.guard})
			if err != nil {
				t.Fatal(err)
			}
			sourceID, fence := custodyID(), custodyID()
			var old captureapp.PolicySourceAdmission
			var initialCheck captureapp.PolicySourceCheck
			fresh := func(t *testing.T) captureapp.PolicySourceCheck {
				t.Helper()
				// Refresh existing observations only; immutable admission/acceptance,
				// original source identity, counters and hard policy end remain unchanged.
				_, recovery := f.fresh(t)
				if err := f.enrollments.RefreshCapacityEnrollment(ctx, f.workloadObservation(t, 0), enrollment); err != nil {
					t.Fatal("current storage binding", err)
				}
				n := time.Now().UTC().Truncate(time.Microsecond)
				src := accepted.Source
				src.ObservedAt = n
				src.FreshUntil = n.Add(30 * time.Second)
				if err := accepted.Sources.ObservePolicy(ctx, src); err != nil {
					t.Fatal("current accepted policy source", err)
				}
				retained, err := s.retention.policies(ctx)
				if err != nil {
					t.Fatal(err)
				}
				target := s.a.Plan.Input.Target
				target.ExecutionClass = artifact.ContextAPIExecution
				target.NodeUID, target.NodeBootID, target.Pin.NodeName = "", "", ""
				target.ObservedAt, target.FreshUntil = n, n.Add(5*time.Second)
				resolution, err := privacy.Resolve(retained, privacy.Input{Target: target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: "packetCapture", RequestedSeconds: 3600, AnchorAt: n}, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				policy := identity.Policy{Revision: identity.Revision{UID: "synthetic-settings", Generation: 1, Digest: [32]byte{1}}, Issuer: accepted.Authority.Creator.Issuer, ObservedAt: n, FreshUntil: n.Add(5 * time.Second), Clients: []identity.Client{{ID: accepted.Authority.Creator.ClientID, Kind: identity.Human, ClassQualified: true}}, EligibleGroups: []string{"maintainers"}, GroupsAtIssueQualified: true, GroupMaxAge: time.Minute}
				node := targets.PacketSourceObservation{PodUID: target.Pin.UID, NodeUID: custodyID(), BootID: custodyID(), CollectorPodUID: custodyID(), CollectorEpoch: custodyID(), ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}
				if old.Permit.Binding.SourceID != "" {
					node.NodeUID = old.Permit.Binding.NodeUID
					node.BootID = old.Permit.Binding.BootID
					node.CollectorPodUID = old.Permit.Binding.CollectorPodUID
					node.CollectorEpoch = old.Permit.Binding.CollectorEpoch
				}
				return captureapp.PolicySourceCheck{Policy: accepted.Compiled, Authority: accepted.Authority, Target: target, Node: node, Recovery: recovery, Retention: resolution, Settings: policy, SourceID: sourceID, Fence: fence, BytesPerSecond: 1 << 20, SourceSlots: 4, ObservedAt: n, ValidUntil: n.Add(5 * time.Second)}
			}
			count := func(t *testing.T) (int64, int64, int64, int64, int64) {
				t.Helper()
				var full, replay, observed, executions, captures int64
				if err := admin.QueryRow(ctx, "SELECT a.charged_full,a.charged_replay,p.observed_bytes_spent,p.executions_spent,(SELECT count(*) FROM context_capture WHERE root_id=$1) FROM context_control_account a,policy_acceptance p WHERE a.root_id=$1 AND a.allocation_id=$2 AND p.id=$3", s.a.RootID, enrollment.AllocationID, accepted.Record.Record.ID).Scan(&full, &replay, &observed, &executions, &captures); err != nil {
					t.Fatal(err)
				}
				return full, replay, observed, executions, captures
			}
			beforeFull, beforeReplay, _, beforeExecutions, beforeCaptures := count(t)
			t.Run("initial-source-pays-real-control-unit-no-capture", func(t *testing.T) {
				initialCheck = fresh(t)
				initialCheck.Initial = true
				initialCheck.InitialCredit = 1 << 20
				old, err = ledger.AdmitSource(ctx, initialCheck)
				if err != nil {
					t.Fatal("initial source admission", err)
				}
				full, replay, observed, executions, captures := count(t)
				if !old.First || full != beforeFull+1 || replay != beforeReplay+1 || observed != initialCheck.InitialCredit || executions != beforeExecutions || captures != beforeCaptures {
					t.Fatal("source charge graph differs", full, replay, observed, executions, captures)
				}
				if old.Permit.HardUntil.After(accepted.Authority.NotAfter) || old.Permit.Binding.SourceID != sourceID || !old.Permit.Startable(time.Now()) {
					t.Fatal("invalid original source bounds")
				}
			})
			if old.Permit.Binding.SourceID == "" {
				return
			}
			t.Run("uncertain-initial-replay-keeps-exact-grant", func(t *testing.T) {
				replay, err := ledger.AdmitSource(ctx, initialCheck)
				if err != nil {
					t.Fatal(err)
				}
				if replay.First || replay.Permit != old.Permit {
					t.Fatal("initial replay rewrote first leaf/start/credit")
				}
			})
			t.Run("quiet-renewal-no-source-row-update", func(t *testing.T) {
				var before, after string
				if err := admin.QueryRow(ctx, "SELECT xmin::text FROM policy_recording_source WHERE root_id=$1 AND id=$2", s.a.RootID, sourceID).Scan(&before); err != nil {
					t.Fatal(err)
				}
				in := fresh(t)
				in.ExpectedCredit = old.Permit.Credit
				var walBefore, walAfter string
				if err := admin.QueryRow(ctx, "SELECT pg_current_wal_insert_lsn()::text").Scan(&walBefore); err != nil {
					t.Fatal(err)
				}
				began := time.Now()
				var next captureapp.PolicySourceAdmission
				for range 8 {
					next, err = ledger.AdmitSource(ctx, in)
					if err != nil {
						t.Fatal(err)
					}
				}
				elapsed := time.Since(began)
				if err := admin.QueryRow(ctx, "SELECT pg_current_wal_insert_lsn()::text").Scan(&walAfter); err != nil {
					t.Fatal(err)
				}
				var wal, tuple, heap, index int64
				if err := admin.QueryRow(ctx, "SELECT pg_wal_lsn_diff($1::pg_lsn,$2::pg_lsn)::bigint", walAfter, walBefore).Scan(&wal); err != nil || wal < 0 {
					t.Fatal("actual global WAL sample", wal, err)
				}
				if err := admin.QueryRow(ctx, "SELECT COALESCE(sum(pg_column_size(s)),0)::bigint,pg_relation_size('policy_recording_source'),pg_indexes_size('policy_recording_source') FROM policy_recording_source s WHERE root_id=$1", s.a.RootID).Scan(&tuple, &heap, &index); err != nil {
					t.Fatal(err)
				}
				metadata := f.qualification.RootBacking.Metadata
				if tuple > metadata.RecordRowBytes {
					t.Fatal("source tuple exceeds its real ordinary record unit", tuple, metadata.RecordRowBytes)
				}
				t.Logf("quietTransactions=8 totalWall=%s meanWall=%s GLOBAL_FIXTURE_WAL=%d sourceTuple=%d wholeSourceRelationHeap=%d wholeSourceRelationIndexes=%d acceptedRecordRowBytes=%d acceptedRecordWALBytes=%d; global WAL includes concurrent fleet maintenance, no subtraction or full-lifetime/backup proof", elapsed, elapsed/8, wal, tuple, heap, index, metadata.RecordRowBytes, metadata.RecordWALBytes)
				if err := admin.QueryRow(ctx, "SELECT xmin::text FROM policy_recording_source WHERE root_id=$1 AND id=$2", s.a.RootID, sourceID).Scan(&after); err != nil {
					t.Fatal(err)
				}
				if before != after || next.Permit.Credit != old.Permit.Credit || !next.Permit.StartedAt.Equal(old.Permit.StartedAt) || !next.Permit.HardUntil.Equal(old.Permit.HardUntil) || !next.Permit.IssuedAt.After(old.Permit.IssuedAt) {
					t.Fatal("quiet grant mutated durable row or original bounds")
				}
				old = next
			})
			t.Run("positive-credit-exact-once-quiet-parent-exhaustion", func(t *testing.T) {
				in := fresh(t)
				in.ExpectedCredit = old.Permit.Credit
				in.AdditionalCredit = accepted.Authority.Limits.MaxObservedBytes
				next, err := ledger.AdmitSource(ctx, in)
				if err != nil {
					t.Fatal(err)
				}
				if next.Permit.Credit != accepted.Authority.Limits.MaxObservedBytes {
					t.Fatal("positive credit was not clamped to remaining parent")
				}
				replay, err := ledger.AdmitSource(ctx, in)
				if err != nil {
					t.Fatal(err)
				}
				if replay.Permit.Credit != next.Permit.Credit {
					t.Fatal("uncertain positive-credit replay debited again")
				}
				in = fresh(t)
				in.ExpectedCredit = next.Permit.Credit
				in.AdditionalCredit = 1
				quiet, err := ledger.AdmitSource(ctx, in)
				if err != nil || quiet.Permit.Credit != next.Permit.Credit {
					t.Fatal("parent exhaustion blocked prepaid quiet renewal", err)
				}
				_, _, observed, executions, captures := count(t)
				if observed != next.Permit.Credit || executions != beforeExecutions || captures != beforeCaptures {
					t.Fatal("credit/capture accounting changed")
				}
				old = quiet
			})
			t.Run("expired-and-other-process-refuse-without-spend", func(t *testing.T) {
				in := fresh(t)
				in.ExpectedCredit = old.Permit.Credit
				in.ValidUntil = in.ObservedAt
				if _, err := ledger.AdmitSource(ctx, in); err == nil {
					t.Fatal("expired check admitted")
				}
				in = fresh(t)
				in.ExpectedCredit = old.Permit.Credit
				in.Node.CollectorEpoch = custodyID()
				if _, err := ledger.AdmitSource(ctx, in); err == nil {
					t.Fatal("another process inherited source")
				}
			})
			t.Run("terminal-clock-quarantine-and-no-refund", func(t *testing.T) {
				start := time.Now().UTC()
				// Existing duty can request a terminal transition, but cannot backdate
				// its clock or the original thirty-second slot quarantine.
				if _, err := f.roles["hub-runtime"].Exec(ctx, "UPDATE policy_recording_source SET ended_at=started_at WHERE root_id=$1 AND id=$2", s.a.RootID, sourceID); err != nil {
					t.Fatal(err)
				}
				var ended time.Time
				var released *time.Time
				if err := admin.QueryRow(ctx, "SELECT ended_at,slot_released_at FROM policy_recording_source WHERE root_id=$1 AND id=$2", s.a.RootID, sourceID).Scan(&ended, &released); err != nil || ended.Before(start) || released != nil {
					t.Fatal("terminal timestamp backdated", ended, released, err)
				}
				if _, err := ledger.SweepSources(ctx); err != nil {
					t.Fatal(err)
				}
				if err := admin.QueryRow(ctx, "SELECT slot_released_at FROM policy_recording_source WHERE root_id=$1 AND id=$2", s.a.RootID, sourceID).Scan(&released); err != nil || released != nil {
					t.Fatal("quarantine released early", err)
				}
				in := fresh(t)
				in.ExpectedCredit = old.Permit.Credit
				if _, err := ledger.AdmitSource(ctx, in); !errors.Is(err, value.ErrConflict) {
					t.Fatal("terminal source revived", err)
				}
				remaining := time.Until(ended.Add(30 * time.Second))
				if remaining > 0 {
					timer := time.NewTimer(remaining + time.Millisecond)
					select {
					case <-ctx.Done():
						timer.Stop()
						t.Fatal(ctx.Err())
					case <-timer.C:
					}
				}
				if _, err := ledger.SweepSources(ctx); err != nil {
					t.Fatal(err)
				}
				if err := admin.QueryRow(ctx, "SELECT slot_released_at FROM policy_recording_source WHERE root_id=$1 AND id=$2", s.a.RootID, sourceID).Scan(&released); err != nil || released == nil || released.Before(ended.Add(30*time.Second)) {
					t.Fatal("actual quarantine not observed", released, err)
				}
				full, replay, observed, executions, captures := count(t)
				if full != beforeFull+1 || replay != beforeReplay+1 || observed != old.Permit.Credit || executions != beforeExecutions || captures != beforeCaptures {
					t.Fatal("terminal transition refunded or fabricated work")
				}
			})
		}
		qualifyPolicyRecorderAdmission(t, ctx, admin, f.fixturePool, f.store, f.keys, func(*testing.T) captureAdmissionScenario { return seed }, option)
	})
}
