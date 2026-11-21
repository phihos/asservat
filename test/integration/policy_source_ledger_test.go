//go:build cgo && libpcap

package integration

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/pcap"
	"asservat.local/asservat/internal/adapters/postgres"
	captureapp "asservat.local/asservat/internal/application/capture"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Selected before acceptance: 31s content plus the existing 1s deletion budget
// fits the original 60s fixture backing and the builtin 30s ring.
const policySourceFixtureRetentionSeconds = int64(31)

// Actual protected capacity/account setup, encrypted policy acceptance audit,
// current SQL permission/retention and exact installed hub SQL grants.
// Workload/collector/administrator/native guard observations remain synthetic;
// this does not start a collector or establish installed source/Save acceptance.
func TestPolicySourceLedgerWithRealPostgres(t *testing.T) {
	withCapacityProducerFixture(t, func(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope fleet.InstallationWitnessScope, claim string, objects *objectstore.Store) {
		f := newCapacitySQLFixture(t, ctx, admin, address, tlsConfig, scope, claim, objects)
		root, enrollment := f.setup(t)
		seed, _, _ := f.prepareManagedContext(t, root, enrollment, policySourceFixtureRetentionSeconds)
		option := policyRecorderProtectedCase{Hub: f.roles["hub-runtime"], Admissions: seed.s, Filters: pcap.NewCompiler(), Expression: "tcp dst port 80", Subjects: []cfg.Subject{{Kind: "Group", Issuer: "https://id.example.test", ID: "maintainers"}}, Ongoing: true, Retention: strconv.FormatInt(policySourceFixtureRetentionSeconds, 10) + "s", PermissionsAccepted: func(batch cfg.PermissionBatch) { f.batch = policyRecorderCloneBatch(batch) }}
		option.SourceAccepted = func(t *testing.T, accepted policySourceAcceptedFixture) {
			s := accepted.Scenario
			ledger, err := postgres.NewPolicySources(ctx, f.roles["hub-runtime"], s.a.RootID, s.recovery.installation)
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
				f.refreshBase(t)
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
				resolution, err := privacy.Resolve(retained, privacy.Input{Target: target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: "packetCapture", RequestedSeconds: policySourceFixtureRetentionSeconds, AnchorAt: n}, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				node := targets.PacketSourceObservation{PodUID: target.Pin.UID, NodeUID: custodyID(), BootID: custodyID(), CollectorPodUID: custodyID(), CollectorEpoch: custodyID(), ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}
				if old.Permit.Binding.SourceID != "" {
					node.NodeUID = old.Permit.Binding.NodeUID
					node.BootID = old.Permit.Binding.BootID
					node.CollectorPodUID = old.Permit.Binding.CollectorPodUID
					node.CollectorEpoch = old.Permit.Binding.CollectorEpoch
				}
				return captureapp.PolicySourceCheck{Policy: accepted.Compiled, Authority: accepted.Authority, Target: target, Node: node, Retention: resolution, SourceID: sourceID, Fence: fence, BytesPerSecond: 1 << 20, SourceSlots: 4, ObservedAt: n, ValidUntil: n.Add(5 * time.Second)}
			}
			count := func(t *testing.T) (int64, int64, int64) {
				t.Helper()
				var observed, executions, captures int64
				if err := admin.QueryRow(ctx, "SELECT p.observed_bytes_spent,p.executions_spent,(SELECT count(*) FROM context_capture WHERE root_id=$1) FROM policy_acceptance p WHERE p.id=$2", s.a.RootID, accepted.Record.Record.ID).Scan(&observed, &executions, &captures); err != nil {
					t.Fatal(err)
				}
				return observed, executions, captures
			}
			_, beforeExecutions, beforeCaptures := count(t)
			t.Run("initial-source-pays-real-control-unit-no-capture", func(t *testing.T) {
				initialCheck = fresh(t)
				initialCheck.Initial = true
				initialCheck.InitialCredit = 1 << 20
				sourceCall, endSourceCall := context.WithDeadline(ctx, initialCheck.ValidUntil)
				defer endSourceCall()
				diagnostics := func(diagnosticCtx context.Context, originalCheck captureapp.PolicySourceCheck) error {
					// Closed fixture readback, before any source mutation. Keep
					// using the original input so a representation mismatch is
					// observed rather than silently normalized away.
					current, persisted, readErr := accepted.Reader.AcceptedPolicyRecord(diagnosticCtx, accepted.Authority.PolicyUID)
					diagnosticErr := readErr
					diagnosticAuthority := originalCheck.Authority
					if readErr == nil {
						diagnosticAuthority = current.Authority
					}
					t.Logf("source_accepted_readable=%t", readErr == nil)
					scopeMatches := readErr == nil && captureapp.RecorderPolicyScopeDigest(diagnosticAuthority.PolicyUID, persisted.IntentVersion, accepted.Source.CollectionDigest, accepted.Compiled, diagnosticAuthority.NamespaceUID, diagnosticAuthority.WorkloadUID, diagnosticAuthority.Delegation, diagnosticAuthority.Owners, diagnosticAuthority.Actions, diagnosticAuthority.Limits) == diagnosticAuthority.ScopeDigest
					t.Logf("source_accepted_readback authority_exact=%t issued_instant=%t expiry_instant=%t current_scope=%t", readErr == nil && reflect.DeepEqual(diagnosticAuthority, accepted.Authority), readErr == nil && diagnosticAuthority.IssuedAt.Equal(originalCheck.Authority.IssuedAt), readErr == nil && diagnosticAuthority.NotAfter.Equal(originalCheck.Authority.NotAfter), scopeMatches)

					return diagnosticErr
				}
				old, err = policySourceFixtureAdmit(sourceCall, initialCheck, diagnostics, ledger.AdmitSource, func(ok bool) { t.Logf("source_diagnostics_readable=%t", ok) })
				if err != nil {
					t.Fatal("initial source admission", err)
				}
				observed, executions, captures := count(t)
				if !old.First || observed != initialCheck.InitialCredit || executions != beforeExecutions || captures != beforeCaptures {
					t.Fatal("source charge graph differs", observed, executions, captures)
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
				observed, executions, captures := count(t)
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
				observed, executions, captures := count(t)
				if observed != old.Permit.Credit || executions != beforeExecutions || captures != beforeCaptures {
					t.Fatal("terminal transition refunded or fabricated work")
				}
			})
		}
		qualifyPolicyRecorderAdmission(t, ctx, admin, f.fixturePool, f.store, f.keys, func(*testing.T) captureAdmissionScenario { return seed }, option)
	})
}

// This local contract uses the same original capacity recipe, real compiler and
// privacy resolver as the external fixture; it performs no provider operations.
func TestPolicySourceFixtureFitsOriginalBacking(t *testing.T) {
	start := time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)
	root, installation := custodyID(), custodyID()
	backing := capacityNativeBacking(root, installation, "synthetic-version")
	if backing.AdmissionSeconds != 60 {
		t.Fatal("original fixture backing changed")
	}
	until := start.Add(time.Duration(backing.AdmissionSeconds) * time.Second)
	raw := publicPolicySpec(t, authorization.AcceptedPolicyAuthority{ClusterID: custodyID()})
	var authored map[string]any
	if err := json.Unmarshal(raw, &authored); err != nil {
		t.Fatal(err)
	}
	authored["retention"] = strconv.FormatInt(policySourceFixtureRetentionSeconds, 10) + "s"
	component := authored["profileComposition"].(map[string]any)["components"].([]any)[0].(map[string]any)
	for _, entry := range component["overrides"].([]any) {
		edit := entry.(map[string]any)
		if edit["field"] == "actionExecutionMode" {
			edit["value"] = "ongoing"
		}
		if edit["field"] == "packetBefore" {
			edit["value"] = "10s"
		}
	}
	raw, err := json.Marshal(authored)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := captureapp.CompilePolicyWithRecorders(t.Context(), targets.Request{}, raw, planning.ContextRecipeName, planning.RecipeDigest(), policySourceCompile(pcap.NewCompiler()))
	if err != nil || compiled.Recorder == nil {
		t.Fatal("actual source fixture compiler", err)
	}
	age, err := time.ParseDuration(compiled.Recorder.Action.RingMaxAge)
	if err != nil {
		t.Fatal(err)
	}
	policy := capacityNativeRetentionPolicy()
	policy.Policy.DefaultSeconds = policySourceFixtureRetentionSeconds
	target := authorization.Target{ClusterID: custodyID(), NamespaceUID: custodyID(), WorkloadUID: custodyID(), PodUID: custodyID()}
	resolve := func(at time.Time) privacy.Resolution {
		set := privacy.PolicySet{Target: target, Revision: policy.Policy.Revision, Policies: []privacy.Policy{policy.Policy}}
		r, e := privacy.Resolve(set, privacy.Input{Target: target, PrivacyClass: "potentialPersonalData", EvidenceType: "packetCapture", AnchorAt: at, RequestedSeconds: policySourceFixtureRetentionSeconds}, at)
		if e != nil {
			t.Fatal(e)
		}
		return r
	}
	// Twenty seconds is a controlled setup allowance, not a measured promise.
	// Retention and the real 30s quarantine overlap; neither extends this root.
	at := start.Add(20 * time.Second)
	r := resolve(at)
	if r.RequestedSeconds != compiled.RetentionSeconds || r.ExpiresAt.Sub(r.AnchorAt) < age || r.DeleteBy.After(until) || at.Add(30*time.Second).After(until) {
		t.Fatalf("fixture exceeds original backing: requested=%ds effective=%s ring=%s delete=%s root=%s", r.RequestedSeconds, r.ExpiresAt.Sub(r.AnchorAt), age, r.DeleteBy.Sub(start), until.Sub(start))
	}
	late := resolve(until.Add(-time.Duration(policySourceFixtureRetentionSeconds) * time.Second))
	if !late.DeleteBy.After(until) {
		t.Fatal("late request no longer reproduces original backing refusal")
	}
}

// The fixture's clock intentionally removes monotonic data and uses UTC SQL
// precision. Exercise JSON storage roundtripping without assuming that two
// equal instants necessarily have the same Go representation.
func TestPolicySourceFixtureAuthorityJSONRepresentation(t *testing.T) {
	at := time.Now().UTC().Truncate(time.Microsecond)
	authority := authorization.AcceptedPolicyAuthority{InstallationID: custodyID(), PolicyUID: custodyID(), Creator: identity.Principal{Issuer: "https://id.example.test", Subject: "fixture", ClientID: "console", Kind: identity.Human}, IssuedAt: at, NotAfter: at.Add(time.Hour), Owners: []artifact.AudienceAssignment{{Kind: "Group", Issuer: "https://id.example.test", SubjectID: "maintainers", Role: "workload-maintainer", BasisKind: "AccessBinding", BasisUID: custodyID(), AssignmentID: custodyID(), BasisDigest: artifact.Digest{1}}}, Actions: []string{"packetCapture"}, Limits: authorization.AutomationLimits{MaxExecutions: 10, MaxBytes: 64 << 20, MaxObservedBytes: 1 << 30}}
	raw, err := json.Marshal(authority)
	if err != nil {
		t.Fatal(err)
	}
	var persisted authorization.AcceptedPolicyAuthority
	if err = json.Unmarshal(raw, &persisted); err != nil {
		t.Fatal(err)
	}
	if !authority.IssuedAt.Equal(persisted.IssuedAt) || !authority.NotAfter.Equal(persisted.NotAfter) || !reflect.DeepEqual(authority, persisted) {
		t.Fatal("fixture UTC/microsecond authority JSON representation differs")
	}
}

// A diagnostic failure must never replace or suppress the original operation.
func policySourceFixtureAdmit(ctx context.Context, in captureapp.PolicySourceCheck, diagnostics func(context.Context, captureapp.PolicySourceCheck) error, admit func(context.Context, captureapp.PolicySourceCheck) (captureapp.PolicySourceAdmission, error), logAvailable func(bool)) (captureapp.PolicySourceAdmission, error) {
	diagnosticErr := diagnostics(ctx, in)
	logAvailable(diagnosticErr == nil)
	return admit(ctx, in)
}

func TestPolicySourceFixtureDiagnosticFailurePreservesOriginalAdmission(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(strconv.FormatBool(failed), func(t *testing.T) {
			deadline := time.Now().Add(5 * time.Second)
			ctx, end := context.WithDeadline(context.Background(), deadline)
			defer end()
			original := captureapp.PolicySourceCheck{SourceID: custodyID(), Fence: custodyID(), ObservedAt: deadline.Add(-5 * time.Second), ValidUntil: deadline, Initial: true, InitialCredit: 1 << 20}
			called := 0
			available := true
			diagnosticFailure := errors.New("fixture diagnostic unavailable")
			wantErr := value.ErrChanged
			_, gotErr := policySourceFixtureAdmit(ctx, original, func(observed context.Context, in captureapp.PolicySourceCheck) error {
				if observed != ctx || !reflect.DeepEqual(in, original) {
					t.Fatal("diagnostic replaced original request")
				}
				if failed {
					return diagnosticFailure
				}
				return nil
			}, func(admitted context.Context, in captureapp.PolicySourceCheck) (captureapp.PolicySourceAdmission, error) {
				called++
				until, ok := admitted.Deadline()
				if admitted != ctx || !ok || !until.Equal(deadline) || !reflect.DeepEqual(in, original) {
					t.Fatal("original admission input/deadline changed")
				}
				return captureapp.PolicySourceAdmission{}, wantErr
			}, func(ok bool) { available = ok })
			if called != 1 || available == failed || !errors.Is(gotErr, wantErr) {
				t.Fatal("diagnostic changed original admission execution/result", called, available, gotErr)
			}
		})
	}
}
