package integration

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/fleet"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

// Fund the ONE authored8MiB recording before original installation. The
// existing pod-status fixture funds three4KiB sources and cannot pay this
// source; no installed pool/allocation is enlarged after admission.
func packetLedgerFunding(t *testing.T, f *capacitySQLFixture) {
	t.Helper()
	bytes := (artifact.Registration{NativeLimit: artifact.RecordingNativeLimit}).ReservedBytes()
	policy := f.template.Policies[0].Budget
	policy.Protected.Bytes = max(policy.Protected.Bytes, bytes)
	policy.Hard.Bytes = max(policy.Hard.Bytes, bytes)
	policy.Context.Bytes = max(policy.Context.Bytes, bytes)
	policy.NamespaceMaximum.Bytes = policy.NamespaceAccounts * policy.Protected.Bytes
	f.template.Pools[0].Budget.Slots[0].Protected = policy.Protected
	pool, err := app.CompileProtectedPoolPlan(f.template, f.template.Pools[0].Resource.Name)
	if err != nil {
		t.Fatal("packet original pool", err)
	}
	if _, err = app.CompileQualifiedRootBacking(f.qualification, pool); err != nil {
		t.Fatal("packet original backing", err)
	}
}

func TestPacketSummaryOriginalFunding(t *testing.T) {
	q, source := capacityNativeQualification(t, custodyID(), custodyID(), custodyID(), custodyID(), "fixture-accounts-v1")
	f := &capacitySQLFixture{qualification: q, template: source}
	queryLedgerQualification(t, f)
	old := source.Policies[0].Budget.Protected.Bytes
	native := (artifact.Registration{NativeLimit: artifact.RecordingNativeLimit}).ReservedBytes()
	if old >= native {
		t.Fatal("baseline no longer demonstrates original packet funding gap", old, native)
	}
	packetLedgerFunding(t, f)
	if f.template.Policies[0].Budget.Protected.Bytes != native || f.template.Policies[0].Budget.Protected.Objects != 12 {
		t.Fatal("packet fixture changed unrelated funding")
	}
	t.Logf("original fixture only: 8MiB authored native reserves%dB versus pod-status%dB; preserve12objects and fund exact byte difference before installation", native, old)
}

// One pristine capacity root, real protected admission/start/publication and
// compiled hub/key process credentials. Native Job/Pod/token/issuer/join inputs
// are the shared lifecycle's synthetic observations, not installed evidence.
func TestPacketSummaryLifecycleWithRealServices(t *testing.T) {
	withCapacityProducerFixture(t, func(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope fleet.InstallationWitnessScope, claim string, administration fleet.Administration, objects *objectstore.AuthorityObjects) {
		t.Run("metadata-pcapng-compiled-lifecycle", func(t *testing.T) {
			withProtectedContextQueryLedger(t, ctx, admin, address, tlsConfig, scope, claim, administration, objects, qualifySharedProjectionLifecycle, false, false, false, true)
		})
	})
}

func admitQueryLedgerPacket(t *testing.T, f *capacitySQLFixture, root app.RootConfiguration, enrollment app.Enrollment) (captureAdmissionScenario, capture.Accepted, *postgres.APIContextExecutions) {
	t.Helper()
	s, publisher, _ := f.prepareManagedContext(t, root, enrollment, 60)
	in := s.a.Plan.Input
	in.Target.ExecutionClass, in.Capability.ExecutionClass = artifact.ContextAPIExecution, artifact.ContextAPIExecution
	in.Target.NodeUID, in.Target.NodeBootID, in.Target.Pin.NodeName = "", "", ""
	policies, err := s.retention.policies(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	in.Retention, err = privacy.Resolve(policies, privacy.Input{Target: in.Target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: "packetCapture", AnchorAt: in.Retention.AnchorAt}, now)
	if err != nil {
		t.Fatal(err)
	}
	composition := planvalue.ProfileComposition{Components: []planvalue.ProfileComponent{{ID: "net", Profile: planvalue.ProfileRef{Catalog: "builtin", Name: "network-connections", Version: "v1"}, Edits: []planvalue.ProfileEdit{{ActionID: "sample", Field: "packetFilter", Text: "tcp dst port 80"}, {ActionID: "sample", Field: "packetAfter", Text: "2s"}}}}, MaxTotalBytes: 16 << 20, MaxDuration: "20s"}
	reviewed, err := planning.CompileRecorder(planvalue.RecorderInput{CaptureID: in.CaptureID, Executor: in.Executor, Target: in.Target, Composition: composition, Retention: in.Retention, Deadline: in.Deadline, NodeRecorder: true}, recordingCompiler{}, now)
	if err != nil {
		t.Fatal(err)
	}
	in.Recorder, err = planning.RecorderContextFromScope(composition, reviewed.CanonicalScope)
	if err != nil {
		t.Fatal(err)
	}
	s.a.Plan, err = planning.CompileContext(in, now)
	if err != nil || s.a.Plan.ScopeDigest != reviewed.ScopeDigest {
		t.Fatal("reviewed packet plan", err)
	}
	s.a.Registration.NativeLimit = artifact.RecordingNativeLimit
	s.a.Registration.ExpiresAt, s.a.Registration.DeleteBy = in.Retention.ExpiresAt, in.Retention.DeleteBy
	accepted, err := s.s.AdmitContext(f.ctx, s.a)
	if err != nil {
		t.Fatal("managed metadata packet admission", err)
	}
	if accepted.Expectation.NativeType != artifact.PCAPNGArtifact || accepted.Expectation.DataClass != "metadata" || accepted.Expectation.Recording == nil {
		t.Fatal("packet accepted with wrong source")
	}
	if _, err = publisher.AcknowledgedCaptureIntent(f.ctx, accepted.CaptureID); err != nil {
		t.Fatal("packet intent audit", err)
	}
	executions, err := postgres.NewAPIContextExecutions(f.ctx, f.roles["hub-runtime"], s.a.RootID, postgres.EffectTransactionGuards{Retention: s.retention.guard, Recovery: s.recovery.guard})
	if err != nil {
		t.Fatal(err)
	}
	return s, accepted, executions
}

func refuseRetainedPacketSummaryDowngrade(t *testing.T, f *queryLedgerFixture) {
	t.Helper()
	db := stdlib.OpenDB(*f.base.admin.Config().ConnConfig)
	defer db.Close()
	p, err := goose.NewProvider(goose.DialectPostgres, db, migrations.Files(), goose.WithDisableGlobalRegistry(true))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := func() string {
		var b []byte
		if err := f.base.admin.QueryRow(f.base.ctx, `SELECT jsonb_build_object('queries',(SELECT jsonb_agg(to_jsonb(q)-ARRAY['invocation_key','request_digest'] ORDER BY q.id) FROM context_query q),'backing',(SELECT jsonb_agg(to_jsonb(b)) FROM context_query_backing b),'allocations',(SELECT jsonb_agg(to_jsonb(a) ORDER BY a.id) FROM context_query_allocation a),'keys',(SELECT jsonb_agg(to_jsonb(k) ORDER BY k.child_id) FROM context_query_key_binding k))`).Scan(&b); err != nil {
			t.Fatal(err)
		}
		if !json.Valid(b) {
			t.Fatal("invalid rollback snapshot")
		}
		return string(b)
	}
	beforePacketSnapshot := snapshot()
	originalHead, e := p.GetDBVersion(f.base.ctx)
	if e != nil {
		t.Fatal(e)
	}
	// Later additive migrations may commit their Down before the retained138
	// audit refuses. Restore that prefix, including the original predicate ACL.
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(f.base.ctx), 30*time.Second)
		defer stop()
		if _, e := p.UpTo(cleanup, originalHead); e != nil {
			t.Error("restore packet schema prefix", e)
			return
		}
		if originalHead >= 139 {
			restorePacketQueryFixturePredicate(t, cleanup, f)
		}
		if snapshot() != beforePacketSnapshot {
			t.Error("restored packet prefix changed retained state")
		}
	}()
	before := snapshot()
	if _, err = p.DownTo(f.base.ctx, 136); err == nil || !strings.Contains(err.Error(), "packet query history cannot be downgraded") {
		t.Fatal("retained packet downgrade", err)
	}
	head, err := p.GetDBVersion(f.base.ctx)
	if err != nil || head != 138 || snapshot() != before {
		t.Fatal("refused downgrade changed history/spend", head, err)
	}
	t.Logf("retained packet138→137 refused (same-tool audit); nullable later columns excluded from prefix snapshot; original schema%d restored on return", originalHead)
}

// Two OAuth clients of the SAME human retain distinct query actors but share
// the existing principal account. This uses actual compiled roles and the full
// same admitted-source/enrollment/native-key lifecycle twice, not seeded rows.
func TestPacketSummarySharedPrincipalLifecycleWithRealServices(t *testing.T) {
	withCapacityProducerFixture(t, func(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope fleet.InstallationWitnessScope, claim string, administration fleet.Administration, objects *objectstore.AuthorityObjects) {
		t.Run("same-human-two-clients", func(t *testing.T) {
			withProtectedContextQueryLedger(t, ctx, admin, address, tlsConfig, scope, claim, administration, objects, func(t *testing.T, f *queryLedgerFixture) {
				qualifySharedProjectionLifecycleClient(t, f, "console", 0)
				qualifySharedProjectionLifecycleClient(t, f, "fixture-other-client", 1)
				var accounts, clients, queries, allocated, expected int
				err := admin.QueryRow(ctx, `SELECT count(DISTINCT q.account_id),count(DISTINCT q.actor->>'ClientID'),count(*),max(p.allocated),sum(context_query_units(q.query->'Scope')) FROM context_query q JOIN context_query_principal p ON p.id=q.account_id AND p.root_id=q.root_id WHERE q.root_id=$1`, f.base.input.PermissionRootID).Scan(&accounts, &clients, &queries, &allocated, &expected)
				if err != nil || accounts != 1 || clients != 2 || queries != 2 || allocated != 4 || expected != 4 {
					t.Fatal("actual same-human account topology/charge", accounts, clients, queries, allocated, expected, err)
				}
				t.Logf("two actual clients, one human account: clients=%d accounts=%d queries=%d allocated=%d exact_account_units=%d", clients, accounts, queries, allocated, expected)
				if !installedPacketSummaryPrincipalAccounting(allocated, expected) {
					t.Fatal("installed fixture rejected actual correctly shared principal charge", allocated, expected)
				}
			}, false, false, false, true)
		})
	})
}
