package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/packets"
	"asservat.local/asservat/internal/adapters/postgres"
	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Actual reviewed raw capture admission/publication and compiled hub/key roles.
// The workload packet generator, Pod/Job/issuer and native join remain synthetic.
func TestRawPacketSummaryLifecycleWithRealServices(t *testing.T) {
	withCapacityProducerFixture(t, func(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope fleet.InstallationWitnessScope, claim string, administration fleet.Administration, objects *objectstore.AuthorityObjects) {
		t.Run("raw-pcapng-compiled-lifecycle", func(t *testing.T) {
			withProtectedContextQueryLedger(t, ctx, admin, address, tlsConfig, scope, claim, administration, objects, qualifyRawPacketSummaryLifecycle, false, false, false, true, true)
		})
	})
}

func syntheticRawPacketSummaryRecording(t *testing.T, started, end time.Time) []byte {
	t.Helper()
	rec, err := packets.NewRawRecorder(recordingProgram, 1<<20, started, "synthetic", packets.RawLimits{Snaplen: 96, TCP: manualRawTCPCap})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		ip := []byte{0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2}
		tcp := make([]byte, 20)
		binary.BigEndian.PutUint16(tcp[:2], 40000)
		binary.BigEndian.PutUint16(tcp[2:4], 80)
		tcp[12] = 5 << 4
		payload := []byte(strings.Repeat("SYNTHETIC-RAW-PAYLOAD", 5))
		binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)+len(tcp)+len(payload)))
		frame := append(append(append([]byte{0, 1, 2, 3, 4, 5, 0, 1, 2, 3, 4, 6, 8, 0}, ip...), tcp...), payload...)
		rec.Add(frame, uint32(len(frame)), started.Add(time.Duration(i)*time.Microsecond))
	}
	out, c, err := rec.Close(end, 0)
	if err != nil || c.Retained != 50 {
		t.Fatal("raw fixture packets", c, err)
	}
	return append([]byte(nil), out...)
}

func refuseRetainedRawPacketSummaryDowngrade(t *testing.T, f *queryLedgerFixture) {
	t.Helper()
	// The shared metadata fixture checks the same minimized-audit conservative
	// rollback fence and all retained query/key/allocation snapshots at138.
	refuseRetainedPacketSummaryDowngrade(t, f)
}

func qualifyRawPacketSummaryLifecycle(t *testing.T, f *queryLedgerFixture) {
	t.Helper()
	snapshot := func() string {
		var b []byte
		if err := f.base.admin.QueryRow(f.base.ctx, `SELECT coalesce(jsonb_agg(to_jsonb(g) ORDER BY id),'[]'::jsonb) FROM access_grant g WHERE root_id=$1`, f.base.input.PermissionRootID).Scan(&b); err != nil || !json.Valid(b) {
			t.Fatal("grant snapshot", err)
		}
		return string(b)
	}
	before := snapshot()
	routes, err := postgres.NewContextCaseReads(f.base.ctx, f.base.roles["hub-runtime"], f.base.input.PermissionRootID, f.scenario.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	who := f.scenario.a.Eligibility.VerifiedIdentity
	who.Scopes = []string{"evidence:read"}
	now := time.Now().UTC().Truncate(time.Microsecond)
	who.VerifiedAt, who.ValidUntil = now, now.Add(5*time.Second)
	recovery, err := f.scenario.recovery.reader.RecoveryState(f.base.ctx)
	if err != nil {
		t.Fatal(err)
	}
	e := f.published.Expectation
	route, err := routes.ResolvePacketProjectionRoute(f.base.ctx, e.CaseID, e.Registration.Location.ArtifactID, who, recovery)
	if err != nil || route.NativeType != artifact.RawPCAPNGArtifact || route.PodUID != e.PodUID {
		t.Fatal("same-read raw native route", route.NativeType, err)
	}
	qualifySharedProjectionLifecycle(t, f)
	if after := snapshot(); after != before {
		t.Fatal("ordinary raw summary changed any acquisition/raw/native grant or spend")
	}
	t.Log("raw source preserved; ordinary fixed summary leaves every grant and spend byte-exact, no native session; same bounded route lookup exposes only raw native discriminator")
	// Only after the ordinary-query grant snapshots, revoke the ORIGINAL
	// acquisition review and prove later executor reads still check it.
	f.refresh(t)
	who = f.scenario.a.Eligibility.VerifiedIdentity // Original acquisition identity, not the read-only summary identity.
	n := time.Now().UTC().Truncate(time.Microsecond)
	who.VerifiedAt, who.ValidUntil = n, n.Add(5*time.Second)
	recovery, err = f.scenario.recovery.reader.RecoveryState(f.base.ctx)
	if err != nil {
		t.Fatal(err)
	}
	executionSQL, err := postgres.NewAPIContextExecutions(f.base.ctx, f.base.roles["hub-runtime"], f.base.input.PermissionRootID, postgres.EffectTransactionGuards{Retention: f.scenario.retention.guard, Recovery: f.scenario.recovery.guard})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = executionSQL.ReadAPIContextWork(f.base.ctx, e.CaptureUID, who, recovery); err != nil {
		t.Fatal("original acquisition grant live control", err)
	}
	var grantID string
	var revision int64
	if err = f.base.admin.QueryRow(f.base.ctx, `SELECT id,revision FROM access_grant WHERE root_id=$1 AND capture_id=$2`, f.base.input.PermissionRootID, e.CaptureUID).Scan(&grantID, &revision); err != nil {
		t.Fatal(err)
	}
	grants, err := postgres.NewAccessGrants(f.base.ctx, f.base.roles["hub-runtime"], f.base.input.PermissionRootID, f.scenario.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	revoked, _, err := grants.RevokeGrant(f.base.ctx, authapp.GrantRevocationInput{GrantID: grantID, Revoker: who.Principal, ExpectedRevision: revision, IdempotencyKey: "raw-fixture-revoke-after-query"}, recovery)
	if err != nil || revoked.RevokedAt.IsZero() {
		t.Fatal("original raw grant positive revocation", err)
	}
	_, err = executionSQL.ReadAPIContextWork(f.base.ctx, e.CaptureUID, who, recovery)
	var step interface{ FixedStep() string }
	phase := ""
	if err != nil && errors.As(err, &step) {
		phase, _, _ = strings.Cut(step.FixedStep(), "/")
	}
	if phase != "approval" {
		t.Fatal("revoked raw grant bypassed current executor approval", err)
	}
	t.Logf("original raw acquisition grant live-read control then explicit positive revocation: later API work refuses at approval with require-all still false; full_stage=%s; no new capture or authority", step.FixedStep())

}

func TestRawPacketSummaryManagedPayload(t *testing.T) {
	start := time.Now().UTC()
	end := start.Add(time.Millisecond)
	native := syntheticRawPacketSummaryRecording(t, start, end)
	if !bytes.Contains(native, []byte("SYNTHETIC-RAW-PAYLOAD")) {
		t.Fatal("managed source was silently sanitized")
	}
	if count, err := packets.CheckRaw(bytes.NewReader(native), packets.RawLimits{Snaplen: 96, TCP: manualRawTCPCap}); err != nil || count != 50 {
		t.Fatal("actual raw canonical check", count, err)
	}
	e := artifact.ContextExpectation{NativeType: artifact.RawPCAPNGArtifact, DataClass: "raw", Registration: artifact.Registration{NativeLimit: artifact.RecordingNativeLimit}, Recording: &artifact.Recording{Profile: "rawPackets", Snaplen: 96, ProtocolSnaplen: &artifact.RecordingProtocolSnaplen{TCP: manualRawTCPCap}}}
	summary, err := packets.SummarizePCAPNG(context.Background(), bytes.NewReader(native), e, start, end)
	if err != nil || !summary.Valid() || summary.Packets != 50 || summary.UnclassifiedPackets == nil || *summary.UnclassifiedPackets != 0 {
		t.Fatal("raw metadata summary", summary.Packets, err)
	}
	output, err := json.Marshal(summary)
	if err != nil || bytes.Contains(output, []byte("SYNTHETIC-RAW-PAYLOAD")) {
		t.Fatal("raw payload escaped summary", err)
	}
}

func rawPacketSummaryComposition(t testing.TB, target targets.Request) planvalue.ProfileComposition {
	t.Helper()
	definition, e := manualRawProfileDefinition()
	if e != nil {
		t.Fatal(e)
	}
	document, e := json.Marshal(map[string]any{"name": manualRawProfileName, "version": manualRawProfileVersion, "definition": definition})
	if e != nil {
		t.Fatal(e)
	}
	ref := planvalue.ProfileRef{Catalog: "namespace", Name: manualRawProfileName, Version: manualRawProfileVersion}
	return planvalue.ProfileComposition{Components: []planvalue.ProfileComponent{{ID: "net", Profile: ref, Edits: []planvalue.ProfileEdit{{ActionID: "sample", Field: "packetFilter", Text: "tcp dst port 80"}, {ActionID: "sample", Field: "actionExecutionMode", Text: "onTrigger"}, {ActionID: "sample", Field: "packetBefore", Text: "0s"}, {ActionID: "sample", Field: "packetAfter", Text: "2s"}}}}, Resolved: []planvalue.CatalogProfile{{Ref: ref, SourceClusterID: target.ClusterID, SourceNamespaceUID: target.Namespace.UID, SourceUID: "synthetic-raw-profile", Document: document, Enabled: true}}, MaxTotalBytes: 16 << 20, MaxDuration: "20s"}
}

// The exact composition used by SQL admission must compile before starting a
// service lab. A namespace profile retains its ongoing default unless the
// caller explicitly supplies the same finite edits as the installed raw path.
func TestRawPacketSummaryManagedAdmissionPlan(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	in := policyRecorderOfflineAdmission(t, now).Plan.Input
	in.Executor = identity.Principal{Issuer: "https://id.example.test", Subject: "fixture", ClientID: "console", Kind: identity.Human}
	c := rawPacketSummaryComposition(t, in.Target.Request)
	p, err := planning.CompileRecorder(planvalue.RecorderInput{CaptureID: in.CaptureID, Executor: in.Executor, Target: in.Target, Composition: c, Retention: in.Retention, Deadline: now.Add(time.Minute), NodeRecorder: true}, recordingCompiler{}, now)
	if err != nil {
		t.Fatal("exact managed raw admission producer", err)
	}
	if len(p.Actions) != 1 || p.Actions[0].ExecutionMode != "onTrigger" || p.Actions[0].Before != "0s" || p.Approval == nil || p.Approval.DataClass != "raw" || p.Approval.ObservationLimits == nil || !planning.AcceptableRecorder(p).Acceptable() {
		t.Fatal("managed raw source lost required approval/observation authority")
	}
	r, _, err := planning.RecordingFor(p)
	if err != nil || r.Profile != "rawPackets" || r.DurationMillis != 2000 || r.Snaplen != 96 || r.ProtocolSnaplen == nil || r.ProtocolSnaplen.TCP != manualRawTCPCap {
		t.Fatal("managed raw source finite bounds", r, err)
	}
	in.Recorder, err = planning.RecorderContextFromScope(c, p.CanonicalScope)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := planning.CompileContext(in, now)
	if err != nil || compiled.ScopeDigest != p.ScopeDigest {
		t.Fatal("actual context producer mismatch", err)
	}
}
