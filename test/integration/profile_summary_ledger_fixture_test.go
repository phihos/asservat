package integration

import (
	capacityapp "asservat.local/asservat/internal/application/capacity"
	executionapp "asservat.local/asservat/internal/application/execution"
	"asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/migrations"
	"context"
	"crypto/sha256"
	"errors"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	authapp "asservat.local/asservat/internal/application/authorization"
	captureapp "asservat.local/asservat/internal/application/capture"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	capture "asservat.local/asservat/internal/domain/capture"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
)

// Managed profile admission uses the real original capacity root and current
// permission/retention/grant adapters. Target and independent human identities
// are synthetic; this fixture does not invoke a workload profiler.
func admitQueryLedgerProfile(t *testing.T, f *capacitySQLFixture, root capacityapp.RootConfiguration, enrollment capacityapp.Enrollment) (captureAdmissionScenario, capture.Accepted, *postgres.APIContextExecutions) {
	t.Helper()
	ctx, admin, poolFor := f.ctx, f.admin, f.fixturePool
	s, publisher, _ := f.prepareManagedContext(t, root, enrollment, 60)
	in := s.a.Plan.Input
	in.Target.ExecutionClass, in.Capability.ExecutionClass = artifact.ContextAPIExecution, artifact.ContextAPIExecution
	in.Target.NodeUID, in.Target.NodeBootID, in.Target.Pin.NodeName = "", "", ""
	policies, err := s.retention.policies(ctx)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	in.Retention, err = privacy.Resolve(policies, privacy.Input{Target: in.Target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: "profile", AnchorAt: now}, now)
	if err != nil {
		t.Fatal(err)
	}
	c := planvalue.ProfileComposition{Components: []planvalue.ProfileComponent{{ID: "cpu", Profile: planvalue.ProfileRef{Catalog: "builtin", Name: "go-cpu", Version: "v1"}, Edits: []planvalue.ProfileEdit{{ActionID: "cpu", Field: "actionMaxBytes", Number: 1 << 20}}}}, MaxTotalBytes: 16 << 20, MaxDuration: "30s"}
	input := planvalue.RecorderInput{CaptureID: in.CaptureID, Executor: in.Executor, Target: in.Target, Composition: c, Retention: in.Retention, Deadline: now.Add(time.Minute), NodeRecorder: true}
	_, err = planning.CompileRecorder(input, nil, now)
	var needed planning.EndpointResolutionNeeded
	if !errors.As(err, &needed) {
		t.Fatal("endpoint query", err)
	}
	input.Endpoints = []targets.ProfileEndpointResolution{{Request: needed.Request, SourceKind: targets.ProfileEndpointTemplateBinding, SourceName: "go-pprof-loopback", AddressMode: "targetLoopback", Port: 6060, DeclaredPortName: "diagnostics", PathPolicy: "go-pprof/v1", DefinitionDigest: artifact.Digest{1}, EndpointDigest: artifact.Digest{2}, ResolvedAt: now}}
	reviewed, err := planning.CompileRecorder(input, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	p := capture.ContextPreview{ID: custodyID(), AssessmentID: custodyID(), AssessmentRulesDigest: planning.RecorderAssessmentRulesDigest(), RootID: s.a.RootID, InstallationID: s.a.Recovery.InstallationID, IssuerEpoch: s.a.Recovery.IssuerEpoch, CaptureID: in.CaptureID, CaseID: s.a.CaseID, OccurrenceID: s.a.OccurrenceID, ArtifactID: s.a.Registration.Location.ArtifactID, AttemptID: s.a.Registration.Location.AttemptID, Actor: in.Executor, ExecutionClass: artifact.ContextAPIExecution,
		Intent: capture.ContextIntent{Target: targets.WorkloadRequest{ClusterID: in.Target.Request.ClusterID, Namespace: in.Target.Request.Namespace.Name, Kind: in.Target.Request.Workload.Kind, Name: in.Target.Request.Workload.Name}, Composition: &c, RequestedSeconds: in.Retention.RequestedSeconds}, Target: in.Target.Request, Pin: in.Target.Pin,
		Storage: capture.ContextStorageSelection{StoreID: s.a.Registration.StoreID, AllocationID: s.a.Registration.AllocationID, PoolRevision: s.a.Registration.PoolRevision, AllocationRevision: s.a.Registration.AllocationRevision, BindingRevision: s.a.Storage.Revision}, Retention: reviewOf(in.Retention), Audience: s.a.Eligibility.DefaultAudience, CanonicalScope: reviewed.CanonicalScope, ScopeDigest: reviewed.ScopeDigest, CreatedAt: now, Deadline: input.Deadline}
	pools, _ := compiledOrdinaryHubPools(t, ctx, admin, poolFor)
	previews, err := postgres.NewContextPreviews(ctx, pools.ordinary, p.RootID)
	if err != nil {
		t.Fatal(err)
	}
	if err = previews.CreateContextPreview(ctx, p); err != nil {
		t.Fatal("profile preview", err)
	}
	grants, err := postgres.NewAccessGrants(ctx, pools.ordinary, p.RootID, s.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	g := authorization.Grant{ID: custodyID(), RootID: p.RootID, Kind: authorization.GrantAdHocCapture, PreviewID: p.ID, CaptureID: p.CaptureID, Target: in.Target.Target(), Requester: p.Actor, ExecutionDigest: p.ScopeDigest, Scope: p.CanonicalScope, Review: []byte(`{}`), DataClass: "raw", Reasons: []authorization.SensitiveReason{{ActionID: reviewed.Actions[0].ID, Code: planvalue.ReasonLiveProfile}}, Lifetime: time.Hour, Revision: 1}
	g.ReviewDigest = authapp.ReviewDigest(g, g.Review)
	g, _, err = grants.RequestGrant(ctx, authapp.StoredGrantRequest{Grant: g, IdempotencyKey: "profile-review", RequestDigest: sha256.Sum256([]byte("synthetic-profile-review"))}, s.a.Recovery)
	if err != nil {
		t.Fatal("profile review", err)
	}
	in.Deadline = input.Deadline
	in.Profile, err = planning.ProfileContextFromScope(c, in.Target.Request, reviewed.CanonicalScope)
	if err != nil {
		t.Fatal(err)
	}
	s.a.Plan, err = planning.CompileContext(in, now)
	if err != nil {
		t.Fatal(err)
	}
	s.a.SubmissionDigest = captureapp.ContextRequestDigest(p.ID)
	r := &s.a.Registration
	r.NativeLimit = 1 << 20
	r.AnchorAt = in.Retention.AnchorAt
	r.WriteUntil = in.Deadline
	r.ExpiresAt = in.Retention.ExpiresAt
	r.DeleteBy = in.Retention.DeleteBy
	if r.WriteUntil.After(r.ExpiresAt) {
		r.WriteUntil = r.ExpiresAt
	}
	if _, err = s.s.AdmitReviewedContext(ctx, p.ID, s.a); err == nil {
		t.Fatal("pending liveProfile grant admitted with optional recording approval off")
	}
	var charged int64
	if err = admin.QueryRow(ctx, "SELECT charged_bytes FROM custody_allocation WHERE id=$1", r.AllocationID).Scan(&charged); err != nil || charged != 0 {
		t.Fatal("pending review charged storage", charged, err)
	}
	reviewer := p.Actor
	reviewer.Subject = "synthetic-independent-profile-reviewer"
	g, _, err = grants.DecideGrant(ctx, authapp.GrantDecisionInput{GrantID: g.ID, Approve: true, Approver: reviewer, Reason: "synthetic profile review", ACR: "gold", AuthTime: time.Now().Add(-time.Second), IdempotencyKey: "profile-approve"}, s.a.Recovery)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := s.s.AdmitReviewedContext(ctx, p.ID, s.a)
	if err != nil {
		t.Fatal("approved profile admission", err)
	}
	if accepted.Expectation.Profile == nil || accepted.Expectation.Recording != nil || accepted.Expectation.DataClass != "raw" || accepted.Expectation.NativeType != artifact.PprofArtifact {
		t.Fatal("profile admitted with wrong shape")
	}

	if _, err = publisher.AcknowledgedCaptureIntent(ctx, accepted.CaptureID); err != nil {
		t.Fatal("managed profile capture intent", err)
	}
	execSQL, err := postgres.NewAPIContextExecutions(ctx, pools.ordinary, p.RootID, postgres.EffectTransactionGuards{Retention: s.retention.guard, Recovery: s.recovery.guard})
	if err != nil {
		t.Fatal(err)
	}
	return s, accepted, execSQL
}

// The target, process and native start observations are explicit fixture inputs.
// Preparation, start fencing and joined stored completion use the production SQL facets.
func startQueryLedgerProfile(t *testing.T, f *capacitySQLFixture, s captureAdmissionScenario, accepted capture.Accepted, execSQL *postgres.APIContextExecutions) (execution.APIExecution, func() executionapp.APIExecutionCheck) {
	t.Helper()
	process := execution.APIProcessBinding{NamespaceUID: custodyID(), AccountUID: custodyID(), PodUID: custodyID(), ProcessEpoch: custodyID(), StartupDigest: artifact.Digest{1}, ImageDigest: accepted.Expectation.CollectorImageDigest}
	refresh := func() executionapp.APIExecutionCheck {
		n := time.Now().UTC().Truncate(time.Microsecond)
		s.batch.ObservedAt, s.batch.FreshUntil, s.batch.Initial = n, n.Add(5*time.Second), nil
		if err := s.p.RefreshPermissions(f.ctx, s.batch); err != nil {
			t.Fatal(err)
		}
		i := s.a.Eligibility.VerifiedIdentity
		i.Scopes = append(append([]string(nil), i.Scopes...), "evidence:read")
		i.VerifiedAt, i.ValidUntil = n, n.Add(5*time.Second)
		recovery, err := s.recovery.reader.RecoveryState(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		work, err := execSQL.ReadAPIContextWork(f.ctx, accepted.CaptureID, i, recovery)
		if err != nil {
			t.Fatal(err)
		}
		projection, err := s.p.Permissions(f.ctx, s.a.Eligibility.Target)
		if err != nil {
			t.Fatal(err)
		}
		eligible := authorization.ContextEligibility(i, projection, s.a.Eligibility.Target, time.Now())
		policies, err := s.retention.policies(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		input := s.a.Plan.Input
		input.Retention, err = privacy.Resolve(policies, privacy.Input{Target: s.a.Eligibility.Target, PrivacyClass: "potentialPersonalData", EvidenceType: accepted.Expectation.Type().EvidenceType, RequestedSeconds: accepted.Expectation.RequestedAgeSeconds, AnchorAt: accepted.Expectation.Registration.AnchorAt}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		input.Target.ObservedAt, input.Target.FreshUntil = n, n.Add(5*time.Second)
		input.Capability.ObservedAt, input.Capability.FreshUntil = n, n.Add(5*time.Second)
		compiled, err := planning.CompileContext(input, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		process.InstallationID, process.ClusterID, process.IssuerEpoch = recovery.InstallationID, input.Target.Target().ClusterID, recovery.IssuerEpoch
		observation := execution.APIProcessObservation{Binding: process, CheckedAt: n, ValidUntil: n.Add(5 * time.Second)}
		until := n.Add(5 * time.Second)
		for _, d := range []time.Time{eligible.ValidUntil, compiled.ValidUntil, recovery.FreshUntil, observation.ValidUntil, accepted.Expectation.Registration.WriteUntil} {
			until = identity.Earlier(until, d)
		}
		check := executionapp.APIExecutionCheck{Work: work, Plan: compiled, Eligibility: eligible, Recovery: recovery, Process: observation, CheckedAt: n, ValidUntil: until.Truncate(time.Microsecond)}
		if !check.Valid(time.Now()) {
			t.Fatal("profile execution fixture invalid")
		}
		return check
	}
	check := refresh()
	original, first, err := execSQL.PrepareAPIExecution(f.ctx, check)
	if err != nil || !first {
		t.Fatal("profile source preparation", err)
	}
	bound, err := execSQL.BindAPIStart(f.ctx, check, original, execution.PreparedStart{ObjectUID: custodyID(), ResourceVersion: "1"})
	if err != nil {
		t.Fatal("profile source binding", err)
	}
	started, err := execSQL.RecordAPIStart(f.ctx, check, bound, execution.Disposition{ObjectUID: bound.ObjectUID, ResourceVersion: "2", Phase: execution.StartCommitted, CommittedAt: time.Now().UTC().Truncate(time.Microsecond), MayStart: true, ValidUntil: bound.Binding.NotAfter})
	if err != nil {
		t.Fatal("profile source start", err)
	}
	return started, refresh
}

func refuseRetainedProfileSummaryDowngrade(t *testing.T, f *queryLedgerFixture) {
	t.Helper()
	db := stdlib.OpenDB(*f.base.admin.Config().ConnConfig)
	defer db.Close()
	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.Files(), goose.WithDisableGlobalRegistry(true))
	if err != nil {
		t.Fatal(err)
	}
	head, err := provider.GetDBVersion(f.base.ctx)
	if err != nil || head < 127 {
		t.Fatal("summary rollback requires schema127 or newer", head, err)
	}
	// A retained verified byte count is a stronger rollback fence introduced
	// after summary queries. Never erase it to reach the older127 guard.
	stop, refusal := int64(127), "profile summary query history cannot be downgraded"
	if head >= 130 {
		var retainedLength bool
		if err = f.base.admin.QueryRow(f.base.ctx, "SELECT EXISTS(SELECT 1 FROM context_verification WHERE native_bytes IS NOT NULL)").Scan(&retainedLength); err != nil {
			t.Fatal("retained native-length observation", err)
		}
		if retainedLength {
			stop, refusal = 130, "retained native-length verification prevents rollback"
		}
	}
	if head >= 134 {
		var retainedTiming bool
		if err = f.base.admin.QueryRow(f.base.ctx, "SELECT EXISTS(SELECT 1 FROM context_verification WHERE acquisition_started_at IS NOT NULL)").Scan(&retainedTiming); err != nil {
			t.Fatal("retained acquisition-window observation", err)
		}
		if retainedTiming {
			stop, refusal = 134, "retained acquisition-window verification prevents rollback"
		}
	}
	// Exclude only133's nullable route column so the snapshot compares the
	// same immutable queries and spend across the supported schema prefix.
	snapshot := func(ctx context.Context) (string, error) {
		var b []byte
		err := f.base.admin.QueryRow(ctx, `SELECT jsonb_build_object('queries',(SELECT jsonb_agg(to_jsonb(q)-'baseline_allocation_id' ORDER BY q.id) FROM context_query q WHERE q.root_id=$1),'backing',(SELECT to_jsonb(b) FROM context_query_backing b WHERE b.root_id=$1),'allocations',(SELECT jsonb_agg(to_jsonb(a) ORDER BY a.id) FROM context_query_allocation a WHERE a.root_id=$1))`, f.base.input.PermissionRootID).Scan(&b)
		if err != nil {
			return "", err
		}
		if stop == 134 {
			var verification []byte
			if err = f.base.admin.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(v) ORDER BY capture_id) FROM context_verification v WHERE root_id=$1`, f.base.input.PermissionRootID).Scan(&verification); err != nil {
				return "", err
			}
			return string(b) + "\n" + string(verification), nil
		}
		if stop == 130 {
			var sizes []byte
			if err = f.base.admin.QueryRow(ctx, `SELECT jsonb_agg(jsonb_build_object('capture',capture_id,'bytes',native_bytes,'copies',encode(copies_digest,'hex')) ORDER BY capture_id) FROM context_verification WHERE root_id=$1`, f.base.input.PermissionRootID).Scan(&sizes); err != nil {
				return "", err
			}
			return string(b) + "\n" + string(sizes), nil
		}
		return string(b), nil
	}
	before, err := snapshot(f.base.ctx)
	if err != nil {
		t.Fatal("summary pre-rollback snapshot", err)
	}
	// Goose may have committed later Down migrations before the retained
	// source refuses. Repair that prefix on every exit, including Fatal/cancel.
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(f.base.ctx), 30*time.Second)
		defer cancel()
		if _, err := provider.UpTo(cleanup, head); err != nil {
			t.Error("restore schema after summary rollback", err)
			return
		}
		restored, err := provider.GetDBVersion(cleanup)
		if err != nil || restored != head {
			t.Error("summary rollback did not restore original schema head", restored, head, err)
		}
		after, err := snapshot(cleanup)
		if err != nil || after != before {
			t.Error("summary rollback restoration changed retained query/spend state", err)
		}
	}()
	if _, err = provider.DownTo(f.base.ctx, stop-1); err == nil || !strings.Contains(err.Error(), refusal) {
		t.Fatal("retained summary/source rollback", stop, err)
	}
	afterHead, err := provider.GetDBVersion(f.base.ctx)
	if err != nil || afterHead != stop {
		t.Fatal("refused rollback left unexpected schema prefix", afterHead, stop, err)
	}
	after, err := snapshot(f.base.ctx)
	if err != nil || after != before {
		t.Fatal("refused summary/source rollback changed query identity or spend", err)
	}
	t.Logf("retained summary/source rollback%d->%d refused by %s; query identity/limits/spend unchanged; original schema%d restoration readback follows", stop, stop-1, refusal, head)
}
