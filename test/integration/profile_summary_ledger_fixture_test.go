package integration

import (
	"crypto/sha256"
	"errors"
	"reflect"
	"testing"
	"time"

	executionapp "asservat.local/asservat/internal/application/execution"
	"asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/identity"

	"asservat.local/asservat/internal/adapters/postgres"
	authapp "asservat.local/asservat/internal/application/authorization"
	captureapp "asservat.local/asservat/internal/application/capture"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	capture "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/collector"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
)

// Managed profile admission uses the real original capacity root and current
// permission/retention/grant adapters. Target and independent human identities
// are synthetic; this fixture does not invoke a workload profiler.
func admitQueryLedgerProfile(t *testing.T, f *capacitySQLFixture, root capacityRoot, enrollment capacityEnrollment, rawPacket ...bool) (captureAdmissionScenario, capture.Accepted, *postgres.APIContextExecutions) {
	t.Helper()
	ctx, admin, poolFor := f.ctx, f.admin, f.fixturePool
	raw := len(rawPacket) > 0 && rawPacket[0]
	rawSyscall := len(rawPacket) > 1 && rawPacket[1]
	isLogs := len(rawPacket) > 2 && rawPacket[2]
	evidenceType := "profile"
	if raw {
		evidenceType = "packetCapture"
	}
	if rawSyscall {
		evidenceType = "syscallTrace"
	}
	if isLogs {
		evidenceType = "logs"
	}
	s, publisher, _ := f.prepareManagedContext(t, root, enrollment, 60)
	in := s.a.Plan.Input
	in.Target.ExecutionClass, in.Capability.ExecutionClass = artifact.ContextAPIExecution, artifact.ContextAPIExecution
	in.Target.NodeUID, in.Target.NodeBootID, in.Target.Pin.NodeName = "", "", ""
	policies, err := s.retention.policies(ctx)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	in.Retention, err = privacy.Resolve(policies, privacy.Input{Target: in.Target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: evidenceType, AnchorAt: now}, now)
	if err != nil {
		t.Fatal(err)
	}
	c := planvalue.ProfileComposition{Components: []planvalue.ProfileComponent{{ID: "cpu", Profile: planvalue.ProfileRef{Catalog: "builtin", Name: "go-cpu", Version: "v1"}, Edits: []planvalue.ProfileEdit{{ActionID: "cpu", Field: "actionMaxBytes", Number: 1 << 20}}}}, MaxTotalBytes: 16 << 20, MaxDuration: "30s"}
	input := planvalue.RecorderInput{CaptureID: in.CaptureID, Executor: in.Executor, Target: in.Target, Composition: c, Retention: in.Retention, Deadline: now.Add(time.Minute), NodeRecorder: true}
	var reviewed planvalue.RecorderPlan
	if isLogs {
		c = logsQueryComposition()
		input.Composition, input.RequireApproval = c, true
		reviewed, err = planning.CompileRecorder(input, nil, now)
	} else if rawSyscall {
		c = manualArgumentSQLComposition(t, in.Target)
		input.Composition = c
		reviewed, err = planning.CompileRecorder(input, installedArgumentsCompiler{}, now)
	} else if raw {
		c = rawPacketSummaryComposition(t, in.Target.Request)
		input.Composition = c
		reviewed, err = planning.CompileRecorder(input, recordingCompiler{}, now)
	} else {
		_, err = planning.CompileRecorder(input, nil, now)
		var needed planning.EndpointResolutionNeeded
		if !errors.As(err, &needed) {
			t.Fatal("endpoint query", err)
		}
		input.Endpoints = []targets.ProfileEndpointResolution{{Request: needed.Request, SourceKind: targets.ProfileEndpointTemplateBinding, SourceName: "go-pprof-loopback", AddressMode: "targetLoopback", Port: 6060, DeclaredPortName: "diagnostics", PathPolicy: "go-pprof/v1", DefinitionDigest: artifact.Digest{1}, EndpointDigest: artifact.Digest{2}, ResolvedAt: now}}
		reviewed, err = planning.CompileRecorder(input, nil, now)
	}
	if err != nil {
		t.Fatal("reviewed source", err)
	}

	p := capture.ContextPreview{ID: custodyID(), AssessmentID: custodyID(), AssessmentRulesDigest: planning.RecorderAssessmentRulesFor(reviewed.Actions), RootID: s.a.RootID, InstallationID: s.recovery.installation, CaptureID: in.CaptureID, CaseID: s.a.CaseID, OccurrenceID: s.a.OccurrenceID, ArtifactID: s.a.Registration.Location.ArtifactID, AttemptID: s.a.Registration.Location.AttemptID, Actor: in.Executor, ExecutionClass: artifact.ContextAPIExecution,
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
	grants, err := postgres.NewAccessGrants(ctx, pools.ordinary, p.RootID, s.recovery.installation)
	if err != nil {
		t.Fatal(err)
	}
	g := authorization.Grant{ID: custodyID(), RootID: p.RootID, Kind: authorization.GrantAdHocCapture, PreviewID: p.ID, CaptureID: p.CaptureID, Target: in.Target.Target(), Requester: p.Actor, ExecutionDigest: p.ScopeDigest, Scope: p.CanonicalScope, Review: []byte(`{}`), DataClass: "raw", Reasons: []authorization.SensitiveReason{{ActionID: reviewed.Actions[0].ID, Code: planvalue.ReasonLiveProfile}}, Lifetime: time.Hour, Revision: 1}
	if raw || rawSyscall || isLogs {
		g.Reasons = reviewed.Approval.Reasons
	}
	g.ReviewDigest = authapp.ReviewDigest(g, g.Review)
	g, _, err = grants.RequestGrant(ctx, authapp.StoredGrantRequest{Grant: g, IdempotencyKey: "profile-review", RequestDigest: sha256.Sum256([]byte("synthetic-profile-review"))})
	if err != nil {
		t.Fatal("profile review", err)
	}
	in.Deadline = input.Deadline
	if isLogs {
		in.Logs = &planvalue.LogsContext{Composition: c, RequireApproval: true}
	} else if raw || rawSyscall {
		in.Recorder, err = planning.RecorderContextFromScope(c, reviewed.CanonicalScope)
	} else {
		in.Profile, err = planning.ProfileContextFromScope(c, in.Target.Request, reviewed.CanonicalScope)
	}
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
	if raw || rawSyscall || isLogs {
		r.NativeLimit = artifact.RecordingNativeLimit
	}
	if isLogs {
		r.NativeLimit = artifact.LogNativeLimit
	}
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
	g, _, err = grants.DecideGrant(ctx, authapp.GrantDecisionInput{GrantID: g.ID, Approve: true, Approver: reviewer, Reason: "synthetic profile review", ACR: "gold", AuthTime: time.Now().Add(-time.Second), IdempotencyKey: "profile-approve"})
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := s.s.AdmitReviewedContext(ctx, p.ID, s.a)
	if err != nil {
		t.Fatal("approved profile admission", err)
	}
	if isLogs {
		if accepted.Expectation.NativeType != artifact.LogsArtifact || accepted.Expectation.Logs == nil || accepted.Expectation.DataClass != "raw" {
			t.Fatal("logs admitted wrong shape")
		}
	} else if rawSyscall {
		if accepted.Expectation.NativeType != artifact.SyscallArgumentsArtifact || accepted.Expectation.Recording == nil || accepted.Expectation.Recording.Arguments == nil || accepted.Expectation.DataClass != "raw" {
			t.Fatal("rawsyscall admitted with wrong shape")
		}
	} else if raw {
		if accepted.Expectation.Recording == nil || accepted.Expectation.Recording.Profile != "rawPackets" || accepted.Expectation.NativeType != artifact.RawPCAPNGArtifact || accepted.Expectation.DataClass != "raw" {
			t.Fatal("raw admitted with wrong shape")
		}
	} else if accepted.Expectation.Profile == nil || accepted.Expectation.Recording != nil || accepted.Expectation.DataClass != "raw" || accepted.Expectation.NativeType != artifact.PprofArtifact {
		t.Fatal("profile admitted with wrong shape")
	}

	if _, err = publisher.AcceptedCaptureIntent(ctx, accepted.CaptureID); err != nil {
		t.Fatal("managed profile capture intent", err)
	}
	execSQL, err := postgres.NewAPIContextExecutions(ctx, pools.ordinary, p.RootID, s.recovery.installation)
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
		s.batch.ObservedAt, s.batch.FreshUntil = n, n.Add(5*time.Second)
		if err := s.p.RefreshPermissions(f.ctx, s.batch); err != nil {
			t.Fatal(err)
		}
		i := s.a.Eligibility.VerifiedIdentity
		i.Scopes = append(append([]string(nil), i.Scopes...), "evidence:read")
		i.VerifiedAt, i.ValidUntil = n, n.Add(5*time.Second)
		work, err := execSQL.ReadAPIContextWork(f.ctx, accepted.CaptureID, i)
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
		process.InstallationID, process.ClusterID, process.IssuerEpoch = s.recovery.installation, input.Target.Target().ClusterID, s.recovery.observation.issuer
		observation := execution.APIProcessObservation{Binding: process, CheckedAt: n, ValidUntil: n.Add(5 * time.Second)}
		until := n.Add(5 * time.Second)
		for _, d := range []time.Time{eligible.ValidUntil, compiled.ValidUntil, observation.ValidUntil, accepted.Expectation.Registration.WriteUntil} {
			until = identity.Earlier(until, d)
		}
		check := executionapp.APIExecutionCheck{Work: work, Plan: compiled, Eligibility: eligible, Process: observation, CheckedAt: n, ValidUntil: until.Truncate(time.Microsecond)}
		if !check.Valid(time.Now()) {
			t.Fatal("profile execution fixture invalid")
		}
		return check
	}
	check := refresh()
	var original execution.APIExecution
	var first bool
	var err error
	if accepted.Expectation.NativeType == artifact.SyscallArgumentsArtifact {
		source := targets.PacketSourceObservation{PodUID: accepted.Expectation.PodUID, NodeUID: custodyID(), BootID: custodyID(), CollectorPodUID: custodyID(), CollectorEpoch: custodyID(), ObservedAt: check.Plan.Input.Target.ObservedAt, FreshUntil: check.ValidUntil}
		var permit collector.ArgumentObservationPermit
		original, first, permit, err = execSQL.PrepareArgumentRecording(f.ctx, check, source)
		if err == nil && (!permit.ValidFinite(time.Now()) || permit.ByteCredit <= 0 || permit.EventCredit <= 0) {
			t.Fatal("raw syscall finite observation preparation")
		}
		if err == nil {
			replay, again, prior, e := execSQL.PrepareArgumentRecording(f.ctx, check, source)
			if e != nil || again || !reflect.DeepEqual(replay, original) || prior != permit {
				t.Fatal("argument preparation replay changed original", e)
			}
		}
	} else if accepted.Expectation.NativeType == artifact.RawPCAPNGArtifact {
		// Raw acquisition uses the existing metered companion, as the production
		// API executor does. Node/process observations remain explicit synthetic input.
		source := targets.PacketSourceObservation{PodUID: accepted.Expectation.PodUID, NodeUID: custodyID(), BootID: custodyID(), CollectorPodUID: custodyID(), CollectorEpoch: custodyID(), ObservedAt: check.Plan.Input.Target.ObservedAt, FreshUntil: check.ValidUntil}
		var permit collector.ObservationPermit
		original, first, permit, err = execSQL.PreparePolicyRecording(f.ctx, check, source)
		if err == nil && (!permit.ValidFinite(time.Now()) || permit.Credit <= 0 || permit.Duration != 2*time.Second) {
			t.Fatal("raw observation preparation lost original credit/bounds")
		}
		if err == nil {
			replay, again, prior, e := execSQL.PreparePolicyRecording(f.ctx, check, source)
			if e != nil || again || !reflect.DeepEqual(replay, original) || !reflect.DeepEqual(prior, permit) {
				t.Fatal("raw preparation replay changed execution/observation debit", e)
			}
			var sessions, spent int64
			if e = f.admin.QueryRow(f.ctx, `SELECT count(*),coalesce(sum(s.spent),0) FROM policy_observation_session p JOIN adhoc_observation_spend s ON s.root_id=p.root_id AND s.grant_id=p.grant_id WHERE p.root_id=$1 AND p.capture_id=$2`, s.a.RootID, accepted.CaptureID).Scan(&sessions, &spent); e != nil || sessions != 1 || spent != permit.Credit {
				t.Fatal("raw single prepaid observation", sessions, spent, permit.Credit, e)
			}
		}
	} else {
		original, first, err = execSQL.PrepareAPIExecution(f.ctx, check)
	}
	if err != nil || !first {
		t.Fatal("profile source preparation", err)
	}
	started, err := execSQL.RecordAPIStart(f.ctx, check, original)
	if err != nil {
		t.Fatal("profile source start", err)
	}
	return started, refresh
}
