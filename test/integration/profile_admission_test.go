package integration

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	authapp "asservat.local/asservat/internal/application/authorization"
	captureapp "asservat.local/asservat/internal/application/capture"
	executionapp "asservat.local/asservat/internal/application/execution"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	capture "asservat.local/asservat/internal/domain/capture"
	execution "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/identity"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Real SQL authority/admission/binding with explicit synthetic target and
// reviewer inputs. This does not claim an installed profiler or native stop.
func qualifyProfileAdmission(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, create func(*testing.T) captureAdmissionScenario) {
	t.Run("profile-approved-admission-stream-binding", func(t *testing.T) {
		for _, mode := range []struct {
			name                        string
			mayHaveStarted, unavailable bool
		}{{name: "before-endpoint"}, {name: "after-endpoint", mayHaveStarted: true}, {name: "endpoint-unavailable", unavailable: true}} {
			mayHaveStarted := mode.mayHaveStarted
			t.Run(mode.name, func(t *testing.T) {
				recordingScenarioSlots = 8
				defer func() { recordingScenarioSlots = 1 }()
				s := create(t)
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
				c := planvalue.ProfileComposition{Components: []planvalue.ProfileComponent{{ID: "cpu", Profile: planvalue.ProfileRef{Catalog: "builtin", Name: "go-cpu", Version: "v1"}}}, MaxTotalBytes: 16 << 20, MaxDuration: "30s"}
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
				r.NativeLimit = 16 << 20
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
				// Recovery resolves the original approved timing scope rather than
				// comparing its zero review deadline to the accepted write deadline.
				resolutionPool := poolFor("context_request_resolution_runtime", "synthetic-context-request-resolution")
				defer resolutionPool.Close()
				resolver, err := postgres.NewContextRequestResolutions(ctx, resolutionPool, p.RootID, s.recovery.guard)
				if err != nil {
					t.Fatal(err)
				}
				recovery, err := s.recovery.reader.RecoveryState(ctx)
				if err != nil {
					t.Fatal(err)
				}
				i := s.a.Eligibility.VerifiedIdentity
				i.Scopes = append(append([]string(nil), i.Scopes...), "evidence:read")
				i.VerifiedAt = time.Now().UTC().Truncate(time.Microsecond)
				i.ValidUntil = i.VerifiedAt.Add(5 * time.Second)
				query := capture.ReplayQuery{RootID: p.RootID, PreviewID: p.ID, IdempotencyKey: s.a.IdempotencyKey, SubmissionDigest: s.a.SubmissionDigest, Identity: i, Recovery: recovery}
				resolved, err := resolver.ResolveOrCloseContextRequest(ctx, query)
				if err != nil || resolved.State != capture.RequestAccepted || resolved.Accepted == nil || resolved.Accepted.CaptureID != accepted.CaptureID || !resolved.Accepted.Deadline.Equal(accepted.Deadline) {
					t.Fatal("approved profile request resolution", resolved.State, err)
				}
				plan := artifact.StreamingPlan{Registration: *r, WriterEpoch: custodyID()}
				var epoch *string
				var state []byte
				var objects int64
				if err = admin.QueryRow(ctx, "SELECT writer_epoch::text,state FROM custody_stream WHERE attempt_id=$1", r.Location.AttemptID).Scan(&epoch, &state); err != nil || epoch != nil {
					t.Fatal("admission invented writer epoch", err)
				}
				if err = admin.QueryRow(ctx, "SELECT charged_bytes,charged_objects FROM custody_allocation WHERE id=$1", r.AllocationID).Scan(&charged, &objects); err != nil || charged != r.ReservedBytes()+plan.TemporaryBytes() || objects != int64(5+plan.PartLimit()) {
					t.Fatal("multipart precharge", charged, objects, err)
				}
				again, err := s.s.AdmitReviewedContext(ctx, p.ID, s.a)
				if err != nil || !again.Replay {
					t.Fatal("profile admission replay", err)
				}
				ledger, err := postgres.New(ctx, poolFor("custody_runtime", "synthetic-runtime"))
				if err != nil {
					t.Fatal(err)
				}
				if _, fresh, err := ledger.AdvanceStreaming(ctx, plan, artifact.StreamingStep{Kind: artifact.StreamClaimCreate}); err == nil || fresh {
					t.Fatal("unbound writer acquired multipart permission")
				}
				auditPool := poolFor("capture_audit_runtime", "synthetic-capture-audit")
				intents, err := postgres.NewCaptureIntentAudits(ctx, auditPool, p.RootID)
				if err != nil {
					t.Fatal(err)
				}
				if err = (auditapp.CaptureIntentPublisher{Ledger: intents, Objects: &objectstore.CaptureIntentObjects{Store: store, Seal: keys, Open: keys}}).PublishCaptureIntents(ctx); err != nil {
					t.Fatal(err)
				}
				execSQL, err := postgres.NewAPIContextExecutions(ctx, pools.ordinary, p.RootID, postgres.EffectTransactionGuards{Retention: s.retention.guard, Recovery: s.recovery.guard})
				if err != nil {
					t.Fatal(err)
				}
				process := execution.APIProcessBinding{NamespaceUID: custodyID(), AccountUID: custodyID(), PodUID: custodyID(), ProcessEpoch: plan.WriterEpoch, StartupDigest: artifact.Digest{1}, ImageDigest: accepted.Expectation.CollectorImageDigest}
				refresh := func() executionapp.APIExecutionCheck {
					n := time.Now().UTC().Truncate(time.Microsecond)
					s.batch.ObservedAt, s.batch.FreshUntil, s.batch.Initial = n, n.Add(5*time.Second), nil
					if err := s.p.RefreshPermissions(ctx, s.batch); err != nil {
						t.Fatal(err)
					}
					i := s.a.Eligibility.VerifiedIdentity
					i.Scopes = append(append([]string(nil), i.Scopes...), "evidence:read")
					i.VerifiedAt, i.ValidUntil = n, n.Add(5*time.Second)
					recovery, err := s.recovery.reader.RecoveryState(ctx)
					if err != nil {
						t.Fatal(err)
					}
					work, err := execSQL.ReadAPIContextWork(ctx, accepted.CaptureID, i, recovery)
					if err != nil {
						t.Fatal(err)
					}
					projection, err := s.p.Permissions(ctx, s.a.Eligibility.Target)
					if err != nil {
						t.Fatal(err)
					}
					eligible := authorization.ContextEligibility(i, projection, s.a.Eligibility.Target, time.Now())
					policies, err := s.retention.policies(ctx)
					if err != nil {
						t.Fatal(err)
					}
					input := s.a.Plan.Input
					input.Retention, err = privacy.Resolve(policies, privacy.Input{Target: s.a.Eligibility.Target, PrivacyClass: "potentialPersonalData", EvidenceType: "profile", RequestedSeconds: accepted.Expectation.RequestedAgeSeconds, AnchorAt: accepted.Expectation.Registration.AnchorAt}, time.Now())
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
				original, first, err := execSQL.PrepareAPIExecution(ctx, check)
				if err != nil || !first || original.Binding.NativeType != artifact.PprofArtifact {
					t.Fatal("profile preparation", first, err)
				}
				if err = admin.QueryRow(ctx, "SELECT writer_epoch::text,state FROM custody_stream WHERE attempt_id=$1", r.Location.AttemptID).Scan(&epoch, &state); err != nil || epoch == nil || *epoch != process.ProcessEpoch {
					t.Fatal("stream process binding", err)
				}
				var parsed artifact.StreamingState
				if json.Unmarshal(state, &parsed) != nil || parsed.CreateSpent {
					t.Fatal("preparation started remote write")
				}
				replay, first, err := execSQL.PrepareAPIExecution(ctx, refresh())
				if err != nil || first || replay != original {
					t.Fatal("preparation replay replaced start", err)
				}
				process.ProcessEpoch = custodyID()
				if _, first, err = execSQL.PrepareAPIExecution(ctx, refresh()); err == nil || first {
					t.Fatal("replacement process rebound stream")
				}
				if err = admin.QueryRow(ctx, "SELECT charged_bytes FROM custody_allocation WHERE id=$1", r.AllocationID).Scan(&charged); err != nil || charged != r.ReservedBytes()+plan.TemporaryBytes() {
					t.Fatal("uncertain preparation refunded temporary charge", charged, err)
				}
				process = original.Process
				check = refresh()
				running, err := execSQL.RecordAPIStart(ctx, check, original)
				if err != nil {
					t.Fatal("profile start", err)
				}
				if mode.unavailable {
					qualifyProfileUnavailableOutcome(t, ctx, admin, pools.ordinary, s, execSQL, running, check, r.ReservedBytes()+plan.TemporaryBytes(), g.ID)
					return
				}
				var revision int64
				if err = admin.QueryRow(ctx, "SELECT progress_revision FROM context_capture WHERE root_id=$1 AND id=$2", p.RootID, p.CaptureID).Scan(&revision); err != nil {
					t.Fatal(err)
				}
				cancellation := capture.CancellationCheck{RootID: p.RootID, Request: capture.CancellationRequest{CaptureID: p.CaptureID, ExpectedRevision: revision, IdempotencyKey: "stop-profile"}, Identity: check.Eligibility.VerifiedIdentity, Recovery: check.Recovery, CheckedAt: time.Now().UTC().Truncate(time.Microsecond), ValidUntil: check.ValidUntil}
				stopped, err := execSQL.RequestCaptureCancellation(ctx, cancellation)
				if err != nil || stopped.Profile == nil || stopped.Snapshot != nil || !stopped.Decision.Requested || stopped.Decision.Phase != "Running" || !stopped.Decision.ApplicationStopUnknown || stopped.Profile.WriterEpoch != running.Process.ProcessEpoch {
					t.Fatal("typed profile cancellation", stopped, err)
				}
				replayStop, err := execSQL.RequestCaptureCancellation(ctx, cancellation)
				if err != nil || replayStop.Profile == nil || *replayStop.Profile != *stopped.Profile || replayStop.Decision.Revision != stopped.Decision.Revision {
					t.Fatal("profile stop replay changed attempt", err)
				}
				cancelled := running
				cancelled.Phase = "cancelled"
				cancelled.CompletedAt = time.Now().UTC().Truncate(time.Microsecond)
				proof := artifact.ProfileCancellation{CaptureID: p.CaptureID, AttemptID: r.Location.AttemptID, WriterPodUID: running.Process.PodUID, WriterEpoch: running.Process.ProcessEpoch, ExpectationDigest: running.ExpectationDigest, JoinedAt: cancelled.CompletedAt, MayHaveStarted: mayHaveStarted}
				changed := proof
				changed.WriterEpoch = custodyID()
				if _, err = execSQL.RecordAPIProfileCancellation(ctx, cancelled, changed, check.Process, check.Recovery); err == nil {
					t.Fatal("replacement writer cancelled profile")
				}
				if _, err = execSQL.RecordAPIProfileCancellation(ctx, cancelled, proof, check.Process, check.Recovery); err != nil {
					t.Fatal("joined profile cancellation", err)
				}
				joined, err := execSQL.RequestCaptureCancellation(ctx, cancellation)
				if err != nil || joined.Profile != nil || joined.Decision.Phase != "Cancelled" || joined.Decision.ApplicationStopUnknown != mayHaveStarted {
					t.Fatal("joined profile stop status", joined, err)
				}
				if err = admin.QueryRow(ctx, "SELECT charged_bytes FROM custody_allocation WHERE id=$1", r.AllocationID).Scan(&charged); err != nil || charged != r.ReservedBytes()+plan.TemporaryBytes() {
					t.Fatal("cancel refunded uncertain profile charge", charged, err)
				}

			})
		}
	})
}
