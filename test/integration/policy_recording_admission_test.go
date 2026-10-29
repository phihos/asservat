package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	captureapp "asservat.local/asservat/internal/application/capture"
	configapp "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/capture"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/internal/transport/conversion"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Explicit test-only reuse of the existing protected fixture's original roles
// and intent publisher. Nil preserves the legacy component cases unchanged.
type policyRecorderProtectedCase struct {
	// SourceAccepted stops before any occurrence/capture: a real audited policy
	// acceptance can qualify the separate ordinary source ledger in this fixture.
	Ongoing             bool
	SourceAccepted      func(*testing.T, policySourceAcceptedFixture)
	Hub                 *pgxpool.Pool
	Admissions          *postgres.ContextAdmissions
	Filters             planning.FilterCompiler
	Expression          string
	Subjects            []cfg.Subject
	Intent              func(context.Context, string) error
	Stored              func(policyObservationRetirementInput)
	PermissionsAccepted func(cfg.PermissionBatch)
}

type policySourceAcceptedFixture struct {
	Scenario  captureAdmissionScenario
	Compiled  capture.RestartPolicy
	Authority authorization.AcceptedPolicyAuthority
	Source    capture.PolicySource
	Sources   *postgres.Policies
	Record    capture.AcceptedPolicy
}

// Real Tick -> immutable occurrence -> recording admission and shared/grant
// debit. Protected source/target/identity, initial trust and independent review
// remain explicit synthetic component facts. No collector or public enablement.
func qualifyPolicyRecorderAdmission(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, create func(*testing.T) captureAdmissionScenario, protected ...policyRecorderProtectedCase) {
	modes := []string{"packet-policy", "snapshot-policy-refuses-recorder", "packet-policy-observation-sql", "packet-policy-companion-sql"}
	if len(protected) > 0 {
		modes = []string{"packet-policy-companion-sql"}
	}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			s := create(t)
			var beforeGraph *policyObservationGraphSample
			if mode == "packet-policy-companion-sql" {
				sample := samplePolicyObservationGraph(t, ctx, admin, s.a.RootID, s.a.Registration.AllocationID, s.poolID)
				beforeGraph = &sample
			}
			packetPolicy := mode != "snapshot-policy-refuses-recorder"
			observationSQL := mode == "packet-policy-observation-sql"
			companionSQL := mode == "packet-policy-companion-sql"
			observed := observationSQL || companionSQL
			compilePolicy := publicPolicyCompile
			var filters planning.FilterCompiler = publicPolicyFilters{}
			if companionSQL {
				compilePolicy = policyRawCompile
				filters = policyRawFilters{}
			}
			if len(protected) > 0 {
				filters = protected[0].Filters
				compilePolicy = policyMetadataCompile(filters)
				if protected[0].Ongoing {
					compilePolicy = policySourceCompile(filters)
				}
			}
			clock := func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }
			root, installation := s.a.RootID, s.recovery.installation
			target := s.a.Plan.Input.Target.Target()
			b := &s.batch.Bases[0]
			if len(protected) > 0 {
				b.Subjects = protected[0].Subjects
			}
			b.Automation = &authorization.AutomationEnvelope{AllowedActions: []string{authorization.PolicyContextAction, "packetCapture"}, MaxLifetimeSeconds: 3600, MaxExecutions: 10, MaxBytes: 64 << 20}
			if observed {
				b.Automation.MaxObservedBytes = 1 << 30
			}
			b.Resource.Generation++
			b.Resource.SpecDigest[0]++
			b.Resource.ResourceVersion = custodyID()
			b.Continuous = true
			b.ScopeDigest = configapp.PermissionScopeDigest(*b)
			s.batch.Initial = nil
			s.batch.RequestID, s.batch.ObservedAt = custodyID(), clock()
			s.batch.FreshUntil = s.batch.ObservedAt.Add(5 * time.Second)
			s.batch.InputDigest[0]++
			changed, err := s.p.AcceptPermissions(ctx, s.batch)
			if err != nil {
				t.Fatal("automation envelope", err)
			}
			s.batch.ExpectedSequence = changed.Sequence
			s.batch.Initial = nil
			if len(protected) > 0 && protected[0].PermissionsAccepted != nil {
				protected[0].PermissionsAccepted(policyRecorderCloneBatch(s.batch))
			}
			for range 2 {
				if err = (auditapp.AuthorityPublisher{Ledger: s.p, Objects: &objectstore.AuthorityObjects{Store: store, Seal: keys, Open: keys}}).PublishAuthority(ctx); err != nil {
					t.Fatal(err)
				}
			}
			projection, err := s.p.Permissions(ctx, target)
			if err != nil {
				t.Fatal(err)
			}
			sponsor := policyRecorderSponsor(s.a.Eligibility.VerifiedIdentity, projection, b.Resource.UID)
			if sponsor.AssignmentID == "" {
				t.Fatal("current sponsor absent")
			}
			factory := func(role, password string) *postgres.Policies {
				pool := poolFor(role, password)
				t.Cleanup(pool.Close)
				p, err := postgres.NewPolicies(ctx, pool, root, installation)
				if err != nil {
					t.Fatal(err)
				}
				return p
			}
			sources := factory("policy_source_runtime", "synthetic-policy-source")
			acceptor := factory("policy_accept_runtime", "synthetic-policy-accept")
			auditor := factory("policy_audit_runtime", "synthetic-policy-audit")
			reader := factory("policy_read_runtime", "synthetic-policy-read")
			var hub *pgxpool.Pool
			if len(protected) > 0 {
				hub = protected[0].Hub
			} else {
				role := narrowRole(t, ctx, admin, "policy_recorder_"+strings.ReplaceAll(mode, "-", "_")+"_", "synthetic-policy-recorder", func(role string) []string {
					sql, ok := postgres.PublicRuntimeRoleGrantSQL("hub-runtime", role)
					if !ok {
						t.Fatal("hub duty")
					}
					return sql
				})
				hub = poolFor(role, "synthetic-policy-recorder")
				defer hub.Close()
			}
			current, err := postgres.NewAutomationAuthorities(ctx, hub, root, installation)
			if err != nil {
				t.Fatal(err)
			}
			ledger, err := postgres.NewPolicyTriggers(ctx, hub, root, installation)
			if err != nil {
				t.Fatal(err)
			}
			// Match production's independently credentialed admission facet;
			// the ordinary hub union intentionally cannot lock storage bindings.
			var admissions *postgres.ContextAdmissions
			if len(protected) > 0 {
				admissions = protected[0].Admissions
			} else {
				admitRole := narrowRole(t, ctx, admin, "policy_recorder_admit_"+strings.Split(mode, "-")[0]+"_", "synthetic-policy-recorder-admit", func(role string) []string {
					sql, ok := postgres.PublicRuntimeRoleGrantSQL("capture-admit", role)
					if !ok {
						t.Fatal("capture-admit purpose")
					}
					return sql
				})
				admitPool := poolFor(admitRole, "synthetic-policy-recorder-admit")
				defer admitPool.Close()
				admissions, err = postgres.NewContextAdmissions(ctx, admitPool, root, postgres.EffectTransactionGuards{Recovery: s.recovery.guard, Retention: s.retention.guard})
				if err != nil {
					t.Fatal(err)
				}
			}
			now := clock()
			creator := s.a.Eligibility.VerifiedIdentity.Principal
			authority := authorization.AcceptedPolicyAuthority{InstallationID: installation, PolicyUID: custodyID(), Creator: creator, ClusterID: target.ClusterID, NamespaceUID: target.NamespaceUID, WorkloadUID: target.WorkloadUID, Delegation: identity.Revision{UID: b.Resource.UID, Generation: b.Resource.Generation, Digest: b.Resource.SpecDigest}, Owners: []artifact.AudienceAssignment{sponsor}, Actions: []string{"packetCapture"}, Limits: authorization.AutomationLimits{MaxExecutions: 10, MaxBytes: 64 << 20}, IssuedAt: now, NotAfter: now.Add(time.Hour)}
			if observed {
				authority.Limits.MaxObservedBytes = 1 << 30
			}
			authority.Executor = authorization.PolicyPrincipal(installation, authority.PolicyUID)
			spec := publicPolicySpec(t, authority)
			var authored map[string]any
			if json.Unmarshal(spec, &authored) != nil {
				t.Fatal("policy spec")
			}
			selected := authored["target"].(map[string]any)
			selected["namespace"] = s.a.Plan.Input.Target.Request.Namespace.Name
			selected["workloadRef"].(map[string]any)["name"] = s.a.Plan.Input.Target.Request.Workload.Name
			if companionSQL {
				component := authored["profileComposition"].(map[string]any)["components"].([]any)[0].(map[string]any)
				for _, entry := range component["overrides"].([]any) {
					edit := entry.(map[string]any)
					if len(protected) > 0 && protected[0].Ongoing {
						if edit["field"] == "actionExecutionMode" {
							edit["value"] = "ongoing"
						}
						if edit["field"] == "packetBefore" {
							edit["value"] = "10s"
						}
					}
					if edit["field"] == "packetFilter" {
						edit["value"] = policyRawExpression
						if len(protected) > 0 {
							edit["value"] = protected[0].Expression
						}
					}
				}
			}
			spec, err = json.Marshal(authored)
			if err != nil {
				t.Fatal(err)
			}
			compiled, err := captureapp.CompilePolicyWithRecorders(spec, planning.ContextRecipeName, planning.RecipeDigest(), compilePolicy)
			if err != nil || compiled.Recorder == nil {
				t.Fatal("policy recorder compiler", err)
			}
			source := capture.PolicySource{InstallationID: installation, ClusterID: target.ClusterID, NamespaceUID: "control", Name: "restarts", Revision: identity.Revision{UID: authority.PolicyUID, Generation: 1, Digest: sha256.Sum256(spec)}, ResourceVersion: "policy-1", CollectionDigest: sha256.Sum256(spec), ObservedAt: now, FreshUntil: now.Add(30 * time.Second)}
			scope := captureapp.RecorderPolicyScope(authority.PolicyUID, 1, source.CollectionDigest, compiled, target.NamespaceUID, target.WorkloadUID, authority.Delegation, authority.Owners, authority.Actions, authority.Limits)
			if !packetPolicy {
				authority.Actions = []string{authorization.PolicyContextAction}
				scope, err = json.Marshal(struct {
					Format string
					Recipe artifact.Digest
				}{"synthetic-snapshot-control/v1", planning.RecipeDigest()})
				if err != nil {
					t.Fatal(err)
				}
			}
			authority.ScopeDigest = sha256.Sum256(scope)
			if err = sources.ObservePolicy(ctx, source); err != nil {
				t.Fatal(err)
			}
			recovery, err := s.recovery.reader.RecoveryState(ctx)
			if err != nil {
				t.Fatal(err)
			}
			author := s.a.Eligibility.VerifiedIdentity
			author.VerifiedAt, author.ValidUntil = now, now.Add(30*time.Second)
			workload := authorization.WorkloadTarget{ClusterID: target.ClusterID, NamespaceUID: target.NamespaceUID, WorkloadUID: target.WorkloadUID}
			accepted := capture.PolicyAdmission{RootID: root, Recovery: recovery, Authority: authority, Author: author, Workload: &workload, Submission: capture.VerifiedPolicySubmission{Nonce: custodyID(), Actor: creator, Source: source.Revision, ClusterID: source.ClusterID, NamespaceUID: source.NamespaceUID, Name: source.Name, ScopeDigest: authority.ScopeDigest, EnvelopeDigest: artifact.Digest{92}, IssuedAt: now, ExpiresAt: now.Add(30 * time.Second)}}
			accepted.Verification = syntheticSubmissionCheck(accepted, now)
			record, err := acceptor.AcceptPolicy(ctx, accepted)
			if err != nil {
				t.Fatal("accepted policy", err)
			}
			if err = (auditapp.PolicyAcceptancePublisher{Ledger: auditor, Objects: &objectstore.PolicyAcceptanceObjects{Store: store, Seal: keys, Open: keys}}).PublishPolicyAcceptances(ctx); err != nil {
				t.Fatal(err)
			}
			if len(protected) > 0 && protected[0].SourceAccepted != nil {
				protected[0].SourceAccepted(t, policySourceAcceptedFixture{Scenario: s, Compiled: compiled, Authority: authority, Source: source, Sources: sources, Record: record})
				return
			}
			var grant string
			if packetPolicy {
				grant = attachPolicyAccountingGrant(t, ctx, admin, poolFor, s, authority, scope, "recorder-positive", *compiled.Recorder)
			} else {
				grant = attachPolicyAccountingGrant(t, ctx, admin, poolFor, s, authority, scope, "snapshot-negative")
			}
			// Refresh only the existing protected observation, without changing
			// accepted content, source expiry, counters or grant configuration.
			s.batch.ObservedAt = clock()
			s.batch.FreshUntil = s.batch.ObservedAt.Add(5 * time.Second)
			if err = s.p.RefreshPermissions(ctx, s.batch); err != nil {
				t.Fatal("current permissions before Tick", err)
			}
			// The actual trigger ledger spends exactly one accepted execution. Its
			// baseline is silent; a real higher counter creates one original occurrence.
			observation := targets.RestartObservation{ClusterID: target.ClusterID, Namespace: s.a.Plan.Input.Target.Request.Namespace, Workload: s.a.Plan.Input.Target.Request.Workload, Pods: []targets.PodRestarts{{UID: target.PodUID, Name: s.a.Plan.Input.Target.Request.PodName, Restarts: 1, Reason: "Error", ExitCode: 1}}, ObservedAt: clock()}
			observation.FreshUntil = observation.ObservedAt.Add(5 * time.Second)
			if rows, err := ledger.Tick(ctx, capture.PolicyTick{Policy: compiled, Authority: authority, Observation: observation}); err != nil || len(rows) != 0 {
				t.Fatal("silent baseline", rows, err)
			}
			observation.Pods[0].Restarts++
			observation.ObservedAt = clock()
			observation.FreshUntil = observation.ObservedAt.Add(5 * time.Second)
			rows, err := ledger.Tick(ctx, capture.PolicyTick{Policy: compiled, Authority: authority, Observation: observation})
			if err != nil || len(rows) != 1 {
				t.Fatal("actual triggering occurrence", rows, err)
			}
			// Current independently read team eligibility supplies the real policy
			// principal, never a fresh login/remembered creator group list.
			now = clock()
			projectionNow, err := current.PolicyAutomationAuthority(ctx, authority, target)
			if err != nil {
				t.Fatal(err)
			}
			executor := authorization.PolicyExecutorIdentity(authority, now, now.Add(5*time.Second))
			eligible := authorization.PolicyContextEligibility(executor, authority, projectionNow, target, now)
			if !eligible.Eligible {
				t.Fatal("team eligibility", eligible.Reason)
			}
			a := s.a
			in := a.Plan.Input
			in.Executor = authority.Executor
			in.Deadline = now.Add(30 * time.Second)
			in.Target.ExecutionClass, in.Capability.ExecutionClass = artifact.ContextAPIExecution, artifact.ContextAPIExecution
			in.Target.NodeUID, in.Target.NodeBootID, in.Target.Pin.NodeName = "", "", ""
			in.Target.ObservedAt, in.Target.FreshUntil = now, now.Add(5*time.Second)
			in.Capability.ObservedAt, in.Capability.FreshUntil = now, now.Add(5*time.Second)
			retained, err := s.retention.policies(ctx)
			if err != nil {
				t.Fatal(err)
			}
			// The source helper observes a new protected snapshot during this
			// blocking read. Validate after it returns; retain every original
			// identity, plan, storage, grant and policy deadline above.
			now = clock()
			in.Retention, err = privacy.Resolve(retained, privacy.Input{Target: target, PrivacyClass: "potentialPersonalData", EvidenceType: "packetCapture", AnchorAt: a.Registration.AnchorAt}, now)
			if err != nil {
				t.Fatal("recording retention after current source read", err)
			}

			a.Plan.Input = in
			a.Eligibility, a.IdempotencyKey = eligible, rows[0].ID
			a.Recovery, err = s.recovery.reader.RecoveryState(ctx)
			if err != nil {
				t.Fatal(err)
			}
			a, preview := buildPolicyRecorderAdmissionFixture(t, a, compiled.Recorder.Composition, filters, !companionSQL, clock())
			requirePolicyRecorderAdmissionFixture(t, a, preview, clock())
			previews, err := postgres.NewContextPreviews(ctx, hub, root)
			if err != nil {
				t.Fatal(err)
			}
			if err = previews.CreateContextPreview(ctx, preview); err != nil {
				t.Fatal("persist actual policy recorder preview", err)
			}
			if _, err = reader.AcceptedPolicyAuthority(ctx, authority.PolicyUID); err != nil {
				t.Fatal(err)
			}
			output, err := admissions.AdmitReviewedContext(ctx, preview.ID, a)
			if packetPolicy {
				if err != nil || output.Expectation.Recording == nil || output.Expectation.Recording.MaxBytes != artifact.RecordingNativeLimit || output.Expectation.RecipeDigest != compiled.Recorder.RecipeDigest {
					t.Fatal("real team recorder admission", err)
				}
				again, err := admissions.AdmitReviewedContext(ctx, preview.ID, a)
				if err != nil || again.CaptureID != output.CaptureID {
					t.Fatal("same occurrence replay", err)
				}
			} else if !errors.Is(err, capture.ErrDenied) {
				t.Fatal("snapshot-only policy/grant admitted actual recorder", err)
			}
			// Reuse the production status/grant models; fixture counter names
			// cannot drift into an invented column or the personal result pool.
			status, err := ledger.Status(ctx, authority.PolicyUID)
			if err != nil {
				t.Fatal("accepted budget status", err)
			}
			grantStore, err := postgres.NewAccessGrants(ctx, hub, root, s.recovery.guard)
			if err != nil {
				t.Fatal(err)
			}
			charged, err := grantStore.Grant(ctx, grant)
			if err != nil {
				t.Fatal("grant reservation counters", err)
			}
			execs, bytes := status.ExecutionsSpent, status.CollectedBytesSpent
			grantExec, grantBytes := charged.PolicySpend.Executions, charged.PolicySpend.CollectedBytes
			var reservations int64
			if err = admin.QueryRow(ctx, "SELECT count(*) FROM policy_occurrence WHERE root_id=$1 AND acceptance_id=$2 AND reserved_capture_id IS NOT NULL", root, record.Record.ID).Scan(&reservations); err != nil {
				t.Fatal(err)
			}
			wantBytes, wantExec, wantReservations := int64(0), int64(0), int64(0)
			if packetPolicy {
				wantBytes, wantExec, wantReservations = artifact.RecordingNativeLimit, 1, 1
			}
			if execs != 1 || bytes != wantBytes || grantExec != wantExec || grantBytes != wantBytes || reservations != wantReservations {
				t.Fatal("action mismatch/replay changed prospective pools", execs, bytes, grantExec, grantBytes, reservations)
			}
			t.Logf("actual Tick accepted executions=%d; native output=%d grant executions=%d output=%d reservations=%d", execs, bytes, grantExec, grantBytes, reservations)
			if observationSQL {
				qualifyFinitePolicyObservationSQL(t, ctx, admin, hub, poolFor, root, record.Record.ID, grant, output)
			}
			if companionSQL {
				qualifyPolicyObservationCompanion(t, ctx, admin, hub, poolFor, store, keys, s, admissions, current, authority, a, output, record.Record.ID, grant, beforeGraph, protected...)
			}
		})
	}
}

// Both the offline preflight and real fixture assemble the same marked plan,
// passive preview and reviewed request identity. No production validator/export.
func buildPolicyRecorderAdmissionFixture(t testing.TB, a capture.Admission, composition planvalue.ProfileComposition, filters planning.FilterCompiler, requireApproval bool, now time.Time) (capture.Admission, capture.ContextPreview) {
	t.Helper()
	in := a.Plan.Input
	reviewed, err := planning.CompileRecorder(planvalue.RecorderInput{CaptureID: in.CaptureID, Executor: in.Executor, Target: in.Target, Composition: composition, Retention: in.Retention, Deadline: in.Deadline, NodeRecorder: true, RequireApproval: requireApproval}, filters, now)
	if err != nil {
		t.Fatal("reviewed recorder fixture", err)
	}
	in.Recorder, err = planning.RecorderContextFromScope(composition, reviewed.CanonicalScope)
	if err != nil {
		t.Fatal(err)
	}
	a.Plan, err = planning.CompileContext(in, now)
	if err != nil {
		t.Fatal(err)
	}
	a.Registration.WriteUntil, a.Registration.ExpiresAt, a.Registration.DeleteBy = in.Deadline, in.Retention.ExpiresAt, in.Retention.DeleteBy
	p := capture.ContextPreview{ID: custodyID(), AssessmentID: custodyID(), AssessmentRulesDigest: planning.RecorderAssessmentRulesDigest(), RootID: a.RootID, InstallationID: a.Recovery.InstallationID, IssuerEpoch: a.Recovery.IssuerEpoch, CaptureID: in.CaptureID, CaseID: a.CaseID, OccurrenceID: a.OccurrenceID, ArtifactID: a.Registration.Location.ArtifactID, AttemptID: a.Registration.Location.AttemptID, Actor: in.Executor, ExecutionClass: in.Target.ExecutionClass,
		Intent: capture.ContextIntent{Target: targets.WorkloadRequest{ClusterID: in.Target.Request.ClusterID, Namespace: in.Target.Request.Namespace.Name, Kind: "Pod", Name: in.Target.Request.PodName}, Composition: composition.Clone(), RequestedSeconds: in.Retention.RequestedSeconds}, Target: in.Target.Request, Pin: in.Target.Pin,
		Storage:   capture.ContextStorageSelection{StoreID: a.Registration.StoreID, AllocationID: a.Registration.AllocationID, PoolRevision: a.Registration.PoolRevision, AllocationRevision: a.Registration.AllocationRevision, BindingRevision: a.Storage.Revision},
		Retention: capture.ContextRetentionReview{PurposeRef: in.Retention.PurposeRef, RequestedSeconds: in.Retention.RequestedSeconds, MaximumSeconds: in.Retention.MaximumSeconds, DeletionBudgetSeconds: in.Retention.DeletionBudgetSeconds, Policies: in.Retention.Policies}, Audience: append([]artifact.AudienceAssignment(nil), a.Eligibility.DefaultAudience...), CanonicalScope: reviewed.CanonicalScope, ScopeDigest: reviewed.ScopeDigest, CreatedAt: now, Deadline: in.Deadline}
	a.SubmissionDigest = captureapp.ContextRequestDigest(p.ID)
	return a, p
}
func requirePolicyRecorderAdmissionFixture(t testing.TB, a capture.Admission, p capture.ContextPreview, now time.Time) {
	t.Helper()
	in, r, e := a.Plan.Input, a.Registration, a.Eligibility
	target := in.Target.Target()
	checks := map[string]bool{
		"root-key":                   authorization.UUID(a.RootID) && authorization.UUID(a.IdempotencyKey),
		"frozen-plan":                planning.VerifyFrozenContextPlan(a.Plan),
		"registration":               r.Validate() == nil,
		"native-8MiB":                in.Recorder != nil && r.NativeLimit == artifact.RecordingNativeLimit,
		"storage-root":               a.Storage.RootID == a.RootID,
		"storage-target":             a.Storage.Matches(target),
		"storage-allocation":         a.Storage.AllocationID == r.AllocationID,
		"storage-valid":              a.Storage.Valid(now),
		"registration-cluster":       r.Location.ClusterID == target.ClusterID,
		"retention-anchor":           r.AnchorAt.Equal(in.Retention.AnchorAt),
		"retention-expiry":           r.ExpiresAt.Equal(in.Retention.ExpiresAt),
		"retention-deletion":         r.DeleteBy.Equal(in.Retention.DeleteBy),
		"original-write-bound":       !r.WriteUntil.After(in.Deadline),
		"case-id":                    authorization.UUID(a.CaseID) && (in.CaseID == "" || in.CaseID == a.CaseID),
		"occurrence-id":              authorization.UUID(a.OccurrenceID),
		"eligible":                   e.Eligible && now.Before(e.ValidUntil),
		"eligible-target":            e.Target == target,
		"eligible-principal":         e.Principal == in.Executor && e.VerifiedIdentity.Principal == in.Executor,
		"eligible-identity-revision": e.IdentityRevision == e.VerifiedIdentity.Policy && e.VerifiedIdentity.Valid(now),
		"permission-revision":        e.PermissionRevision.Valid(),
		"current-recovery":           a.Recovery.Valid(now),
		"actual-preview":             captureapp.ValidContextPreview(p) && p.Current(now),
		"reviewed-request-digest":    a.SubmissionDigest == captureapp.ContextRequestDigest(p.ID),
		"preview-scope":              p.ScopeDigest == a.Plan.ScopeDigest && bytes.Equal(p.CanonicalScope, a.Plan.CanonicalScope),
		"marked-reviewed-entrypoint": in.Recorder != nil && planning.RecorderApprovedAcceptance(a.Plan.CanonicalScope) && authorization.UUID(p.ID),
	}
	var failed []string
	for name, ok := range checks {
		if !ok {
			failed = append(failed, name)
		}
	}
	slices.Sort(failed)
	if len(failed) != 0 {
		t.Fatal("assembled policy recorder fixture rejected predicates", failed)
	}
}

func TestPolicyRecorderAdmissionFixtureOfflineBindings(t *testing.T) {
	for _, mode := range []struct {
		name            string
		raw, requireAll bool
	}{
		{"headers-require-all", false, true}, {"raw-require-all", true, true}, {"raw-independent-approval", true, false},
	} {
		t.Run(mode.name, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Microsecond)
			a := policyRecorderOfflineAdmission(t, now)
			spec := publicPolicySpec(t, authorization.AcceptedPolicyAuthority{ClusterID: a.Storage.ClusterID})
			compilePolicy := publicPolicyCompile
			var filters planning.FilterCompiler = publicPolicyFilters{}
			if mode.raw {
				spec = bytes.ReplaceAll(spec, []byte("tcp dst port 80"), []byte(policyRawExpression))
				compilePolicy = policyRawCompile
				filters = policyRawFilters{}
			}
			compiled, err := captureapp.CompilePolicyWithRecorders(spec, planning.ContextRecipeName, planning.RecipeDigest(), compilePolicy)
			if err != nil {
				t.Fatal(err)
			}
			a, p := buildPolicyRecorderAdmissionFixture(t, a, compiled.Recorder.Composition, filters, mode.requireAll, now)
			requirePolicyRecorderAdmissionFixture(t, a, p, now)
			recording, _, err := planning.RecordingForContext(a.Plan)
			if err != nil || recording.RequireApproval != mode.requireAll || a.Plan.Input.Recorder.RequireApproval != mode.requireAll {
				t.Fatal("fixture changed protected require-all input", err)
			}
			_, approval, err := planning.RecorderScopeSummary(p.CanonicalScope)
			if err != nil || approval == nil || mode.raw && (approval.ObservationLimits == nil || recording.Filter == nil || !planning.RawBytePredicate(recording.Filter.Expression)) {
				t.Fatal("fixture lost independent raw approval", err)
			}
		})
	}
}

// Shared compiler-only seed; no persisted observation or authority is invented.
func policyRecorderOfflineAdmission(t testing.TB, now time.Time) capture.Admission {
	t.Helper()
	root, installation, cluster := custodyID(), custodyID(), custodyID()
	target := capacityNativeTarget(cluster, cfg.NamespaceRef{Name: "app", UID: custodyID()}, cfg.WorkloadRef{Kind: "Deployment", Name: "api", UID: custodyID()}, now)
	target.ExecutionClass = artifact.ContextAPIExecution
	target.NodeUID, target.NodeBootID, target.Pin.NodeName = "", "", ""
	set := privacy.PolicySet{Target: target.Target(), Revision: identity.Revision{UID: "policy-set", Generation: 1, Digest: artifact.Digest{1}}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), Complete: true, Policies: []privacy.Policy{{Revision: identity.Revision{UID: "baseline", Generation: 1, Digest: artifact.Digest{2}}, Baseline: true, PurposeRef: "diagnostics", DefaultSeconds: 3600, MaximumSeconds: 86400, DeletionBudgetSeconds: 300}}}
	retained, err := privacy.Resolve(set, privacy.Input{Target: target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: "packetCapture", AnchorAt: now}, now)
	if err != nil {
		t.Fatal(err)
	}
	actor := authorization.PolicyPrincipal(installation, "policy-recorder")
	in := capacityNativeContextInput(target, retained, actor, custodyID(), now)
	owner := artifact.AudienceAssignment{Kind: "Group", Issuer: "https://id.example.test", SubjectID: "maintainers", Role: "workload-maintainer", BasisKind: "AccessBinding", BasisUID: "binding", BasisDigest: artifact.Digest{3}, AssignmentID: custodyID()}
	verified := identity.Identity{Principal: actor, Policy: identity.Revision{UID: "policy-recorder", Generation: 1, Digest: artifact.Digest{4}}, Scopes: []string{"evidence:capture"}, VerifiedAt: now, ValidUntil: now.Add(5 * time.Second)}
	eligible := authorization.CaptureEligibility{Result: authorization.Result{Eligible: true, Principal: actor, IdentityRevision: verified.Policy, PermissionRevision: identity.Revision{UID: "permissions", Generation: 1, Digest: artifact.Digest{5}}, ValidUntil: verified.ValidUntil}, Target: target.Target(), VerifiedIdentity: verified, DefaultAudience: []artifact.AudienceAssignment{owner}}
	allocation := custodyID()
	return capture.Admission{RootID: root, IdempotencyKey: custodyID(), Plan: planvalue.ContextPlan{Input: in}, Eligibility: eligible, Recovery: artifact.RecoveryProof{InstallationID: installation, IssuerEpoch: custodyID(), Revision: identity.Revision{UID: "recovery", Generation: 1, Digest: artifact.Digest{6}}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, Storage: capture.StorageBinding{RootID: root, ClusterID: cluster, NamespaceUID: target.Target().NamespaceUID, WorkloadUID: target.Target().WorkloadUID, AllocationID: allocation, Revision: identity.Revision{UID: "storage", Generation: 1, Digest: artifact.Digest{7}}, ObservedAt: now, FreshUntil: now.Add(30 * time.Second)}, Registration: artifact.Registration{Location: artifact.Location{ClusterID: cluster, ArtifactID: custodyID(), AttemptID: custodyID()}, StoreID: custodyID(), AllocationID: allocation, PoolRevision: 1, AllocationRevision: 1, NativeLimit: artifact.RecordingNativeLimit, AnchorAt: retained.AnchorAt}, CaseID: custodyID(), OccurrenceID: custodyID()}
}

func policyMetadataCompile(filters planning.FilterCompiler) func(json.RawMessage) (planvalue.PolicyRecorderConfiguration, error) {
	return func(raw json.RawMessage) (planvalue.PolicyRecorderConfiguration, error) {
		var wire contracts.CaptureComposition
		if err := json.Unmarshal(raw, &wire); err != nil {
			return planvalue.PolicyRecorderConfiguration{}, err
		}
		c, err := conversion.CompositionFromWire(wire)
		if err != nil || c == nil {
			return planvalue.PolicyRecorderConfiguration{}, planvalue.ErrInvalid
		}
		return planning.CompilePolicyRecorder(*c, filters)
	}
}

func policyRecorderSponsor(author identity.Identity, projection authorization.Projection, delegation string) artifact.AudienceAssignment {
	var sponsor artifact.AudienceAssignment
	for _, row := range projection.Allows {
		if row.Audience.Role == "workload-maintainer" && row.Audience.BasisUID == delegation && row.Audience.BasisKind == "AccessBinding" && row.Audience.Kind == "Group" && row.Audience.Issuer == author.Principal.Issuer && slices.Contains(author.Groups, row.Audience.SubjectID) {
			sponsor = row.Audience
		}
	}
	return sponsor
}

// Other nested values are replaced, not mutated, by this fixture. Clone only
// the mutable basis records so each case owns generation/version updates.
func policyRecorderCloneBatch(b cfg.PermissionBatch) cfg.PermissionBatch {
	b.Bases = slices.Clone(b.Bases)
	return b
}

func policySourceCompile(filters planning.FilterCompiler) func(json.RawMessage) (planvalue.PolicyRecorderConfiguration, error) {
	return func(raw json.RawMessage) (planvalue.PolicyRecorderConfiguration, error) {
		var wire contracts.CaptureComposition
		if err := json.Unmarshal(raw, &wire); err != nil {
			return planvalue.PolicyRecorderConfiguration{}, err
		}
		c, err := conversion.CompositionFromWire(wire)
		if err != nil || c == nil {
			return planvalue.PolicyRecorderConfiguration{}, planvalue.ErrInvalid
		}
		return planning.CompileOngoingPolicyRecorder(*c, filters)
	}
}
