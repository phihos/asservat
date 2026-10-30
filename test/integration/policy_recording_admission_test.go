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
	RecordingSaves      bool
	RecurringSharing    bool
	OrdinaryGrant       bool
	Retention           string
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
	GrantID   string
	Scenario  captureAdmissionScenario
	Compiled  capture.RestartPolicy
	Authority authorization.AcceptedPolicyAuthority
	Source    capture.PolicySource
	Sources   *postgres.Policies
	Reader    *postgres.Policies
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
				if protected[0].RecurringSharing && !slices.Contains(b.Roles, "evidence-owner") {
					b.Roles = append(slices.Clone(b.Roles), "evidence-owner")
				}
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
			var recurringSharing *capture.PolicyShareInstruction
			if len(protected) > 0 && protected[0].RecurringSharing {
				var owner artifact.AudienceAssignment
				for _, assignment := range projection.Allows {
					if assignment.Audience.BasisUID == b.Resource.UID && assignment.Audience.Role == "evidence-owner" {
						owner = assignment.Audience
					}
				}
				if owner.AssignmentID == "" {
					t.Fatal("current recurring sharing owner absent")
				}
				recipient := authorization.ShareRecipient{Kind: "User", Issuer: creator.Issuer, ID: "synthetic-policy-recipient"}
				sharingUntil := now.Add(30 * time.Minute).UTC().Truncate(time.Second)
				recurringSharing = &capture.PolicyShareInstruction{Creator: creator, Management: []artifact.AudienceAssignment{owner}, Recipients: []authorization.ShareRecipient{recipient}, MaxCaptures: 4, NotAfter: sharingUntil}
			}
			if len(protected) > 0 {
				policyRecorderReviewedSaveSpec(authored, protected[0].RecordingSaves, recurringSharing)
			}
			if len(protected) > 0 && protected[0].Retention != "" {
				authored["retention"] = protected[0].Retention
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
			if recurringSharing != nil {
				author = policyRecorderRecurringSharingAuthor(author)
			}
			author.VerifiedAt, author.ValidUntil = now, now.Add(30*time.Second)
			workload := authorization.WorkloadTarget{ClusterID: target.ClusterID, NamespaceUID: target.NamespaceUID, WorkloadUID: target.WorkloadUID}
			if recurringSharing != nil {
				current, err := s.p.WorkloadPermissions(ctx, workload)
				if err != nil {
					t.Fatal("current recurring sharing workload permissions", err)
				}
				eligible, managers := authorization.PolicyWorkloadShareManagement(author, current, workload, authority.Delegation.UID, []string{sponsor.SubjectID}, clock())
				if !eligible.Eligible || !slices.Equal(managers, recurringSharing.Management) {
					t.Fatal("recurring sharing author preflight", eligible.Reason)
				}
			}
			accepted := capture.PolicyAdmission{RootID: root, Recovery: recovery, Authority: authority, Author: author, Workload: &workload, Submission: capture.VerifiedPolicySubmission{Nonce: custodyID(), Actor: creator, Source: source.Revision, ClusterID: source.ClusterID, NamespaceUID: source.NamespaceUID, Name: source.Name, ScopeDigest: authority.ScopeDigest, EnvelopeDigest: artifact.Digest{92}, IssuedAt: now, ExpiresAt: now.Add(30 * time.Second)}}
			accepted.Sharing = recurringSharing
			accepted.Verification = syntheticSubmissionCheck(accepted, now)
			record, err := acceptor.AcceptPolicy(ctx, accepted)
			if err != nil {
				t.Fatal("accepted policy", err)
			}
			if err = (auditapp.PolicyAcceptancePublisher{Ledger: auditor, Objects: &objectstore.PolicyAcceptanceObjects{Store: store, Seal: keys, Open: keys}}).PublishPolicyAcceptances(ctx); err != nil {
				t.Fatal(err)
			}
			if recurringSharing != nil && record.Record.Sharing == nil {
				t.Fatal("accepted recurring sharing missing")
			}
			if len(protected) > 0 && protected[0].SourceAccepted != nil {
				var grant string
				if protected[0].OrdinaryGrant {
					grant = attachOrdinaryPolicyAccountingGrant(t, ctx, admin, poolFor, s, authority, scope, "ordinary-source", *compiled.Recorder)
				}
				protected[0].SourceAccepted(t, policySourceAcceptedFixture{GrantID: grant, Scenario: s, Compiled: compiled, Authority: authority, Source: source, Sources: sources, Reader: reader, Record: record})
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

// Set reviewed intent before raw source hashing/observation/acceptance. The same
// constructor is exercised by the pure compiler contract control below.
func policyRecorderReviewedSaveSpec(authored map[string]any, enabled bool, sharing *capture.PolicyShareInstruction) {
	if enabled {
		authored["recordingSaves"] = map[string]any{"enabled": true}
	}
	if sharing != nil {
		recipients := make([]map[string]any, len(sharing.Recipients))
		for n, recipient := range sharing.Recipients {
			recipients[n] = map[string]any{"kind": recipient.Kind, "issuer": recipient.Issuer, "id": recipient.ID}
		}
		authored["sharing"] = map[string]any{"recipients": recipients, "futureCaptures": map[string]any{"enabled": true, "maxCaptures": sharing.MaxCaptures}, "notAfter": sharing.NotAfter.UTC().Format(time.RFC3339)}
	}
}

func TestManualSaveFixtureReviewedOptInAndSharingCompile(t *testing.T) {
	var authored map[string]any
	if err := json.Unmarshal(publicPolicySpec(t, authorization.AcceptedPolicyAuthority{ClusterID: custodyID()}), &authored); err != nil {
		t.Fatal(err)
	}
	component := authored["profileComposition"].(map[string]any)["components"].([]any)[0].(map[string]any)
	for _, value := range component["overrides"].([]any) {
		edit := value.(map[string]any)
		if edit["field"] == "actionExecutionMode" {
			edit["value"] = "ongoing"
		}
		if edit["field"] == "packetBefore" {
			edit["value"] = "10s"
		}
	}
	sharing := &capture.PolicyShareInstruction{Recipients: []authorization.ShareRecipient{{Kind: "User", Issuer: "https://id.example.test", ID: "synthetic-policy-recipient"}}, MaxCaptures: 4, NotAfter: time.Now().UTC().Truncate(time.Second).Add(30 * time.Minute)}
	policyRecorderReviewedSaveSpec(authored, true, sharing)
	raw, err := json.Marshal(authored)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := captureapp.CompilePolicyWithRecorders(raw, planning.ContextRecipeName, planning.RecipeDigest(), policySourceCompile(publicPolicyFilters{}))
	if err != nil || !compiled.RecordingSaves || compiled.Recorder == nil || compiled.Recorder.Action.ExecutionMode != "ongoing" || compiled.Sharing == nil || compiled.Sharing.MaxCaptures != sharing.MaxCaptures || len(compiled.Sharing.Recipients) != 1 {
		t.Fatal("reviewed manual opt-in and recurring sharing not supported by actual compiler", err)
	}
	delete(authored, "recordingSaves")
	raw, err = json.Marshal(authored)
	if err != nil {
		t.Fatal(err)
	}
	old, err := captureapp.CompilePolicyWithRecorders(raw, planning.ContextRecipeName, planning.RecipeDigest(), policySourceCompile(publicPolicyFilters{}))
	if err != nil || old.RecordingSaves {
		t.Fatal("legacy policy silently gained manual save capability", err)
	}
}

// The sharing fixture author is independently entitled to read and share, in
// addition to the capture-only identity used by the legacy admission cases.
func policyRecorderRecurringSharingAuthor(author identity.Identity) identity.Identity {
	for _, scope := range []string{"evidence:read", authorization.ShareScope} {
		if !slices.Contains(author.Scopes, scope) {
			author.Scopes = append(slices.Clone(author.Scopes), scope)
		}
	}
	return author
}

func TestManualSaveRecurringSharingAuthorHasCurrentOwnerEligibility(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	author := identity.Identity{Principal: identity.Principal{Issuer: "https://id.example.test", Subject: "developer", ClientID: "browser", Kind: identity.Human}, Groups: []string{"maintainers"}, Scopes: []string{"evidence:capture", authorization.ShareScope}, Policy: identity.Revision{UID: "identity", Generation: 1, Digest: artifact.Digest{1}}, VerifiedAt: now, ValidUntil: now.Add(30 * time.Second)}
	target := authorization.WorkloadTarget{ClusterID: custodyID(), NamespaceUID: custodyID(), WorkloadUID: custodyID()}
	owner := artifact.AudienceAssignment{Kind: "Group", Issuer: author.Principal.Issuer, SubjectID: "maintainers", Role: "evidence-owner", BasisKind: "AccessBinding", BasisUID: "binding", BasisDigest: artifact.Digest{2}, AssignmentID: custodyID()}
	p := authorization.WorkloadProjection{Target: target, Revision: identity.Revision{UID: "permissions", Generation: 1, Digest: artifact.Digest{3}}, ObservedAt: now, FreshUntil: now.Add(30 * time.Second), DeniesComplete: true, DeniesObservedAt: now, DeniesFreshUntil: now.Add(30 * time.Second), Allows: []authorization.CurrentAssignment{{Audience: owner, ObservedAt: now, FreshUntil: now.Add(30 * time.Second)}}}
	if r, _ := authorization.PolicyWorkloadShareManagement(author, p, target, "binding", []string{"maintainers"}, now); r.Eligible || r.Reason != "InsufficientScope" {
		t.Fatal("capture+share identity must reproduce missing read refusal", r)
	}
	corrected := policyRecorderRecurringSharingAuthor(author)
	r, management := authorization.PolicyWorkloadShareManagement(corrected, p, target, "binding", []string{"maintainers"}, now)
	if !r.Eligible || len(management) != 1 || management[0] != owner {
		t.Fatal("sharing fixture author lacks genuine current owner eligibility", r, management)
	}
	missingOwner := p
	missingOwner.Allows = nil
	if r, _ := authorization.PolicyWorkloadShareManagement(corrected, missingOwner, target, "binding", []string{"maintainers"}, now); r.Eligible {
		t.Fatal("scopes alone invented owner authority")
	}
	denied := p
	denied.Denies = slices.Clone(p.Allows)
	if r, _ := authorization.PolicyWorkloadShareManagement(corrected, denied, target, "binding", []string{"maintainers"}, now); r.Eligible || r.Reason != "ExplicitDeny" {
		t.Fatal("sharing fixture bypassed current deny", r)
	}
}
