package integration

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	captureapp "asservat.local/asservat/internal/application/capture"
	configapp "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Real Tick -> immutable occurrence -> recording admission and shared/grant
// debit. Protected source/target/identity, initial trust and independent review
// remain explicit synthetic component facts. No collector or public enablement.
func qualifyPolicyRecorderAdmission(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, create func(*testing.T) captureAdmissionScenario) {
	for _, mode := range []string{"packet-policy", "snapshot-policy-refuses-recorder"} {
		t.Run(mode, func(t *testing.T) {
			s := create(t)
			clock := func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }
			root, installation := s.a.RootID, s.recovery.installation
			target := s.a.Plan.Input.Target.Target()
			b := &s.batch.Bases[0]
			b.Automation = &authorization.AutomationEnvelope{AllowedActions: []string{authorization.PolicyContextAction, "packetCapture"}, MaxLifetimeSeconds: 3600, MaxExecutions: 10, MaxBytes: 64 << 20}
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
			for range 2 {
				if err = (auditapp.AuthorityPublisher{Ledger: s.p, Objects: &objectstore.AuthorityObjects{Store: store, Seal: keys, Open: keys}}).PublishAuthority(ctx); err != nil {
					t.Fatal(err)
				}
			}
			projection, err := s.p.Permissions(ctx, target)
			if err != nil {
				t.Fatal(err)
			}
			var sponsor artifact.AudienceAssignment
			for _, row := range projection.Allows {
				if row.Audience.Role == "workload-maintainer" && row.Audience.BasisUID == b.Resource.UID {
					sponsor = row.Audience
				}
			}
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
			role := narrowRole(t, ctx, admin, "policy_recorder_"+strings.ReplaceAll(mode, "-", "_")+"_", "synthetic-policy-recorder", func(role string) []string {
				sql, ok := postgres.PublicRuntimeRoleGrantSQL("hub-runtime", role)
				if !ok {
					t.Fatal("hub duty")
				}
				return sql
			})
			hub := poolFor(role, "synthetic-policy-recorder")
			defer hub.Close()
			current, err := postgres.NewAutomationAuthorities(ctx, hub, root, installation)
			if err != nil {
				t.Fatal(err)
			}
			ledger, err := postgres.NewPolicyTriggers(ctx, hub, root, installation)
			if err != nil {
				t.Fatal(err)
			}
			admissions, err := postgres.NewContextAdmissions(ctx, hub, root, postgres.EffectTransactionGuards{Recovery: s.recovery.guard, Retention: s.retention.guard})
			if err != nil {
				t.Fatal(err)
			}
			now := clock()
			creator := s.a.Eligibility.VerifiedIdentity.Principal
			authority := authorization.AcceptedPolicyAuthority{InstallationID: installation, PolicyUID: custodyID(), Creator: creator, ClusterID: target.ClusterID, NamespaceUID: target.NamespaceUID, WorkloadUID: target.WorkloadUID, Delegation: identity.Revision{UID: b.Resource.UID, Generation: b.Resource.Generation, Digest: b.Resource.SpecDigest}, Owners: []artifact.AudienceAssignment{sponsor}, Actions: []string{"packetCapture"}, Limits: authorization.AutomationLimits{MaxExecutions: 10, MaxBytes: 64 << 20}, IssuedAt: now, NotAfter: now.Add(time.Hour)}
			authority.Executor = authorization.PolicyPrincipal(installation, authority.PolicyUID)
			spec := publicPolicySpec(t, authority)
			var authored map[string]any
			if json.Unmarshal(spec, &authored) != nil {
				t.Fatal("policy spec")
			}
			selected := authored["target"].(map[string]any)
			selected["namespace"] = s.a.Plan.Input.Target.Request.Namespace.Name
			selected["workloadRef"].(map[string]any)["name"] = s.a.Plan.Input.Target.Request.Workload.Name
			spec, err = json.Marshal(authored)
			if err != nil {
				t.Fatal(err)
			}
			compiled, err := captureapp.CompilePolicyWithRecorders(spec, planning.ContextRecipeName, planning.RecipeDigest(), publicPolicyCompile)
			if err != nil || compiled.Recorder == nil {
				t.Fatal("policy recorder compiler", err)
			}
			source := capture.PolicySource{InstallationID: installation, ClusterID: target.ClusterID, NamespaceUID: "control", Name: "restarts", Revision: identity.Revision{UID: authority.PolicyUID, Generation: 1, Digest: sha256.Sum256(spec)}, ResourceVersion: "policy-1", CollectionDigest: sha256.Sum256(spec), ObservedAt: now, FreshUntil: now.Add(30 * time.Second)}
			scope := captureapp.RecorderPolicyScope(authority.PolicyUID, 1, source.CollectionDigest, compiled, target.NamespaceUID, target.WorkloadUID, authority.Delegation, authority.Owners, authority.Actions, authority.Limits)
			if mode != "packet-policy" {
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
			var grant string
			if mode == "packet-policy" {
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
			in.Retention, err = privacy.Resolve(retained, privacy.Input{Target: target, PrivacyClass: "potentialPersonalData", EvidenceType: "packetCapture", AnchorAt: a.Registration.AnchorAt}, now)
			if err != nil {
				t.Fatal(err)
			}
			reviewed, err := planning.CompileRecorder(planvalue.RecorderInput{CaptureID: in.CaptureID, Executor: in.Executor, Target: in.Target, Composition: compiled.Recorder.Composition, Retention: in.Retention, Deadline: in.Deadline, NodeRecorder: true, RequireApproval: true}, publicPolicyFilters{}, now)
			if err != nil {
				t.Fatal(err)
			}
			in.Recorder, err = planning.RecorderContextFromScope(compiled.Recorder.Composition, reviewed.CanonicalScope)
			if err != nil {
				t.Fatal(err)
			}
			a.Plan, err = planning.CompileContext(in, now)
			if err != nil {
				t.Fatal(err)
			}
			a.Registration.WriteUntil, a.Registration.ExpiresAt, a.Registration.DeleteBy = in.Deadline, in.Retention.ExpiresAt, in.Retention.DeleteBy
			a.Eligibility, a.IdempotencyKey = eligible, rows[0].ID
			a.Recovery, err = s.recovery.reader.RecoveryState(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = reader.AcceptedPolicyAuthority(ctx, authority.PolicyUID); err != nil {
				t.Fatal(err)
			}
			output, err := admissions.AdmitContext(ctx, a)
			if mode == "packet-policy" {
				if err != nil || output.Expectation.Recording == nil || output.Expectation.Recording.MaxBytes != artifact.RecordingNativeLimit || output.Expectation.RecipeDigest != compiled.Recorder.RecipeDigest {
					t.Fatal("real team recorder admission", err)
				}
				again, err := admissions.AdmitContext(ctx, a)
				if err != nil || again.CaptureID != output.CaptureID {
					t.Fatal("same occurrence replay", err)
				}
			} else if !errors.Is(err, capture.ErrDenied) {
				t.Fatal("snapshot-only policy/grant admitted actual recorder", err)
			}
			var execs, bytes, grantExec, grantBytes, reservations int64
			if err = admin.QueryRow(ctx, `SELECT executions_spent,collected_bytes_spent,(SELECT policy_executions_spent FROM access_grant WHERE id=$2),(SELECT policy_collected_bytes_spent FROM access_grant WHERE id=$2),(SELECT count(*) FROM policy_occurrence WHERE acceptance_id=$1 AND reserved_capture_id IS NOT NULL) FROM policy_acceptance WHERE id=$1`, record.Record.ID, grant).Scan(&execs, &bytes, &grantExec, &grantBytes, &reservations); err != nil {
				t.Fatal(err)
			}
			wantBytes, wantExec, wantReservations := int64(0), int64(0), int64(0)
			if mode == "packet-policy" {
				wantBytes, wantExec, wantReservations = artifact.RecordingNativeLimit, 1, 1
			}
			if execs != 1 || bytes != wantBytes || grantExec != wantExec || grantBytes != wantBytes || reservations != wantReservations {
				t.Fatal("action mismatch/replay changed prospective pools", execs, bytes, grantExec, grantBytes, reservations)
			}
			t.Logf("actual Tick accepted executions=%d; native output=%d grant executions=%d output=%d reservations=%d", execs, bytes, grantExec, grantBytes, reservations)
		})
	}
}
