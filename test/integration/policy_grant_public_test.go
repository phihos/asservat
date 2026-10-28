package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	authapp "asservat.local/asservat/internal/application/authorization"
	captureapp "asservat.local/asservat/internal/application/capture"
	configapp "asservat.local/asservat/internal/application/configuration"
	identities "asservat.local/asservat/internal/application/identity"
	planningapp "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/capture"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/transport/conversion"
	"asservat.local/asservat/internal/transport/presentation"
	"github.com/jackc/pgx/v5/pgxpool"
)

type publicPolicyIdentity struct{ i identity.Identity }

func (s *publicPolicyIdentity) ResolveIdentity(context.Context) (identity.Identity, error) {
	return s.i, nil
}

// The pinned corpus is genuine libpcap output for exactly this expression.
// Refuse other expressions rather than impersonating a general filter compiler.
type publicPolicyFilters struct{}

func (publicPolicyFilters) CompileFilter(expression string) (planvalue.CompiledFilter, error) {
	if expression != "tcp dst port 80" {
		return planvalue.CompiledFilter{}, planvalue.ErrInvalid
	}
	return (recordingCompiler{}).CompileFilter(expression)
}
func publicPolicyCompile(raw json.RawMessage) (planvalue.PolicyRecorderConfiguration, error) {
	var wire contracts.CaptureComposition
	if err := json.Unmarshal(raw, &wire); err != nil {
		return planvalue.PolicyRecorderConfiguration{}, err
	}
	composition, err := conversion.CompositionFromWire(wire)
	if err != nil || composition == nil {
		return planvalue.PolicyRecorderConfiguration{}, planvalue.ErrInvalid
	}
	return planningapp.CompilePolicyRecorder(*composition, publicPolicyFilters{})
}
func publicPolicySpec(t *testing.T, a authorization.AcceptedPolicyAuthority) []byte {
	t.Helper()
	spec := map[string]any{
		"target":    map[string]any{"cluster": a.ClusterID, "namespace": "app", "workloadRef": map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "name": "app"}, "maxPods": 1, "selection": "triggeringPod", "adoption": "pinUID"},
		"detectors": []any{map[string]any{"id": "crash", "kind": "exit", "options": map[string]any{"reasons": []any{"OOMKilled", "Error"}, "exitCodes": []any{137, 1}}}},
		"when":      map[string]any{"detector": "crash"},
		"budgets":   map[string]any{"cooldown": "5m", "burst": 2, "maxOccurrencesPerHour": 12, "maxConcurrentActions": 1},
		"retention": "1h", "suspended": false, "observation": map[string]any{"mode": "allAuthorized"}, "evaluation": map[string]any{"scope": "pod", "fireOnActivation": false, "rearmFor": "10s"},
		"profileComposition": map[string]any{"components": []any{map[string]any{"id": "net", "profileRef": map[string]any{"catalog": "builtin", "name": "network-connections", "version": "v1"}, "overrides": []any{
			map[string]any{"actionID": "sample", "field": "actionExecutionMode", "value": "onTrigger"},
			map[string]any{"actionID": "sample", "field": "packetBefore", "value": "0s"},
			map[string]any{"actionID": "sample", "field": "packetAfter", "value": "1s"},
			map[string]any{"actionID": "sample", "field": "actionTimeout", "value": "10s"},
			map[string]any{"actionID": "sample", "field": "packetFilter", "value": "tcp dst port 80"},
		}}}, "maxTotalBytes": 16 << 20, "maxDuration": "10s"},
	}
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestPublicPolicyGrantFixtureUsesSupportedCompilerInputs(t *testing.T) {
	spec := publicPolicySpec(t, authorization.AcceptedPolicyAuthority{ClusterID: "11111111-1111-4111-8111-111111111111"})
	compiled, err := captureapp.CompilePolicyWithRecorders(spec, planningapp.ContextRecipeName, planningapp.RecipeDigest(), publicPolicyCompile)
	if err != nil || compiled.Recorder == nil {
		t.Fatal("public fixture cannot compile actual protected configuration", err)
	}
	action := compiled.Recorder.Action
	if action.Filter != "tcp dst port 80" || action.ExecutionMode != "onTrigger" || action.Before != "0s" || action.After != "1s" || action.FilterInstructions != len(recordingProgram) {
		t.Fatal("public fixture review differs from supported compiler output", action)
	}
	if _, err := (publicPolicyFilters{}).CompileFilter("tcp port 443"); err == nil {
		t.Fatal("fixture corpus impersonated another filter")
	}
}

type publicPolicyDocuments struct {
	observation *capture.PolicySource
	spec        []byte
}

func (s publicPolicyDocuments) ReadPolicy(_ context.Context, name, uid string) (capture.PolicySource, []byte, error) {
	o := *s.observation
	if name != o.Name || uid != "" && uid != o.Revision.UID {
		return capture.PolicySource{}, nil, capture.ErrUnavailable
	}
	o.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
	o.FreshUntil = o.ObservedAt.Add(capture.PolicySourceInterval)
	return o, append([]byte(nil), s.spec...), nil
}

// Capture ports deliberately remain absent: this audit fixture cannot collect.
type publicPolicyNoCapture struct {
	presentation.ContextUseCase
	presentation.ContextProgressUseCase
}
type publicPolicyAuditObjects struct {
	auditapp.OperationObjects
	loseIntent, loseOutcome bool
}

func (s *publicPolicyAuditObjects) CreateOperationIntent(ctx context.Context, in audit.OperationIntent) (audit.Receipt, error) {
	r, e := s.OperationObjects.CreateOperationIntent(ctx, in)
	if e == nil && s.loseIntent {
		s.loseIntent = false
		return audit.Receipt{}, auditapp.ErrUnavailable
	}
	return r, e
}
func (s *publicPolicyAuditObjects) CreateOperationOutcome(ctx context.Context, in audit.OperationOutcome) (audit.Receipt, error) {
	r, e := s.OperationObjects.CreateOperationOutcome(ctx, in)
	if e == nil && s.loseOutcome {
		s.loseOutcome = false
		return audit.Receipt{}, auditapp.ErrUnavailable
	}
	return r, e
}

type publicPolicyProjection struct {
	actual authapp.WorkloadProjectionReader
	short  func(time.Time)
}

func (s publicPolicyProjection) WorkloadPermissions(ctx context.Context, target authorization.WorkloadTarget) (authorization.WorkloadProjection, error) {
	p, e := s.actual.WorkloadPermissions(ctx, target)
	if e == nil && s.short != nil {
		until := time.Now().UTC().Add(500 * time.Millisecond).Truncate(time.Microsecond)
		p.FreshUntil = identity.Earlier(p.FreshUntil, until)
		p.DeniesFreshUntil = identity.Earlier(p.DeniesFreshUntil, until)
		for n := range p.Allows {
			p.Allows[n].FreshUntil = identity.Earlier(p.Allows[n].FreshUntil, until)
		}
		s.short(until)
	}
	return p, e
}

// Real C03 + canonical operations + separately credentialed SQL/encrypted S3.
// Protected source, initial trust and verified IdP/step-up facts are
// synthetic. No Pod/capture is invented by the public request or attachment.
func qualifyPolicyGrantPublicOperations(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, permissions *postgres.Permissions, source *postgres.Policies, observation capture.PolicySource, author identity.Identity, root string, a authorization.AcceptedPolicyAuthority, acceptance string, spec []byte, batch cfg.PermissionBatch) {
	t.Helper()
	clock := func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }
	// Add a real independently accepted reviewer while preserving the original
	// automation sponsor assignment (the test does not invent current rights).
	reviewerBasis := cfg.PermissionBasis{Resource: cfg.Resource{Kind: "AccessBinding", UID: custodyID(), Generation: 1, ResourceVersion: "reviewer-v1", SpecDigest: artifact.Digest{79}}, Scope: batch.Bases[0].Scope, Effect: "Allow", Subjects: []cfg.Subject{{Kind: "User", Issuer: author.Principal.Issuer, ID: "policy-public-reviewer"}}, Roles: []string{"action-approver"}}
	reviewerBasis.ScopeDigest = configapp.PermissionScopeDigest(reviewerBasis)
	batch.Initial = nil
	batch.Bases[0].Continuous = true
	batch.Bases = append(batch.Bases, reviewerBasis)
	batch.RequestID = custodyID()
	batch.InputDigest[0]++
	batch.ObservedAt = clock()
	batch.FreshUntil = batch.ObservedAt.Add(5 * time.Second)
	accepted, e := permissions.AcceptPermissions(ctx, batch)
	if e != nil {
		t.Fatal("public reviewer acceptance", e)
	}
	batch.ExpectedSequence = accepted.Sequence
	for range 2 {
		if e = (auditapp.AuthorityPublisher{Ledger: permissions, Objects: &objectstore.AuthorityObjects{Store: store, Seal: keys, Open: keys}}).PublishAuthority(ctx); e != nil {
			t.Fatal(e)
		}
	}
	hubRole := narrowRole(t, ctx, admin, "policy_public_hub_", "synthetic-public-policy", func(role string) []string {
		g, ok := postgres.PublicRuntimeRoleGrantSQL("hub-runtime", role)
		if !ok {
			t.Fatal("installed hub role absent")
		}
		return g
	})
	hub := poolFor(hubRole, "synthetic-public-policy")
	defer hub.Close()
	currentPermissions, e := postgres.NewPermissions(ctx, hub, root)
	if e != nil {
		t.Fatal(e)
	}
	policyStore, e := postgres.NewPolicies(ctx, hub, root, a.InstallationID)
	if e != nil {
		t.Fatal(e)
	}
	guard, e := postgres.NewRecoveryTransactionGuard(root, a.InstallationID)
	if e != nil {
		t.Fatal(e)
	}
	grants, e := postgres.NewAccessGrants(ctx, hub, root, guard)
	if e != nil {
		t.Fatal(e)
	}
	recovery, e := postgres.NewRecoveryReader(ctx, hub, a.InstallationID)
	if e != nil {
		t.Fatal(e)
	}
	statuses, e := postgres.NewPolicyTriggers(ctx, hub, root, a.InstallationID)
	if e != nil {
		t.Fatal(e)
	}
	settingsRole := narrowRole(t, ctx, admin, "policy_public_settings_", "synthetic-public-settings", func(role string) []string {
		g, ok := postgres.PublicRuntimeRoleGrantSQL("permission-accept", role)
		if !ok {
			t.Fatal("settings duty absent")
		}
		return g
	})
	settingsPool := poolFor(settingsRole, "synthetic-public-settings")
	defer settingsPool.Close()
	settings, e := postgres.NewPolicies(ctx, settingsPool, root, a.InstallationID)
	if e != nil {
		t.Fatal(e)
	}
	configPool := poolFor("operation_audit_config_runtime", "synthetic-operation-config")
	defer configPool.Close()
	config, e := postgres.New(ctx, configPool)
	if e != nil {
		t.Fatal(e)
	}
	journalPool := poolFor("operation_audit_runtime", "synthetic-operation-journal")
	defer journalPool.Close()
	ackPool := poolFor("operation_audit_ack_runtime", "synthetic-operation-ack")
	defer ackPool.Close()
	objects := &publicPolicyAuditObjects{OperationObjects: &objectstore.OperationAuditObjects{Store: store, Seal: keys, Open: keys}}
	gates := map[string]auditapp.OperationAuditor{}
	for _, lane := range []string{"normal", "resolution"} {
		j, e := postgres.NewOperationJournal(ctx, journalPool, root, lane, guard)
		if e != nil {
			t.Fatal(e)
		}
		ack, e := postgres.NewOperationAcknowledgements(ctx, ackPool, root, lane, guard)
		if e != nil {
			t.Fatal(e)
		}
		gates[lane] = auditapp.OperationAuditor{Journal: j, Acknowledgements: ack, Objects: objects, Now: clock}
	}
	refresh := func() {
		t.Helper()
		now := clock()
		batch.ObservedAt = now
		batch.FreshUntil = now.Add(5 * time.Second)
		if e := permissions.RefreshPermissions(ctx, batch); e != nil {
			t.Fatal(e)
		}
		periods := identity.PolicyGrantSettingsObservation{Issuer: author.Principal.Issuer, Revision: identity.Revision{UID: "public-policy-periods", Generation: 1, Digest: artifact.Digest{80}}, ObservedAt: now, FreshUntil: now.Add(30 * time.Second), Values: identity.PolicyGrantApproval{DefaultAge: time.Hour, MaxAge: time.Hour, RenewalNotice: time.Minute}}
		if e := settings.AcceptPolicyGrantSettings(ctx, periods); e != nil {
			t.Fatal(e)
		}
		for _, lane := range []string{"normal", "resolution"} {
			if e := config.ProvisionOperationAuditPool(ctx, auditapp.OperationAuditPool{RootID: root, Lane: lane, AccountVersion: "accounts-v1", Accounts: 4, RecordsPerAccount: 64, RetainedSeconds: 3600, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), ValidUntil: now.Add(time.Hour)}); e != nil {
				t.Fatal(e)
			}
		}
	}
	author.Scopes = []string{"evidence:read", "evidence:capture"}
	actor := &publicPolicyIdentity{i: author}
	reviewer := &publicPolicyIdentity{i: author}
	reviewer.i.Principal.Subject = "policy-public-reviewer"
	reviewer.i.Groups = nil
	reviewer.i.Assurance = identity.Assurance{ACR: "fixture-mfa", AuthenticatedAt: clock().Add(-time.Minute), StepUpUntil: clock().Add(4 * time.Minute)}
	docs := publicPolicyDocuments{observation: &observation, spec: spec}
	plans := captureapp.PolicyGrantPlans{Accepted: policyStore, Documents: docs, Sources: source, CompileRecorder: publicPolicyCompile, RecipeName: planningapp.ContextRecipeName, RecipeDigest: planningapp.RecipeDigest(), Now: clock}
	service := authapp.GrantService{RootID: root, InstallationID: a.InstallationID, Permissions: currentPermissions, WorkloadPermissions: currentPermissions, PolicyPlans: plans, PolicyRequests: grants, ApprovalSettings: grants, Store: grants, Recovery: recovery, NewID: custodyID, Now: clock}
	const origin = "https://asservat.example.invalid"
	grantOps, e := presentation.NewGrantOperations(origin, clock, custodyID, service)
	if e != nil {
		t.Fatal(e)
	}
	closed := publicPolicyNoCapture{}
	base, e := presentation.NewContextOperations(presentation.ContextOperationsConfig{PublicOrigin: origin, Now: clock, NewID: custodyID}, closed, closed)
	if e != nil {
		t.Fatal(e)
	}
	inner, e := presentation.NewInvestigationOperations(base, nil)
	if e != nil {
		t.Fatal(e)
	}
	inner, e = presentation.NewInvestigationGrantOperations(inner, grantOps)
	if e != nil {
		t.Fatal(e)
	}
	activation := captureapp.PolicyActivation{RootID: root, InstallationID: a.InstallationID, Documents: docs, Sources: source, Ledger: statuses, GrantAttachments: policyStore, Recovery: recovery, Now: clock}
	status := captureapp.PolicyStatusService{RootID: root, InstallationID: a.InstallationID, Documents: docs, Ledger: statuses, Permissions: currentPermissions, Recovery: recovery, Now: clock}
	stop := captureapp.PolicyDeactivation{RootID: root, InstallationID: a.InstallationID, Documents: docs, Ledger: statuses, Permissions: currentPermissions, Recovery: recovery, Now: clock}
	policyOps, e := presentation.NewPolicyOperations(origin, clock, custodyID, activation, status, stop)
	if e != nil {
		t.Fatal(e)
	}
	inner, e = presentation.NewInvestigationPolicyOperations(inner, policyOps)
	if e != nil {
		t.Fatal(e)
	}
	mac, e := auditapp.NewOperationMAC("audit-v1", bytes.Repeat([]byte{1}, 32), "accounts-v1", bytes.Repeat([]byte{2}, 32))
	if e != nil {
		t.Fatal(e)
	}
	defer mac.Close()
	audited, e := presentation.NewAuditedOperations(presentation.AuditedOperationsConfig{RootID: root, Retention: time.Hour, NormalConcurrency: 2, ResolutionConcurrency: 1, PerPrincipalConcurrency: 1, NormalPerSecond: 100, ResolutionPerSecond: 100, Now: clock, NewID: custodyID}, inner, gates["normal"], gates["resolution"], mac)
	if e != nil {
		t.Fatal(e)
	}
	call := func(current identities.CurrentIdentity, name string, input any) (map[string]any, error) {
		refresh()
		raw, e := json.Marshal(input)
		if e != nil {
			t.Fatal(e)
		}
		reply, e := audited.Call(ctx, current, name, raw)
		if e != nil {
			return nil, e
		}
		var result map[string]any
		if json.Unmarshal(reply.Body, &result) != nil {
			t.Fatal("canonical public reply absent")
		}
		return result, nil
	}
	request := map[string]any{"policy_uid": a.PolicyUID, "policy_name": observation.Name, "idempotency_key": "public-original", "limits": map[string]any{"max_executions": 2, "max_collected_bytes": 32 << 20, "max_observed_bytes": 0}}
	counts := func() (int64, int64) {
		var rows, receipts int64
		if e := admin.QueryRow(ctx, "SELECT count(*) FROM access_grant WHERE root_id=$1", root).Scan(&rows); e != nil {
			t.Fatal(e)
		}
		if e := admin.QueryRow(ctx, "SELECT count(*) FROM policy_grant_attachment WHERE root_id=$1", root).Scan(&receipts); e != nil {
			t.Fatal(e)
		}
		return rows, receipts
	}
	sourceObserved := func() time.Time {
		var observed time.Time
		if e := admin.QueryRow(ctx, "SELECT observed_at FROM policy_source WHERE root_id=$1 AND policy_uid=$2", root, a.PolicyUID).Scan(&observed); e != nil {
			t.Fatal(e)
		}
		return observed
	}
	beforeIntent := sourceObserved()
	objects.loseIntent = true
	if _, e = call(actor, "request_policy_grant", request); e == nil {
		t.Fatal("unknown encrypted intent allowed public request")
	}
	if !sourceObserved().Equal(beforeIntent) {
		t.Fatal("source observation mutated before acknowledged request intent")
	}
	if rows, receipts := counts(); rows != 0 || receipts != 0 {
		t.Fatal("mutation before acknowledged public intent", rows, receipts)
	}
	objects.loseOutcome = true
	if _, e = call(actor, "request_policy_grant", request); e == nil {
		t.Fatal("unknown encrypted outcome returned public success")
	}
	if rows, receipts := counts(); rows != 1 || receipts != 0 {
		t.Fatal("unknown outcome erased or duplicated request", rows, receipts)
	}
	result, e := call(actor, "request_policy_grant", request)
	if e != nil || result["status"] != "ok" {
		t.Fatal("same-key public request recovery", result, e)
	}
	data := result["data"].(map[string]any)
	grantID := data["grant_id"].(string)
	if data["kind"] != "policy" || data["capture_id"] != nil || data["can_decide"] != false {
		t.Fatal("policy request invented manual/result rights", data)
	}
	original, e := grants.Grant(ctx, grantID)
	if e != nil {
		t.Fatal(e)
	}
	decision := map[string]any{"grant_id": grantID, "decision": "approve", "reason": "independent fixture review", "idempotency_key": "public-review"}
	if result, e = call(actor, "decide_review", decision); e != nil || result["status"] != "error" || result["data"].(map[string]any)["code"] != "SelfApprovalRefused" {
		t.Fatal("requester independently approved", result, e)
	}
	plain := reviewer.i
	reviewer.i.Assurance = identity.Assurance{}
	if result, e = call(reviewer, "decide_review", decision); e != nil || result["status"] != "error" || result["data"].(map[string]any)["code"] != "StepUpRequired" {
		t.Fatal("approval omitted verified step-up", result, e)
	}
	reviewer.i = plain
	if result, e = call(reviewer, "decide_review", decision); e != nil || result["status"] != "ok" {
		t.Fatal("independent public approval", result, e)
	}
	attachment := map[string]any{"policy_name": observation.Name, "grant_id": grantID, "idempotency_key": "public-attachment"}
	beforeIntent = sourceObserved()
	objects.loseIntent = true
	if _, e = call(actor, "activate_policy", attachment); e == nil {
		t.Fatal("unknown attachment intent returned success")
	}
	if !sourceObserved().Equal(beforeIntent) {
		t.Fatal("source observation mutated before acknowledged attachment intent")
	}
	if _, receipts := counts(); receipts != 0 {
		t.Fatal("attachment ran before encrypted intent")
	}
	objects.loseOutcome = true
	if _, e = call(actor, "activate_policy", attachment); e == nil {
		t.Fatal("unknown attachment outcome returned success")
	}
	if _, receipts := counts(); receipts != 1 {
		t.Fatal("unknown outcome discarded immutable attachment", receipts)
	}
	// A changed-and-restored authored reference clears the pointer. Exact public
	// retry returns its historical receipt without restoring current attachment.
	for _, ref := range []string{grantID, ""} {
		observation.Revision.Generation++
		observation.Revision.Digest[0]++
		observation.AuthoredGrantRef = ref
		observed, _, e := docs.ReadPolicy(ctx, observation.Name, a.PolicyUID)
		if e != nil {
			t.Fatal(e)
		}
		if e := source.ObservePolicy(ctx, observed); e != nil {
			t.Fatal(e)
		}
	}
	if result, e = call(actor, "activate_policy", attachment); e != nil || result["status"] != "ok" || result["data"].(map[string]any)["replay"] != true {
		t.Fatal("same-key attachment recovery", result, e)
	}
	if result, e = call(actor, "get_policy_status", map[string]any{"policy_name": observation.Name}); e != nil || result["status"] != "ok" || result["data"].(map[string]any)["attached_grant_id"] != nil {
		t.Fatal("historical receipt became current pointer", result, e)
	}
	after, e := grants.Grant(ctx, grantID)
	if e != nil || !after.RequestedAt.Equal(original.RequestedAt) || !after.PolicyNotAfter.Equal(original.PolicyNotAfter) || after.PolicySpend != (authorization.PolicyGrantSpend{}) {
		t.Fatal("public replay renewed original period/spend", after, e)
	}
	current, e := statuses.Status(ctx, a.PolicyUID)
	if e != nil || current.ActiveID != acceptance || current.ExecutionsSpent != 0 || current.CollectedBytesSpent != 0 {
		t.Fatal("public controls reaccepted or spent policy", current, e)
	}
	var acknowledged, uncertain int64
	if e = admin.QueryRow(ctx, "SELECT count(*) FILTER(WHERE intent_receipt IS NOT NULL AND outcome_receipt IS NOT NULL),count(*) FILTER(WHERE outcome IS NOT NULL AND outcome_receipt IS NULL) FROM operation_audit WHERE root_id=$1", root).Scan(&acknowledged, &uncertain); e != nil || acknowledged < 5 || uncertain < 2 {
		t.Fatal("independent encrypted receipts/uncertainty absent", acknowledged, uncertain, e)
	}
	t.Logf("public policy request/review/attachment: one grant, one immutable attachment, original expiry, zero execution/output spend; encrypted acknowledged=%d uncertain outcomes=%d", acknowledged, uncertain)
	// Actual original reviewer and step-up bounds under a held SQL grant row.
	for _, mode := range []string{"eligibility", "step-up"} {
		t.Run("held-row-original-"+mode+"-deadline", func(t *testing.T) {
			refresh()
			input := authapp.PolicyGrantRequestInput{PolicyUID: a.PolicyUID, PolicyName: observation.Name, IdempotencyKey: "held-" + mode, Limits: authorization.AutomationLimits{MaxExecutions: 1, MaxBytes: 16 << 20}}
			pending, _, e := service.RequestPolicy(ctx, actor, input)
			if e != nil {
				t.Fatal(e)
			}
			tx, e := admin.Begin(ctx)
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback(context.Background())
			if _, e = tx.Exec(ctx, "SELECT id FROM access_grant WHERE id=$1 FOR UPDATE", pending.ID); e != nil {
				t.Fatal(e)
			}
			until := make(chan time.Time, 1)
			deciding := service
			as := &publicPolicyIdentity{i: reviewer.i}
			if mode == "eligibility" {
				deciding.WorkloadPermissions = publicPolicyProjection{actual: currentPermissions, short: func(deadline time.Time) { until <- deadline }}
			} else {
				deadline := clock().Add(500 * time.Millisecond)
				as.i.Assurance.StepUpUntil = deadline
				until <- deadline
			}
			done := make(chan error, 1)
			go func() {
				_, _, e := deciding.Decide(ctx, as, pending.ID, true, "held original deadline", "held-decision")
				done <- e
			}()
			deadline := <-until
			seen := false
			observeEnd := time.Now().Add(400 * time.Millisecond)
			for time.Now().Before(observeEnd) {
				if e := admin.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename=$1 AND wait_event_type='Lock' AND query LIKE '%access_grant%')", hubRole).Scan(&seen); e != nil {
					t.Fatal(e)
				}
				if seen {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !seen {
				t.Fatal("decision did not reach actual held-row SQL wait")
			}
			timer := time.NewTimer(time.Until(deadline.Add(1200 * time.Millisecond)))
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if e = tx.Commit(ctx); e != nil {
				t.Fatal(e)
			}
			e = <-done
			var decision *string
			if readErr := admin.QueryRow(ctx, "SELECT decision FROM access_grant WHERE id=$1", pending.ID).Scan(&decision); readErr != nil || decision != nil {
				t.Fatal("decision committed after original bound despite hidden reply", decision, readErr, e)
			}
			if e == nil {
				t.Fatal("expired original review returned success")
			}
			if errors.Is(e, context.Canceled) {
				t.Log("original deadline canceled SQL before effect")
			}
		})
	}
}
