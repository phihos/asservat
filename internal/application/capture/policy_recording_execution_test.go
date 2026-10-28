package capture

import (
	"context"
	"errors"
	"testing"
	"time"

	authapp "asservat.local/asservat/internal/application/authorization"
	identities "asservat.local/asservat/internal/application/identity"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

// Synthetic current protected authority/settings ports; the real shared
// evaluator, request-owned policy identity and recorder compiler run below.
// This does not establish SQL admission or a collector permit.
type teamRecordingAuthority struct {
	f         *investigationFixture
	authority authorization.AcceptedPolicyAuthority
	reads     int
}

func (s *teamRecordingAuthority) AcceptedPolicyAuthority(context.Context, string) (authorization.AcceptedPolicySnapshot, error) {
	s.reads++
	return authorization.AcceptedPolicySnapshot{Authority: s.authority, ObservedAt: s.f.now, FreshUntil: s.f.now.Add(5 * time.Second), SourceUntil: s.f.now.Add(30 * time.Second)}, nil
}
func (s *teamRecordingAuthority) PolicyAutomationAuthority(ctx context.Context, a authorization.AcceptedPolicyAuthority, target authorization.Target) (authorization.AutomationProjection, error) {
	p, err := s.f.Permissions(ctx, target)
	return authorization.AutomationProjection{InstallationID: a.InstallationID, Delegation: a.Delegation, Envelope: authorization.AutomationEnvelope{AllowedActions: []string{"packetCapture"}, MaxLifetimeSeconds: 3600, MaxExecutions: a.Limits.MaxExecutions, MaxBytes: a.Limits.MaxBytes, MaxObservedBytes: a.Limits.MaxObservedBytes}, ObservedAt: s.f.now, FreshUntil: s.f.now.Add(30 * time.Second), Permissions: p}, err
}

type teamRecordingSettings struct {
	policy      identity.Policy
	issuers     []string
	unavailable bool
}

func (s *teamRecordingSettings) IdentityPolicy(_ context.Context, issuer string) (identity.Policy, error) {
	s.issuers = append(s.issuers, issuer)
	if s.unavailable {
		return identity.Policy{}, value.ErrUnavailable
	}
	return s.policy, nil
}
func newTeamRecordingFixture(t *testing.T) (*investigationFixture, *teamRecordingAuthority, *teamRecordingSettings, policyIdentity) {
	t.Helper()
	f := newInvestigationFixture()
	f.target.NodeUID, f.target.NodeBootID, f.target.Pin.NodeName = "", "", ""
	f.target.ExecutionClass, f.cap.ExecutionClass = artifact.ContextAPIExecution, artifact.ContextAPIExecution
	creator := f.actor
	creator.Subject = "departed-creator"
	owner := f.audience
	owner.Kind = "Group"
	owner.SubjectID = "current-team"
	f.audience = owner
	a := authorization.AcceptedPolicyAuthority{InstallationID: f.svc.InstallationID, PolicyUID: "packet-policy", Creator: creator, Executor: authorization.PolicyPrincipal(f.svc.InstallationID, "packet-policy"), ScopeDigest: artifact.Digest{77}, ClusterID: f.target.Request.ClusterID, NamespaceUID: f.target.Request.Namespace.UID, WorkloadUID: f.target.Request.Workload.UID, Delegation: identity.Revision{UID: owner.BasisUID, Generation: 1, Digest: owner.BasisDigest}, Owners: []artifact.AudienceAssignment{owner}, Actions: []string{"packetCapture"}, Limits: authorization.AutomationLimits{MaxExecutions: 10, MaxBytes: 64 << 20, MaxObservedBytes: 1 << 30}, IssuedAt: f.now.Add(-time.Minute), NotAfter: f.now.Add(30 * time.Minute)}
	authority := &teamRecordingAuthority{f: f, authority: a}
	f.actor = a.Executor
	f.svc.Eligibility = authapp.CaptureEligibility{Accepted: authority, Current: authority, Now: func() time.Time { return f.now }}
	f.svc.Recorders = availableRecording{f}
	settings := &teamRecordingSettings{policy: identity.Policy{Revision: identity.Revision{UID: "identity", Generation: 1, Digest: artifact.Digest{1}}, Issuer: creator.Issuer, ObservedAt: f.now, FreshUntil: f.now.Add(30 * time.Second), Clients: []identity.Client{{ID: "console", Kind: identity.Human, ClassQualified: true}}, EligibleGroups: []string{"current-team"}, GroupsAtIssueQualified: true, GroupMaxAge: time.Minute, RequireRecordingApproval: true}}
	f.svc.Approvals = settings
	f.svc.ReportPreviewFailure = func(stage string) { t.Log("team preview stage", stage) }
	current := newPolicyIdentity(context.Background(), authority, a, f.now.Add(45*time.Second), func() time.Time { return f.now })
	return f, authority, settings, current
}
func finiteTeamComposition() *planvalue.ProfileComposition {
	return networkComposition(planvalue.ProfileEdit{ActionID: "sample", Field: "actionExecutionMode", Text: "onTrigger"}, planvalue.ProfileEdit{ActionID: "sample", Field: "packetBefore", Text: "0s"}, planvalue.ProfileEdit{ActionID: "sample", Field: "packetAfter", Text: "2s"}, planvalue.ProfileEdit{ActionID: "sample", Field: "actionTimeout", Text: "10s"})
}
func TestTeamRecorderUsesAcceptedSettingsIssuerWithoutCreatorCredentials(t *testing.T) {
	f, a, settings, current := newTeamRecordingFixture(t)
	grants := &fakeGrants{}
	f.svc.Grants = grants
	preview, err := f.svc.PreviewComposition(context.Background(), current, f.compositionIntent(finiteTeamComposition()))
	if err != nil || !preview.Recordable || preview.Plan.Approval == nil {
		t.Fatal("accepted team recorder preview", err)
	}
	if len(settings.issuers) != 1 || settings.issuers[0] != a.authority.Creator.Issuer {
		t.Fatal("settings lookup did not use accepted provenance", settings.issuers)
	}
	for _, member := range preview.Preview.Audience {
		if member.SubjectID == a.authority.Creator.Subject || member.Kind == "Workload" {
			t.Fatal("invented creator/policy evidence access", member)
		}
	}
	// Reach the existing admission transaction without opening a human ad hoc
	// review. Its separate SQL implementation locks the original policy grant.
	admission := &retainedRecording{investigationFixture: f}
	f.svc.Admission = admission
	_, err = f.svc.Request(context.Background(), current, preview.Preview.ID, fixtureID(900))
	if !errors.Is(err, reachedRecordingAdmission) || len(admission.seen) != 1 || len(grants.requests) != 0 {
		t.Fatal("team request opened personal review or missed atomic admission", err, len(grants.requests))
	}
	if !admission.seen[0].Plan.Input.Recorder.RequireApproval {
		t.Fatal("team plan dropped protected recording approval requirement")
	}
}

func TestTeamRecorderSettingsRefuseMissingProvenanceAndOutage(t *testing.T) {
	for _, mode := range []string{"missing-settings", "settings-outage", "different-settings-issuer", "policy-shaped-identity"} {
		t.Run(mode, func(t *testing.T) {
			f, _, settings, current := newTeamRecordingFixture(t)
			var source interface {
				ResolveIdentity(context.Context) (identity.Identity, error)
			} = current
			switch mode {
			case "missing-settings":
				f.svc.Approvals = nil
			case "settings-outage":
				settings.unavailable = true
			case "different-settings-issuer":
				settings.policy.Issuer = "https://other.example.invalid"
			case "policy-shaped-identity":
				source = identityOnlyPolicy{resolve: current.ResolveIdentity}
			}
			if _, err := f.svc.PreviewComposition(context.Background(), source, f.compositionIntent(finiteTeamComposition())); err == nil || f.admissions.Load() != 0 {
				t.Fatal("unowned/unavailable protected settings permitted team recording", err)
			}
		})
	}
}

// Forwarding the identity alone must not also forward private accepted settings
// provenance. A separate wrapper deliberately exports no such method.
type identityOnlyPolicy struct {
	resolve func(context.Context) (identity.Identity, error)
}

func (s identityOnlyPolicy) ResolveIdentity(ctx context.Context) (identity.Identity, error) {
	return s.resolve(ctx)
}

func TestTeamRecorderSettingsProvenanceReusesExistingAcceptanceObservation(t *testing.T) {
	_, a, _, current := newTeamRecordingFixture(t)
	if _, err := current.ResolveIdentity(context.Background()); err != nil {
		t.Fatal(err)
	}
	reads := a.reads
	issuer, err := current.acceptedSettingsIssuer(context.Background())
	if err != nil || issuer != a.authority.Creator.Issuer || a.reads != reads {
		t.Fatal("provenance added acceptance read or selected another issuer", issuer, err, a.reads, reads)
	}
}
func TestTeamRawPredicateDoesNotReachAdmissionOrPersonalReview(t *testing.T) {
	f, _, _, current := newTeamRecordingFixture(t)
	f.svc.Filters = &stubFilters{}
	grants := &fakeGrants{}
	f.svc.Grants = grants
	composition := finiteTeamComposition()
	composition.Components[0].Edits = append(composition.Components[0].Edits, planvalue.ProfileEdit{ActionID: "sample", Field: "packetFilter", Text: "tcp[13] & 2 != 0"})
	preview, err := f.svc.PreviewComposition(context.Background(), current, f.compositionIntent(composition))
	if err != nil || preview.Recordable {
		t.Fatal("sensitive raw predicate became recordable", err)
	}
	if _, err = f.svc.Request(context.Background(), current, preview.Preview.ID, fixtureID(901)); !errors.Is(err, value.ErrRecorderUnavailable) || len(grants.requests) != 0 || f.admissions.Load() != 0 {
		t.Fatal("raw team plan bypassed observation gate or opened personal review", err)
	}
}

type teamRecordingAdmission struct {
	*investigationFixture
	seen []value.Admission
}

func (s *teamRecordingAdmission) AdmitReviewedContext(_ context.Context, _ string, a value.Admission) (value.Accepted, error) {
	s.seen = append(s.seen, a)
	return value.Accepted{}, value.ErrCapacity
}

// These ports must never be reached when real preview/request is refused by
// the original atomic capacity transaction.
type teamNeverStart struct{ t *testing.T }

func (s teamNeverStart) AcknowledgedCaptureIntent(context.Context, string) (audit.CaptureIntent, error) {
	s.t.Fatal("refused admission attempted capture audit")
	return audit.CaptureIntent{}, value.ErrUnavailable
}
func (s teamNeverStart) StartContext(context.Context, identities.CurrentIdentity, string) error {
	s.t.Fatal("refused admission attempted acquisition")
	return value.ErrUnavailable
}
func TestPolicyTriggerUsesActualRecorderPreviewAndOriginalOccurrenceKey(t *testing.T) {
	f, a, _, _ := newTeamRecordingFixture(t)
	admission := &teamRecordingAdmission{investigationFixture: f}
	f.svc.Admission = admission
	configuration, err := compiler.CompilePolicyRecorder(*finiteTeamComposition(), &stubFilters{})
	if err != nil {
		t.Fatal(err)
	}
	tgr := PolicyTrigger{Accepted: a, Now: func() time.Time { return f.now }, Capture: ContextSubmission{ContextInvestigation: f.svc, Intents: teamNeverStart{t}, Start: teamNeverStart{t}}}
	policy := value.RestartPolicy{Recorder: &configuration, RetentionSeconds: 60}
	observation := targets.RestartObservation{ClusterID: a.authority.ClusterID, Namespace: f.target.Request.Namespace}
	occurrence := value.PolicyOccurrence{ID: fixtureID(950), PodUID: f.target.Request.PodUID}
	id, refusal := tgr.capture(context.Background(), a.authority, policy, observation, f.target.Request.PodName, occurrence)
	if id != "" || refusal != "capacity" || len(admission.seen) != 1 {
		t.Fatal("trigger did not reach actual recorder admission exactly once", id, refusal, len(admission.seen))
	}
	in := admission.seen[0]
	if in.IdempotencyKey != occurrence.ID || in.Plan.Input.Executor != a.authority.Executor || in.Plan.Input.Recorder == nil || in.Plan.Input.Target.Target().PodUID != occurrence.PodUID || in.Plan.RecipeDigest != configuration.RecipeDigest {
		t.Fatal("trigger changed occurrence, real Pod, team executor or frozen recipe", in)
	}
	for _, preview := range f.previews {
		if preview.Intent.Diagnostic != "" || preview.Intent.Composition == nil || preview.Intent.Target.Kind != "Pod" || preview.Intent.Target.Name != f.target.Request.PodName {
			t.Fatal("trigger substituted pod-status or invented another Pod", preview.Intent)
		}
	}
}

func TestTeamRecorderSettingsChangesAfterPreviewDenyBeforeAdmission(t *testing.T) {
	for _, mode := range []string{"absent", "outage", "recording-requirement-changed", "issuer-changed"} {
		t.Run(mode, func(t *testing.T) {
			f, _, settings, current := newTeamRecordingFixture(t)
			preview, err := f.svc.PreviewComposition(context.Background(), current, f.compositionIntent(finiteTeamComposition()))
			if err != nil || !preview.Recordable {
				t.Fatal(err)
			}
			admission := &teamRecordingAdmission{investigationFixture: f}
			f.svc.Admission = admission
			switch mode {
			case "absent":
				f.svc.Approvals = nil
			case "outage":
				settings.unavailable = true
			case "recording-requirement-changed":
				settings.policy.RequireRecordingApproval = false
			case "issuer-changed":
				settings.policy.Issuer = "https://other.example.invalid"
			}
			if _, err = f.svc.Request(context.Background(), current, preview.Preview.ID, fixtureID(902)); err == nil || len(admission.seen) != 0 {
				t.Fatal("changed/missing settings reached team admission", err)
			}
		})
	}
}

type teamTriggerLedger struct {
	PolicyTriggerLedger
	ticks []value.PolicyTick
}

func (s *teamTriggerLedger) Tick(_ context.Context, in value.PolicyTick) ([]value.PolicyOccurrence, error) {
	s.ticks = append(s.ticks, in)
	return nil, nil
}

type triggerAcceptedRecord struct{ record *acceptedGrantPlanFixture }

func (s triggerAcceptedRecord) AcceptedPolicyAuthority(context.Context, string) (authorization.AcceptedPolicySnapshot, error) {
	snap := s.record.snapshot
	snap.IntentVersion = s.record.record.IntentVersion
	snap.SourceRevision = s.record.record.Source.Revision
	return snap, nil
}
func TestPolicyTriggerCompilesOnlyExactAcceptedRecorderBeforeTickSpend(t *testing.T) {
	for _, mode := range []string{"exact", "changed-interpretation", "raw-observation-unavailable"} {
		t.Run(mode, func(t *testing.T) {
			f, accepted, _ := newPolicyGrantPlanFixture(t)
			originalEdit := f.edit
			if mode != "exact" {
				f.edit = func(spec map[string]any) {
					originalEdit(spec)
					composition := spec["profileComposition"].(map[string]any)
					if mode == "changed-interpretation" {
						composition["maxDuration"] = "30s"
					} else {
						component := composition["components"].([]any)[0].(map[string]any)
						component["overrides"] = append(component["overrides"].([]any), map[string]any{"actionID": "sample", "field": "packetFilter", "value": "tcp[13] & 2 != 0"})
					}
				}
			}
			ledger := &teamTriggerLedger{}
			inv := newInvestigationFixture()
			trigger := PolicyTrigger{RootID: activationRoot, InstallationID: activationInstallation, RecipeName: "builtin-pod-status-v1", RecipeDigest: testRecipe, CompileRecorder: testPolicyRecorderCompiler, Ledger: ledger, Documents: f, Sources: f, Accepted: triggerAcceptedRecord{accepted}, Observer: f, Capture: ContextSubmission{ContextInvestigation: inv.svc, Intents: teamNeverStart{t}, Start: teamNeverStart{t}}, Audit: f, Now: func() time.Time { return f.now }}
			err := trigger.Tick(context.Background(), value.ActivePolicy{PolicyUID: "policy-uid", Name: "restarts"})
			switch mode {
			case "exact":
				if err != nil || len(ledger.ticks) != 1 || ledger.ticks[0].Policy.Recorder == nil {
					t.Fatal("exact accepted recorder never reached ordinary occurrence ledger", err)
				}
			case "changed-interpretation":
				if !errors.Is(err, value.ErrChanged) || len(ledger.ticks) != 0 {
					t.Fatal("reinterpreted accepted recorder spent trigger occurrence", err)
				}
			case "raw-observation-unavailable":
				if !errors.Is(err, value.ErrRecorderUnavailable) || len(ledger.ticks) != 0 {
					t.Fatal("raw recorder spent occurrence without live observation authority", err)
				}
			}
		})
	}
}
