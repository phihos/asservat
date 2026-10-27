package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	access "asservat.local/asservat/internal/application/authorization"
	executionapp "asservat.local/asservat/internal/application/execution"
	identities "asservat.local/asservat/internal/application/identity"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/capture"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/internal/transport/contextstart"
	admission "k8s.io/api/admissionregistration/v1"
	authn "k8s.io/api/authentication/v1"
	authz "k8s.io/api/authorization/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

func regionalObservationID(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }

// The real StartContext, router, HubOperations, runner, evaluator and protected
// capability adapter compose here. SQL, identity, retention and the regional
// replies are explicitly synthetic; the test stops at the first SQL preparation.
// Loopback TLS counts provider calls, not native API latency or admission proof.
type regionalObservationFixture struct {
	publicContextOperationPorts
	t                       *testing.T
	now                     time.Time
	identity                identity.Identity
	work                    executionapp.APIContextWork
	target                  targets.PodResolution
	retention               privacy.Resolution
	recovery                artifact.RecoveryProof
	process                 value.APIProcessObservation
	receiver                fleet.APIContextReceiver
	workReads, preparations int
	check                   executionapp.APIExecutionCheck
	signed                  fleet.APIContextWork
}

func (f *regionalObservationFixture) Resolve(ctx context.Context, _ string) (identity.Identity, error) {
	return f.identity, ctx.Err()
}
func (f *regionalObservationFixture) RecoveryState(ctx context.Context) (artifact.RecoveryProof, error) {
	return f.recovery, ctx.Err()
}
func (f *regionalObservationFixture) ReadAPIContextWork(ctx context.Context, id string, who identity.Identity, recovery artifact.RecoveryProof) (executionapp.APIContextWork, error) {
	f.workReads++
	if id != f.work.Accepted.CaptureID || who.Principal != f.identity.Principal || recovery != f.recovery {
		f.t.Fatal("changed accepted-read inputs")
	}
	return f.work, ctx.Err()
}
func (f *regionalObservationFixture) Permissions(ctx context.Context, target authorization.Target) (authorization.Projection, error) {
	return authorization.Projection{Target: target, Revision: f.identity.Policy, ObservedAt: f.now, FreshUntil: f.identity.ValidUntil, DeniesObservedAt: f.now, DeniesFreshUntil: f.identity.ValidUntil, DeniesComplete: true, Allows: []authorization.CurrentAssignment{{Audience: f.work.Accepted.Expectation.Audience[0], ObservedAt: f.now, FreshUntil: f.identity.ValidUntil}}}, ctx.Err()
}
func (f *regionalObservationFixture) ResolveRetention(ctx context.Context, _ privacy.Input) (privacy.Resolution, error) {
	return f.retention, ctx.Err()
}

type regionalObservationRetention struct{ f *regionalObservationFixture }

func (r regionalObservationRetention) Resolve(ctx context.Context, in privacy.Input) (privacy.Resolution, error) {
	return r.f.ResolveRetention(ctx, in)
}
func (f *regionalObservationFixture) SignAPIContextWork(ctx context.Context, work fleet.APIContextWork) ([]byte, error) {
	f.signed = work
	return []byte("synthetic-signer-no-native-authority"), ctx.Err()
}
func (f *regionalObservationFixture) PrepareAPIExecution(ctx context.Context, check executionapp.APIExecutionCheck) (value.APIExecution, bool, error) {
	f.preparations++
	f.check = check
	if !check.Valid(time.Now()) || ctx.Err() != nil {
		f.t.Fatal("invalid original authority at preparation")
	}
	// No synthetic SQL row or key effect is created. The count establishes that
	// the actual bootstrap-to-runner path reached this first boundary.
	return value.APIExecution{}, false, value.ErrUnavailable
}

// This protocol peer supplies only ResolvePod/ReadProcess and a finish receipt.
// Any attempt to wrap, start or acquire before the refused preparation fails.
type regionalObservationStream struct {
	f       *regionalObservationFixture
	ctx     context.Context
	replies []contracts.APIContextFrame
}

func (s *regionalObservationStream) Context() context.Context { return s.ctx }
func (s *regionalObservationStream) Close() error             { return nil }
func (s *regionalObservationStream) AwaitWork(context.Context) (contracts.APIContextFrame, fleet.APIContextReceiver, error) {
	panic("hub-only synthetic stream")
}
func (s *regionalObservationStream) Receive(ctx context.Context) (contracts.APIContextFrame, error) {
	if ctx.Err() != nil {
		return contracts.APIContextFrame{}, ctx.Err()
	}
	if len(s.replies) == 0 {
		return contracts.APIContextFrame{}, value.ErrUnavailable
	}
	r := s.replies[0]
	s.replies = s.replies[1:]
	return r, nil
}
func (s *regionalObservationStream) Send(ctx context.Context, frame contracts.APIContextFrame) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	switch frame.Kind {
	case contracts.APIContextWorkFrame, contracts.APIContextReceiptFrame:
		return nil
	case contracts.APIContextOperationRequestFrame:
		op, err := contracts.DecodeAPIContextOperation(frame.Payload)
		if err != nil {
			return err
		}
		var body any
		switch op.Method {
		case "resolve-pod":
			var requested targets.Request
			if json.Unmarshal(op.Body, &requested) != nil || requested != s.f.work.Target {
				return value.ErrDenied
			}
			body = s.f.target
		case "read-process":
			body = s.f.process
		case "finish":
			var state string
			if json.Unmarshal(op.Body, &state) != nil {
				return value.ErrInvalid
			}
			b, _ := contracts.EncodeAPIContextResult(contracts.APIContextResult{Format: contracts.APIContextExchangeFormat, ExchangeID: s.f.signed.Channel.ExchangeID, CaptureID: s.f.signed.CaptureID, State: state})
			defer func() {
				s.replies = append(s.replies, contracts.APIContextFrame{Kind: contracts.APIContextResultFrame, Payload: b})
			}()
		default:
			s.f.t.Errorf("unexpected regional effect %s", op.Method)
			return value.ErrDenied
		}
		var b []byte
		if body != nil {
			b, _ = json.Marshal(body)
		}
		r, err := contracts.EncodeAPIContextOperationReply(contracts.APIContextOperationReply{Format: contracts.APIContextExchangeFormat, Sequence: op.Sequence, Method: op.Method, Body: b})
		if err != nil {
			return err
		}
		s.replies = append(s.replies, contracts.APIContextFrame{Kind: contracts.APIContextOperationResponseFrame, Payload: r})
		return nil
	default:
		return value.ErrInvalid
	}
}

func newRegionalObservationFixture(t *testing.T) (*regionalObservationFixture, planning.ContextCapability, contracts.ContextCapabilitySettings) {
	t.Helper()
	id := regionalObservationID
	now := time.Now().UTC().Truncate(time.Microsecond)
	rev := identity.Revision{UID: id(40), Generation: 1, Digest: [32]byte{40}}
	f := &regionalObservationFixture{t: t, now: now}
	f.identity = identity.Identity{Principal: identity.Principal{Issuer: "https://identity.example.test", Subject: "dev", ClientID: "console", Kind: identity.Human}, Policy: rev, Scopes: []string{"evidence:capture"}, Groups: []string{"team"}, VerifiedAt: now, ValidUntil: now.Add(5 * time.Second)}
	f.recovery = artifact.RecoveryProof{InstallationID: id(44), IssuerEpoch: id(3), Revision: rev, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	image := artifact.Digest{6}
	projection := compiler.ProjectionDigest()
	settings := contracts.ContextCapabilitySettings{Format: contracts.ContextCapabilityFormat, RootID: id(41), InstallationID: id(44), ClusterID: id(2), IssuerEpoch: id(3), Revision: 1, Enabled: true, ExecutionClass: string(artifact.ContextAPIExecution), CollectorVersion: "synthetic", CollectorImageDigest: hex.EncodeToString(image[:]), ProjectionDigest: hex.EncodeToString(projection[:])}
	raw, _ := json.Marshal(settings)
	canonical := jsontext.Value(raw)
	if err := canonical.Canonicalize(); err != nil {
		t.Fatal(err)
	}
	cap := planning.ContextCapability{ExecutionClass: artifact.ContextAPIExecution, Enabled: true, Revision: identity.Revision{UID: id(49), Generation: 1, Digest: sha256.Sum256(canonical)}, CollectorVersion: settings.CollectorVersion, CollectorImageDigest: image, ProjectionDigest: projection, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	e := artifact.ContextExpectation{Registration: artifact.Registration{Location: artifact.Location{ClusterID: id(2), ArtifactID: id(16), AttemptID: id(11)}, StoreID: id(17), AllocationID: id(18), PoolRevision: 1, AllocationRevision: 1, NativeLimit: 4096, AnchorAt: now, WriteUntil: now.Add(time.Minute), ExpiresAt: now.Add(time.Minute), DeleteBy: now.Add(90 * time.Second)}, CaseID: id(21), OccurrenceID: id(22), PodUID: id(9), Namespace: "payments", NamespaceUID: id(23), WorkloadUID: id(24), CollectorVersion: "synthetic", CollectorImageDigest: image, CaptureUID: id(10), ActionID: "pod-status", DataClass: "metadata", PurposeRef: "diagnostics", Audience: []artifact.AudienceAssignment{{Kind: "Group", Issuer: f.identity.Principal.Issuer, SubjectID: "team", Role: "workload-maintainer", BasisKind: "AccessBinding", BasisUID: id(25), AssignmentID: id(26), BasisDigest: artifact.Digest{8}}}, RequestedAgeSeconds: 60, MaximumAgeSeconds: 120, DeletionBudgetSeconds: 30, RetentionRules: []artifact.RetentionRule{{UID: id(27), Generation: 1, Digest: artifact.Digest{9}}}, TriggeredAt: now, ExecutionClass: artifact.ContextAPIExecution}
	f.target = targets.PodResolution{ExecutionClass: artifact.ContextAPIExecution, Request: targets.Request{ClusterID: id(2), Namespace: cfg.NamespaceRef{Name: e.Namespace, UID: e.NamespaceUID}, Workload: cfg.WorkloadRef{Kind: "StatefulSet", Name: "api", UID: e.WorkloadUID}, PodName: "api-0", PodUID: e.PodUID}, Pin: artifact.PinnedPod{Namespace: e.Namespace, NamespaceUID: e.NamespaceUID, Name: "api-0", UID: e.PodUID, ControllerUID: e.WorkloadUID}, PodResourceVersion: "1", WorkloadResourceVersion: "1", ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	proof := artifact.RetentionProof{RootID: id(41), ClusterID: id(2), NamespaceUID: e.NamespaceUID, WorkloadUID: e.WorkloadUID, PodUID: e.PodUID, Topology: rev, Policy: rev, Selectors: rev, SourceCount: 1, ObservedAt: now, ValidUntil: now.Add(5 * time.Second), Sources: [2]artifact.RetentionSourceVersion{{ClusterID: id(2), ControlNamespaceUID: id(42), Epoch: id(43), Hub: true, ProtectionDigest: artifact.Digest{1}, SnapshotDigest: artifact.Digest{2}, Acceptance: rev}}}
	f.retention = privacy.Resolution{Target: f.target.Target(), PolicyRevision: rev, PurposeRef: e.PurposeRef, PrivacyClass: "potentialPersonalData", EvidenceType: "context", RequestedSeconds: e.RequestedAgeSeconds, MaximumSeconds: e.MaximumAgeSeconds, DeletionBudgetSeconds: e.DeletionBudgetSeconds, Policies: e.RetentionRules, Deadlines: privacy.Deadlines{AnchorAt: e.Registration.AnchorAt, ExpiresAt: e.Registration.ExpiresAt, DeleteBy: e.Registration.DeleteBy}, ValidUntil: now.Add(5 * time.Second), Proof: proof}
	plan, err := compiler.CompileContext(planning.ContextInput{CaptureID: e.CaptureUID, CaseID: e.CaseID, Executor: f.identity.Principal, Deadline: e.Registration.WriteUntil, Target: f.target, Capability: cap, Retention: f.retention}, now)
	if err != nil {
		t.Fatal(err)
	}
	e.PlanDigest, e.RecipeDigest = plan.ScopeDigest, plan.RecipeDigest
	f.work = executionapp.APIContextWork{Accepted: capture.Accepted{CaptureID: e.CaptureUID, State: capture.IntentAudited, ScopeDigest: e.PlanDigest, Expectation: e, Pin: f.target.Pin, CreatedAt: now, Deadline: e.Registration.WriteUntil}, Target: f.target.Request, Actor: f.identity.Principal, IntentDigest: artifact.Digest{1}}
	f.process = value.APIProcessObservation{Binding: value.APIProcessBinding{InstallationID: id(44), ClusterID: id(2), IssuerEpoch: id(3), NamespaceUID: id(45), AccountUID: id(46), PodUID: id(47), ProcessEpoch: id(48), StartupDigest: artifact.Digest{1}, ImageDigest: image}, CheckedAt: now, ValidUntil: now.Add(5 * time.Second)}
	channel := fleet.APIContextChannel{RootID: id(41), ExchangeID: id(50), Challenge: id(51), Hub: fleet.OwnerBinding{InstallationID: id(44), ClusterID: id(52), IssuerEpoch: id(3), PodUID: id(53), ProcessEpoch: id(54)}, Connector: fleet.ConnectorProcessIdentity{Binding: fleet.PeerBinding{InstallationID: id(44), ClusterID: id(2), IssuerEpoch: id(3), PeerID: id(55), Role: fleet.ConnectorPeer}, PodUID: id(47), ProcessEpoch: id(56)}, ConnectorLeaf: artifact.Digest{1}, Executor: fleet.APIContextExecutor{NamespaceUID: id(45), AccountUID: id(46), PodUID: id(47), ProcessEpoch: id(48), StartupDigest: artifact.Digest{1}, ImageDigest: image}}
	f.receiver = fleet.APIContextReceiver{Channel: channel, ObservedAt: now, ValidUntil: now.Add(5 * time.Second)}
	return f, cap, settings
}

func regionalObservationCapability(t *testing.T, f *regionalObservationFixture, settings contracts.ContextCapabilitySettings) (*kube.ContextCapabilitySource, *atomic.Int64, *atomic.Int64) {
	t.Helper()
	id := regionalObservationID
	control := cfg.NamespaceRef{Name: "control", UID: id(57)}
	plan := cfg.ConfigMapAdministration{Name: "capability-guard", ControlNamespace: control, SourceName: "context-capability", Administrators: []cfg.KubernetesActor{{Kind: "User", Name: "admin"}}}
	p, b, err := kube.ContextCapabilityAdmission(plan)
	if err != nil {
		t.Fatal(err)
	}
	p.UID = "policy"
	p.Generation = 1
	p.ResourceVersion = "1"
	p.Status.ObservedGeneration = 1
	p.Status.TypeChecking = &admission.TypeChecking{}
	b.UID = "binding"
	b.ResourceVersion = "1"
	raw, _ := json.Marshal(settings)
	observerCalls, probeCalls := &atomic.Int64{}, &atomic.Int64{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		reply := func(v any) { _ = json.NewEncoder(w).Encode(v) }
		if r.Header.Get("Authorization") == "Bearer observer" {
			observerCalls.Add(1)
		} else if r.Header.Get("Authorization") == "Bearer probe" {
			probeCalls.Add(1)
		} else {
			t.Error("unexpected fixture credential")
		}
		switch {
		case strings.Contains(r.URL.Path, "/validatingadmissionpolicies/"):
			reply(p)
		case strings.Contains(r.URL.Path, "/validatingadmissionpolicybindings/"):
			reply(b)
		case strings.HasSuffix(r.URL.Path, "/selfsubjectreviews"):
			reply(authn.SelfSubjectReview{TypeMeta: meta.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "SelfSubjectReview"}, Status: authn.SelfSubjectReviewStatus{UserInfo: authn.UserInfo{Username: "outsider", Groups: []string{"authenticated"}}}})
		case strings.HasSuffix(r.URL.Path, "/selfsubjectaccessreviews"):
			reply(authz.SelfSubjectAccessReview{TypeMeta: meta.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SelfSubjectAccessReview"}, Status: authz.SubjectAccessReviewStatus{Allowed: true}})
		case strings.HasSuffix(r.URL.Path, "/configmaps/context-capability"):
			if r.Method == "PUT" {
				if r.URL.Query().Get("dryRun") != "All" {
					t.Error("persistent fixture probe")
				}
				w.WriteHeader(422)
				reply(meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: meta.StatusFailure, Reason: meta.StatusReasonInvalid, Code: 422, Details: &meta.StatusDetails{Kind: "configmaps", Causes: []meta.StatusCause{{Message: "ValidatingAdmissionPolicy 'capability-guard' with binding 'capability-guard' denied request: Asservat context capability administrator is required."}}}})
				return
			}
			immutable := true
			reply(core.ConfigMap{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}, ObjectMeta: meta.ObjectMeta{Name: plan.SourceName, Namespace: control.Name, UID: types.UID(id(49)), ResourceVersion: "1"}, Immutable: &immutable, Data: map[string]string{"context-capability.json": string(raw)}})
		case r.URL.Path == "/api/v1/namespaces/"+control.Name:
			reply(core.Namespace{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: control.Name, UID: types.UID(control.UID), ResourceVersion: "1"}, Status: core.NamespaceStatus{Phase: core.NamespaceActive}})
		default:
			t.Errorf("unexpected API request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	config := &rest.Config{Host: server.URL, BearerToken: "observer", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
	observer, err := kube.NewPermissionClient(kube.WithOpeningBurst(config), id(52), control, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	config = rest.CopyConfig(config)
	config.BearerToken = "probe"
	probe, err := kube.NewPermissionClient(kube.WithOpeningBurst(config), id(52), control, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := kube.NewContextCapabilityProtection(observer, probe, plan, kube.GuardPin{PolicyUID: "policy", PolicyGeneration: 1, BindingUID: "binding", BindingResourceVersion: "1"})
	if err != nil {
		t.Fatal(err)
	}
	source, err := kube.NewContextCapabilitySource(observer, guard, f, plan.SourceName, id(49), settings)
	if err != nil {
		t.Fatal(err)
	}
	return source, observerCalls, probeCalls
}

func TestRegionalStartReusesPreludeBeforeFirstPreparation(t *testing.T) {
	f, _, settings := newRegionalObservationFixture(t)
	capability, observer, probe := regionalObservationCapability(t, f, settings)
	ctx, cancel := context.WithDeadline(t.Context(), f.now.Add(5*time.Second))
	defer cancel()
	current, _, err := identities.NewBearerRequest(ctx, f, "synthetic-token", time.Now)
	if err != nil {
		t.Fatal(err)
	}
	router, err := contextstart.NewRouter(contextstart.RouterLimits{Standby: 1, Captures: 1, Clusters: []contextstart.ClusterLimit{{ClusterID: f.work.Target.ClusterID, Standby: 1, Captures: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	// The standby's passive residency outlives the start's own deadline.
	resident, endResident := context.WithCancel(t.Context())
	defer endResident()
	standby, err := router.RegisterStandby(resident, f.receiver, func(ctx context.Context) (fleet.APIContextReceiver, error) { return f.receiver, ctx.Err() })
	if err != nil {
		t.Fatal(err)
	}
	stream := &regionalObservationStream{f: f, ctx: ctx}
	done := make(chan error, 1)
	go func() { defer standby.Finish(); done <- standby.Serve(stream, time.Now) }()
	start := RegionalAPIContextStart{Runner: executionapp.APIContextRunner{Read: f, Prepare: f, Record: f, Eligibility: access.Evaluator{Permissions: f, Now: time.Now}, Capabilities: capability, Retention: regionalObservationRetention{f}, Recovery: f, Now: time.Now}, Signer: f, Router: router, Now: time.Now, Report: func(s string) { t.Log(s) }}
	began := time.Now()
	err = start.StartContext(ctx, current, f.work.Accepted.CaptureID)
	elapsed := time.Since(began)
	cancel()
	endResident()
	<-done
	t.Logf("setup progress work=%d observer=%d probe=%d signed=%t", f.workReads, observer.Load(), probe.Load(), f.signed.CaptureID != "")
	if err == nil || f.preparations != 1 {
		t.Fatal("composed path did not reach the intended first SQL boundary", err, f.preparations)
	}
	t.Logf("actual StartContext -> runner first preparation: work reads=%d, TLS observer=%d probe=%d, elapsed=%s, opening QPS=%v burst=%d", f.workReads, observer.Load(), probe.Load(), elapsed, kube.OpeningQPS, kube.OpeningBurst)
	if f.workReads != 1 || observer.Load() != 18 || probe.Load() != 6 {
		t.Fatal("preparation repeated its already observed prelude", f.workReads, observer.Load(), probe.Load())
	}
	if f.check.Work.Actor != f.identity.Principal || f.check.Work.Accepted.CaptureID != f.work.Accepted.CaptureID || f.check.ValidUntil.After(f.identity.ValidUntil) || f.check.ValidUntil.After(f.receiver.ValidUntil) {
		t.Fatal("handoff changed identity, capture or original deadline")
	}
}
