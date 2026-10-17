package kubernetes

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
)

func handoverTestPlan() contracts.InitialPreparationPlan {
	p := preparerTestPlan()
	p.Continuation = contracts.InitialPreparationActivationProtocol
	p.Handover = contracts.InitialPreparationHandoverProtocol
	p.PrivateState = &contracts.WorkerObjectReference{Name: "private-progress", UID: ownerID(901)}
	p.HistoryManager = &contracts.InitialSQLHistoryManager{Name: "synthetic_setup_manager", OID: 12345}
	p.HistoryProbe = &contracts.WorkerObjectReference{Name: "history-probe", UID: ownerID(902)}
	p.ProbeAudience = "https://kubernetes.default.svc.cluster.local"
	return p
}
func TestInitialPreparationHandoverClosedProfiles(t *testing.T) {
	legacy := preparerTestPlan()
	a, e := preparerObjects(legacy)
	if e != nil || len(a) != 9 {
		t.Fatal("legacy inventory", e)
	}
	p := handoverTestPlan()
	b, e := preparerObjects(p)
	if e != nil || len(b) != 11 {
		t.Fatal("handover inventory", e)
	}
	if initialPreparationFinalInputCount != 9 || initialPreparationConfigurationIndex != 8 {
		t.Fatal("final inputs conflated with declarative RBAC")
	}
	for i := range a {
		if i == 1 {
			continue
		}
		if a[i].object.GetObjectKind().GroupVersionKind().Kind != b[i].object.GetObjectKind().GroupVersionKind().Kind {
			t.Fatal("legacy inventory reordered")
		}
	}
	for _, o := range b[9:] {
		if preparerMetadata(o.object).Name != p.Workload.Name+"-history-probe" {
			t.Fatal("unbounded permanent history resource")
		}
	}
	oldPolicy, oldBinding, e := InitialNamespaceAdmission(preparerAdministration(p))
	if e != nil {
		t.Fatal(e)
	}
	retired, binding, e := InitialRetiredStagingAdmission(p)
	if e != nil || !equalJSON(oldBinding, binding) {
		t.Fatal("binding changed", e)
	}
	if len(retired.Spec.MatchConditions) != len(oldPolicy.Spec.MatchConditions)+1 || retired.Spec.MatchConditions[len(retired.Spec.MatchConditions)-1].Expression != "false" {
		t.Fatal("not canonical inert shape")
	}
	retired.Spec.MatchConditions = retired.Spec.MatchConditions[:len(retired.Spec.MatchConditions)-1]
	if !equalJSON(oldPolicy, retired) {
		t.Fatal("retirement changed unrelated protection")
	}
	if _, _, e = InitialRetiredStagingAdmission(legacy); e == nil {
		t.Fatal("legacy silently gained handover")
	}
	bad := p
	bad.Handover = "other"
	if validPreparerPlan(bad) {
		t.Fatal("unknown capability")
	}
}
func TestInitialPreparationSecretCompletionRequiresOwnPositiveCreate(t *testing.T) {
	f := newPreparerFixture(t, "")
	base := f.preparer(t)
	defer base.Close()
	// This isolates the original response owner; no root/activation authority is
	// supplied by this synthetic transport boundary test.
	base.plan.Handover = contracts.InitialPreparationHandoverProtocol
	want := &core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: "synthetic-private", Namespace: f.plan.Workload.Namespace}, Type: core.SecretTypeOpaque, Immutable: ptr.To(true), Data: map[string][]byte{"state.json": []byte("synthetic-only")}}
	base.creator.stamp(&want.ObjectMeta)
	want.Annotations[initialPreparationOperationAnnotation] = ownerID(950)
	ctx := context.Background()
	path := "/api/v1/namespaces/" + f.plan.Workload.Namespace + "/secrets"
	raw, e := base.postPreparationSecret(ctx, path, want)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(raw)
	var got core.Secret
	if json.Unmarshal(raw, &got) != nil {
		t.Fatal("response")
	}
	ref := contracts.WorkerObjectReference{Name: got.Name, UID: string(got.UID)}
	if base.secretCreateClosed(ownerID(950), ref) {
		t.Fatal("GET/body alone supplied proof")
	}
	base.keepSecretCreateResponse(ownerID(950), raw, want, time.Now().Add(time.Second))
	if !base.secretCreateClosed(ownerID(950), ref) {
		t.Fatal("acknowledged original not retained")
	}
	if base.secretCreateClosed(ownerID(951), ref) || base.secretCreateClosed(ownerID(950), contracts.WorkerObjectReference{Name: ref.Name, UID: ownerID(999)}) {
		t.Fatal("proof crossed invocation/UID")
	}
	base.keepSecretCreateResponse(ownerID(951), raw, want, time.Now().Add(-time.Second))
	if base.secretCreateClosed(ownerID(951), ref) {
		t.Fatal("late response qualified")
	}
	base.Close()
	base.keepSecretCreateResponse(ownerID(952), raw, want, time.Now().Add(time.Second))
	if base.secretCreateClosed(ownerID(952), ref) {
		t.Fatal("closed owner admitted new proof")
	}
	if !base.secretCreateClosed(ownerID(950), ref) {
		t.Fatal("join discarded original proof")
	}
}
func TestInitialPreparationSecretUnexpectedSuccessDoesNotClose(t *testing.T) {
	for _, status := range []int{200, 202, 409, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			f := newPreparerFixture(t, "")
			p := f.preparer(t)
			defer p.Close()
			p.plan.Handover = contracts.InitialPreparationHandoverProtocol
			f.mu.Lock()
			f.extra = func(w http.ResponseWriter, r *http.Request) bool {
				if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/secrets") {
					w.WriteHeader(status)
					permissionReply(w, core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: "test", UID: types.UID(ownerID(955))}})
					return true
				}
				return false
			}
			f.mu.Unlock()
			if raw, e := p.postPreparationSecret(context.Background(), "/api/v1/namespaces/initial-target/secrets", &core.Secret{}); e == nil {
				clear(raw)
				t.Fatal("unexpected HTTP outcome conferred original completion")
			}
		})
	}
}
func TestInitialPreparationTerminalRetirementRequiresOriginalPod(t *testing.T) {
	f, p := activationPreparerFixture(t)
	defer p.Close()
	w, e := p.PrepareGatedPod(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	raw, e := p.creator.raw(context.Background(), p.handoverPodPath(), nil)
	if e != nil {
		t.Fatal(e)
	}
	var pod core.Pod
	if json.Unmarshal(raw, &pod) != nil {
		t.Fatal("synthetic pod")
	}
	pod.Spec.SchedulingGates = nil
	pod.Spec.NodeName = "original-node"
	now := time.Now().UTC().Truncate(time.Microsecond)
	w.Activation.Handover = &contracts.InitialPreparationHandover{Launch: &contracts.InitialPreparationLaunch{StartedAt: now, Observed: true}, Cleanup: &contracts.InitialPreparationCleanup{Steps: make([]contracts.InitialPreparationCleanupReceipt, 7)}}
	pod.Status = core.PodStatus{Phase: core.PodSucceeded, ContainerStatuses: []core.ContainerStatus{{Name: pod.Spec.Containers[0].Name, State: core.ContainerState{Terminated: &core.ContainerStateTerminated{ExitCode: 0, StartedAt: meta.NewTime(now.Truncate(time.Second)), FinishedAt: meta.NewTime(now.Truncate(time.Second))}}}}}
	pod.Annotations[initialPreparationRetiredAnnotation] = string(pod.UID)
	for _, mode := range []string{"valid", "early", "replacement", "spec", "wrong-marker", "restarted", "failed"} {
		t.Run(mode, func(t *testing.T) {
			current := pod.DeepCopy()
			root := w
			h := *w.Activation.Handover
			c := *h.Cleanup
			h.Cleanup = &c
			a := *w.Activation
			a.Handover = &h
			root.Activation = &a
			switch mode {
			case "early":
				c.Steps = c.Steps[:6]
			case "replacement":
				current.UID = types.UID(ownerID(999))
			case "spec":
				current.Spec.Containers[0].Image = "bad:latest"
			case "wrong-marker":
				current.Annotations[initialPreparationRetiredAnnotation] = ownerID(999)
			case "restarted":
				current.Status.ContainerStatuses[0].RestartCount = 1
			case "failed":
				current.Status.Phase = core.PodFailed
			}
			body, _ := json.Marshal(current)
			accepted, e := p.handoverPod(body, root, false)
			okay := e == nil && p.successfulHandoverPod(accepted, root)
			if okay != (mode == "valid") {
				t.Fatalf("retirement provenance mode %s accepted=%v err=%v", mode, okay, e)
			}
		})
	}
	_ = f
}
func TestInitialPreparationHandoverGuardPinsActualPod(t *testing.T) {
	p := cfg.InitialWorkloadAdministration{Name: "guard", Configuration: "config", Witness: "witness", FleetSource: "fleet", ControlNamespace: cfg.NamespaceRef{Name: "initial", UID: ownerID(1)}, PodName: "installer", PodUID: ownerID(2), WriterAccount: "writer", WriterAccountUID: ownerID(3), ProbeAccount: "probe", ProbeAccountUID: ownerID(4), Administrators: []cfg.KubernetesActor{{Kind: "User", Name: "operator"}}}
	p.PodSpecDigest[0] = 1
	old, _, e := InitialWorkloadAdmission(p)
	if e != nil {
		t.Fatal(e)
	}
	p.Handover = true
	next, _, e := InitialWorkloadAdmission(p)
	if e != nil || len(next.Spec.Validations) != len(old.Spec.Validations)+2 || !equalJSON(old.Spec.Validations, next.Spec.Validations[:len(old.Spec.Validations)]) {
		t.Fatal("legacy guard changed", e)
	}
	for _, r := range next.Spec.Validations[1:] {
		if !strings.Contains(r.Expression, p.PodUID) || !strings.Contains(r.Expression, "Succeeded") {
			t.Fatal("marker alone qualifies deletion")
		}
	}
}

func TestInitialPreparationCleanupAcknowledgementsAreFiniteAndOrdered(t *testing.T) {
	p := &InitialPreparer{plan: handoverTestPlan()}
	now := time.Now().UTC().Truncate(time.Microsecond)
	h := &contracts.InitialPreparationHandover{OperationID: ownerID(1), Staging: &contracts.InitialPreparationStagingRetirement{ID: ownerID(2), Receipt: &contracts.InitialPreparationPolicyReceipt{UID: ownerID(3)}}, Launch: &contracts.InitialPreparationLaunch{ID: ownerID(4), StartedAt: now.Add(-time.Second), Observed: true}}
	c := &contracts.InitialPreparationCleanup{OperationID: ownerID(5), ActivatedClaimID: ownerID(6), StartedAt: now, PodResourceVersion: "4", SQLState: contracts.WorkerObjectReference{Name: p.plan.Workload.Credentials + "-sql", UID: ownerID(7)}, ProbeAnchor: contracts.WorkerObjectReference{Name: p.probeAnchorName(), UID: ownerID(8)}, Steps: []contracts.InitialPreparationCleanupReceipt{}}
	h.Cleanup = c
	w := contracts.InitialPreparationRoot{Activation: &contracts.InitialPreparationActivation{Handover: h}}
	for _, step := range initialPreparationCleanupSteps {
		if !p.validHandoverCleanup(w) || p.HandoverCleanupComplete(w) {
			t.Fatal("partial cleanup considered complete")
		}
		c.Steps = append(c.Steps, contracts.InitialPreparationCleanupReceipt{Step: step, CompletedAt: now})
	}
	if !p.HandoverCleanupComplete(w) {
		t.Fatal("finite complete cleanup rejected")
	}
	for _, mode := range []string{"duplicate", "reordered", "time-backward", "wrong-ref", "wrong-claim", "unobserved-launch"} {
		t.Run(mode, func(t *testing.T) {
			data, _ := json.Marshal(w)
			var v contracts.InitialPreparationRoot
			_ = json.Unmarshal(data, &v)
			x := v.Activation.Handover.Cleanup
			switch mode {
			case "duplicate":
				x.Steps = append(x.Steps, x.Steps[7])
			case "reordered":
				x.Steps[0], x.Steps[1] = x.Steps[1], x.Steps[0]
			case "time-backward":
				x.Steps[4].CompletedAt = now.Add(-time.Second)
			case "wrong-ref":
				x.ProbeAnchor.Name = "other"
			case "wrong-claim":
				x.ActivatedClaimID = "missing"
			case "unobserved-launch":
				v.Activation.Handover.Launch.Observed = false
			}
			if p.validHandoverCleanup(v) || p.HandoverCleanupComplete(v) {
				t.Fatal("invalid completion accepted")
			}
		})
	}
}

func TestInitialPreparationHistoryManagerBoundBeforeDeclaration(t *testing.T) {
	p := handoverTestPlan()
	before := preparationPlanDigest(p)
	for _, change := range []func(*contracts.InitialPreparationPlan){
		func(v *contracts.InitialPreparationPlan) { v.HistoryManager = nil },
		func(v *contracts.InitialPreparationPlan) {
			v.HistoryManager = &contracts.InitialSQLHistoryManager{Name: "manager"}
		},
		func(v *contracts.InitialPreparationPlan) {
			v.HistoryManager = &contracts.InitialSQLHistoryManager{Name: "manager", OID: 10}
		},
		func(v *contracts.InitialPreparationPlan) {
			v.HistoryManager = &contracts.InitialSQLHistoryManager{Name: strings.Repeat("m", 64), OID: 12345}
		},
	} {
		bad := p
		change(&bad)
		if _, e := BuildInitialPreparationRoot(bad); e == nil {
			t.Fatal("invalid history manager reached declaration")
		}
	}
	for _, pin := range []contracts.InitialSQLHistoryManager{{Name: p.HistoryManager.Name, OID: p.HistoryManager.OID + 1}, {Name: "replacement_manager", OID: p.HistoryManager.OID}} {
		changed := p
		changed.HistoryManager = &pin
		if !validPreparerPlan(changed) || preparationPlanDigest(changed) == before {
			t.Fatal("manager replacement did not change protected root binding")
		}
	}
	legacy := preparerTestPlan()
	raw, e := json.Marshal(legacy)
	if e != nil || strings.Contains(string(raw), "historyManager") {
		t.Fatal("legacy encoding gained manager pin")
	}
	legacy.HistoryManager = p.HistoryManager
	if validPreparerPlan(legacy) {
		t.Fatal("legacy plan gained management exception")
	}
}
