package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	admission "k8s.io/api/admissionregistration/v1"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
)

// This is an admission-policy fixture. It deliberately supplies terminal API
// status on a Pod assigned to a nonexistent node, with no process or credentials.
// It never substitutes that status for the separate actual activation test.
func nativeInitialHandoverAdmission(t *testing.T, f fixture, historyManager contracts.InitialSQLHistoryManager) {
	t.Helper()
	ctx, stop := context.WithTimeout(context.Background(), time.Minute)
	defer stop()
	kc, err := clientcmd.BuildConfigFromFlags("", f.Clusters[0].Config)
	if err != nil {
		t.Fatal(err)
	}
	api, err := kubernetes.NewForConfig(kc)
	if err != nil {
		t.Fatal(err)
	}
	who, err := api.AuthenticationV1().SelfSubjectReviews().Create(ctx, &auth.SelfSubjectReview{}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var namespaces []*core.Namespace
	var policies []*admission.ValidatingAdmissionPolicy
	var bindings []*admission.ValidatingAdmissionPolicyBinding
	var pod *core.Pod
	t.Cleanup(func() {
		clean, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		for _, b := range bindings {
			if e := api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Delete(clean, b.Name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &b.UID}}); e != nil && !apierrors.IsNotFound(e) {
				t.Error(e)
			}
		}
		for _, p := range policies {
			if e := api.AdmissionregistrationV1().ValidatingAdmissionPolicies().Delete(clean, p.Name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &p.UID}}); e != nil && !apierrors.IsNotFound(e) {
				t.Error(e)
			}
		}
		// No process can run on this fixture's nonexistent node. If an assertion
		// fails before its marked terminal deletion, remove only this exact UID.
		if pod != nil {
			for {
				e := api.CoreV1().Pods(pod.Namespace).Delete(clean, pod.Name, meta.DeleteOptions{GracePeriodSeconds: ptr.To[int64](0), Preconditions: &meta.Preconditions{UID: &pod.UID}})
				if e == nil || apierrors.IsNotFound(e) {
					break
				}
				if clean.Err() != nil || !strings.Contains(e.Error(), "ValidatingAdmissionPolicy 'initial-admission-") {
					t.Error(e)
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
		}
		for _, ns := range namespaces {
			for {
				e := api.CoreV1().Namespaces().Delete(clean, ns.Name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &ns.UID}})
				if e == nil || apierrors.IsNotFound(e) {
					break
				}
				if clean.Err() != nil || !initialPreparerCleanupDenial(e, "initial-admission-continuity") {
					t.Error(e)
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			for {
				_, e := api.CoreV1().Namespaces().Get(clean, ns.Name, meta.GetOptions{})
				if apierrors.IsNotFound(e) {
					break
				}
				if e != nil || clean.Err() != nil {
					t.Error("owned admission namespace cleanup", e)
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
		}
	})
	for _, name := range []string{"initial-admission-bootstrap", "initial-admission-target"} {
		ns, e := api.CoreV1().Namespaces().Create(ctx, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: name, Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}}}, meta.CreateOptions{})
		if e != nil {
			t.Fatal(e)
		}
		namespaces = append(namespaces, ns)
	}
	bootstrap, target := namespaces[0], namespaces[1]
	plan := contracts.InitialPreparationPlan{InstallationID: custodyID(), RequestID: custodyID(), ClusterID: custodyID(), BootstrapNamespace: contracts.WorkerObjectReference{Name: bootstrap.Name, UID: string(bootstrap.UID)}, RootName: "root", ProbeName: "continuity-probe", ContinuityName: "initial-admission-continuity", Continuation: contracts.InitialPreparationActivationProtocol, Handover: contracts.InitialPreparationHandoverProtocol, HistoryManager: &historyManager, ProbeAudience: "https://kubernetes.default.svc.cluster.local", PrivateState: &contracts.WorkerObjectReference{Name: "private", UID: custodyID()}, HistoryProbe: &contracts.WorkerObjectReference{Name: "history", UID: custodyID()}, Administrators: []contracts.OwnerDeploymentActor{{Kind: "User", Name: who.Status.UserInfo.Username}}, Workload: contracts.InitialPreparationWorkload{Namespace: target.Name, Name: "installer", WriterAccount: "writer", ProbeAccount: "probe", Configuration: "inputs", Credentials: "providers", Image: f.WorkerImage, Witness: "witness", FleetSource: "fleet", WitnessGuard: "initial-admission-witness", FleetGuard: "initial-admission-fleet", WorkloadGuard: "initial-admission-workload", StagingGuard: "initial-admission-staging", Journal: "journal"}}
	w, err := kube.BuildInitialInstallerWorkload(kube.InitialInstallerWorkloadPlan{Namespace: target.Name, Name: plan.Workload.Name, WriterAccount: "writer", ProbeAccount: "probe", Configuration: "inputs", Credentials: "providers", Image: f.WorkerImage, Witness: "witness", FleetSource: "fleet", WitnessGuard: plan.Workload.WitnessGuard, FleetGuard: plan.Workload.FleetGuard, WorkloadGuard: plan.Workload.WorkloadGuard})
	if err != nil {
		t.Fatal(err)
	}
	accounts := map[string]*core.ServiceAccount{}
	for _, sa := range w.Accounts {
		accounts[sa.Name], err = api.CoreV1().ServiceAccounts(target.Name).Create(ctx, sa, meta.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
	}
	w.Pod.Spec.NodeName = "nonexistent-initial-admission-node"
	w.Pod.Spec.SchedulingGates = nil
	w.Pod.Labels = map[string]string{"fixture": "admission-only"}
	w.Pod.Annotations = map[string]string{"asservat.io/installation-id": plan.InstallationID, "asservat.io/preparation-request": plan.RequestID}
	original := w.Pod.DeepCopy()
	createdPod, err := api.CoreV1().Pods(target.Name).Create(ctx, w.Pod, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pod = createdPod
	// Only synthetic no-process objects are used for wire qualification. The
	// actual installer Pod below is never status-mutated or replaced by a test.
	checkConflict := func(t *testing.T, result rest.Result, group, resource, name string) {
		t.Helper()
		var code int
		raw, e := result.StatusCode(&code).Raw()
		var status meta.Status
		if code != http.StatusConflict || !apierrors.IsConflict(e) || json.Unmarshal(raw, &status) != nil || status.APIVersion != "v1" || status.Kind != "Status" || status.Status != meta.StatusFailure || status.Reason != meta.StatusReasonConflict || status.Code != http.StatusConflict || status.Details == nil || status.Details.Group != group || status.Details.Kind != resource || status.Details.Name != name {
			t.Fatalf("native conditional-update conflict shape differs: HTTP=%d body=%s", code, raw)
		}
		t.Logf("actual HTTP=%d API Status=%s", code, raw)
	}
	t.Run("pod-status-only-conflict-wire", func(t *testing.T) {
		stale := pod.DeepCopy()
		stale.TypeMeta = meta.TypeMeta{APIVersion: "v1", Kind: "Pod"}
		pod.Status.Reason = "SyntheticRevision"
		updated, e := api.CoreV1().Pods(target.Name).UpdateStatus(ctx, pod, meta.UpdateOptions{})
		if e != nil || updated.UID != stale.UID || updated.ResourceVersion == stale.ResourceVersion {
			t.Fatal("synthetic status-only revision unavailable")
		}
		pod = updated
		raw, e := json.Marshal(stale)
		if e != nil {
			t.Fatal(e)
		}
		checkConflict(t, api.CoreV1().RESTClient().Put().Namespace(target.Name).Resource("pods").Name(stale.Name).MaxRetries(0).Body(raw).Do(ctx), "", "pods", stale.Name)
	})
	t.Run("policy-status-only-conflict-wire", func(t *testing.T) {
		p, e := api.AdmissionregistrationV1().ValidatingAdmissionPolicies().Create(ctx, &admission.ValidatingAdmissionPolicy{
			ObjectMeta: meta.ObjectMeta{Name: "initial-admission-conflict-wire"},
			Spec: admission.ValidatingAdmissionPolicySpec{
				FailurePolicy:    ptr.To(admission.Fail),
				MatchConstraints: &admission.MatchResources{ResourceRules: []admission.NamedRuleWithOperations{{RuleWithOperations: admission.RuleWithOperations{Operations: []admission.OperationType{admission.Create}, Rule: admission.Rule{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"namespaces"}}}}}},
				Validations:      []admission.Validation{{Expression: "true"}},
			},
		}, meta.CreateOptions{})
		if e != nil {
			t.Fatal("unbound synthetic conflict policy unavailable", e)
		}
		policies = append(policies, p)
		// Wait for the native controller's initial status before the synthetic
		// status-only revision. No binding is created and this policy grants nothing.
		for p.Status.ObservedGeneration != p.Generation || p.Status.TypeChecking == nil {
			select {
			case <-ctx.Done():
				t.Fatal("synthetic conflict policy status unavailable")
			case <-time.After(50 * time.Millisecond):
			}
			p, e = api.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, p.Name, meta.GetOptions{})
			if e != nil {
				t.Fatal(e)
			}
		}
		stale := p.DeepCopy()
		stale.TypeMeta = meta.TypeMeta{APIVersion: "admissionregistration.k8s.io/v1", Kind: "ValidatingAdmissionPolicy"}
		p.Status.Conditions = append(p.Status.Conditions, meta.Condition{Type: "SyntheticRevision", Status: meta.ConditionTrue, LastTransitionTime: meta.Now(), Reason: "FixtureOnly", Message: "Unbound native API conflict fixture"})
		p, e = api.AdmissionregistrationV1().ValidatingAdmissionPolicies().UpdateStatus(ctx, p, meta.UpdateOptions{})
		if e != nil || p.UID != stale.UID || p.ResourceVersion == stale.ResourceVersion || p.Generation != stale.Generation {
			t.Fatal("policy status-only revision unavailable", e)
		}
		raw, e := json.Marshal(stale)
		if e != nil {
			t.Fatal(e)
		}
		checkConflict(t, api.AdmissionregistrationV1().RESTClient().Put().Resource("validatingadmissionpolicies").Name(stale.Name).MaxRetries(0).Body(raw).Do(ctx), "admissionregistration.k8s.io", "validatingadmissionpolicies", stale.Name)
	})
	wrongNode := "system:node:nonexistent-other-admission-node"
	role, err := api.RbacV1().Roles(target.Name).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: "wrong-node-probe"}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, ResourceNames: []string{pod.Name}, Verbs: []string{"delete"}}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = api.RbacV1().RoleBindings(target.Name).Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: role.Name}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: role.Name}, Subjects: []rbac.Subject{{Kind: "User", Name: wrongNode}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	install := func(p *admission.ValidatingAdmissionPolicy, b *admission.ValidatingAdmissionPolicyBinding, e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
		p, e = api.AdmissionregistrationV1().ValidatingAdmissionPolicies().Create(ctx, p, meta.CreateOptions{})
		if e != nil {
			t.Fatal(e)
		}
		policies = append(policies, p)
		b, e = api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Create(ctx, b, meta.CreateOptions{})
		if e != nil {
			t.Fatal(e)
		}
		bindings = append(bindings, b)
		for {
			got, e := api.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, p.Name, meta.GetOptions{})
			if e != nil {
				t.Fatal(e)
			}
			if got.Status.ObservedGeneration == got.Generation && got.Status.TypeChecking != nil {
				if len(got.Status.TypeChecking.ExpressionWarnings) != 0 {
					t.Fatalf("native admission type warnings: %v", got.Status.TypeChecking.ExpressionWarnings)
				}
				break
			}
			select {
			case <-ctx.Done():
				t.Fatal("native policy qualification timeout")
			case <-time.After(50 * time.Millisecond):
			}
		}
	}
	install(kube.InitialPreparationContinuityAdmission(plan))
	wp := cfg.InitialWorkloadAdministration{Handover: true, Name: plan.Workload.WorkloadGuard, Configuration: "inputs", Witness: "witness", FleetSource: "fleet", ControlNamespace: cfg.NamespaceRef{Name: target.Name, UID: string(target.UID)}, PodName: pod.Name, PodUID: string(pod.UID), WriterAccount: "writer", WriterAccountUID: string(accounts["writer"].UID), ProbeAccount: "probe", ProbeAccountUID: string(accounts["probe"].UID), PodSpecDigest: kube.InstallationPodSpecDigest(pod.Spec), Administrators: []cfg.KubernetesActor{{Kind: "User", Name: who.Status.UserInfo.Username}}}
	install(kube.InitialWorkloadAdmission(wp))
	const marker = "asservat.io/initial-preparation-retired"
	mark := func(p *core.Pod) *core.Pod { v := p.DeepCopy(); v.Annotations[marker] = string(p.UID); return v }
	deny := func(t *testing.T, e error) {
		t.Helper()
		if e == nil || !strings.Contains(e.Error(), "ValidatingAdmissionPolicy 'initial-admission-") {
			t.Fatalf("request escaped native handover policy: %v", e)
		}
	}
	// Wait only on the explicit expected dry-run denial to observe admission
	// cache propagation. It causes no mutation and grants no runtime authority.
	for {
		_, e := api.CoreV1().Pods(target.Name).Update(ctx, mark(pod), meta.UpdateOptions{DryRun: []string{meta.DryRunAll}})
		if e != nil && strings.Contains(e.Error(), "ValidatingAdmissionPolicy '"+wp.Name+"'") {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		select {
		case <-ctx.Done():
			t.Fatal("native final policy not enforcing")
		case <-time.After(50 * time.Millisecond):
		}
	}
	t.Run("premature-retirement-marker", func(t *testing.T) {
		_, e := api.CoreV1().Pods(target.Name).Update(ctx, mark(pod), meta.UpdateOptions{DryRun: []string{meta.DryRunAll}})
		deny(t, e)
	})
	// Synthetic status is used only for policy attack tests, never SQL activation.
	pod.Status.Phase = core.PodSucceeded
	terminalPod, err := api.CoreV1().Pods(target.Name).UpdateStatus(ctx, pod, meta.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pod = terminalPod
	t.Run("terminal-delete-without-marker", func(t *testing.T) {
		deny(t, api.CoreV1().Pods(target.Name).Delete(ctx, pod.Name, meta.DeleteOptions{DryRun: []string{meta.DryRunAll}}))
	})
	t.Run("marker-cannot-change-spec", func(t *testing.T) {
		v := mark(pod)
		v.Spec.Containers[0].Image = "example.invalid/different@sha256:" + strings.Repeat("b", 64)
		_, e := api.CoreV1().Pods(target.Name).Update(ctx, v, meta.UpdateOptions{DryRun: []string{meta.DryRunAll}})
		deny(t, e)
	})
	t.Run("wrong-original-uid-marker", func(t *testing.T) {
		v := mark(pod)
		v.Annotations[marker] = custodyID()
		_, e := api.CoreV1().Pods(target.Name).Update(ctx, v, meta.UpdateOptions{DryRun: []string{meta.DryRunAll}})
		deny(t, e)
	})
	markedPod, err := api.CoreV1().Pods(target.Name).Update(ctx, mark(pod), meta.UpdateOptions{})
	if err != nil {
		t.Fatal("exact terminal marker denied", err)
	}
	pod = markedPod
	t.Run("marker-cannot-be-removed", func(t *testing.T) {
		v := pod.DeepCopy()
		delete(v.Annotations, marker)
		_, e := api.CoreV1().Pods(target.Name).Update(ctx, v, meta.UpdateOptions{DryRun: []string{meta.DryRunAll}})
		deny(t, e)
	})
	t.Run("wrong-kubelet-node", func(t *testing.T) {
		c := rest.CopyConfig(kc)
		c.Impersonate = rest.ImpersonationConfig{UserName: wrongNode, Groups: []string{"system:nodes", "system:authenticated"}}
		client, e := kubernetes.NewForConfig(c)
		if e != nil {
			t.Fatal(e)
		}
		e = client.CoreV1().Pods(target.Name).Delete(ctx, pod.Name, meta.DeleteOptions{DryRun: []string{meta.DryRunAll}})
		// The pinned native API runs NodeRestriction before validating policies.
		// Qualify that precise rejection, without disabling the stronger guard or
		// claiming this request reached Asservat's own node predicate.
		status, ok := e.(apierrors.APIStatus)
		want := "pods \"" + pod.Name + "\" is forbidden: node \"" + strings.TrimPrefix(wrongNode, "system:node:") + "\" can only delete pods with spec.nodeName set to itself"
		if !ok || !apierrors.IsForbidden(e) || status.Status().Code != 403 || status.Status().Message != want {
			t.Fatalf("wrong-node request lacks the qualified NodeRestriction denial: %v", e)
		}
		t.Log("native NodeRestriction rejected the wrong node before Asservat policy evaluation")
	})
	t.Run("delayed-original-create-stays-occupied", func(t *testing.T) {
		_, e := api.CoreV1().Pods(target.Name).Create(ctx, original, meta.CreateOptions{})
		if !apierrors.IsAlreadyExists(e) {
			t.Fatalf("original key not occupied: %v", e)
		}
		v, e := api.CoreV1().Pods(target.Name).Get(ctx, pod.Name, meta.GetOptions{})
		if e != nil || v.UID != pod.UID || v.Annotations[marker] != string(pod.UID) {
			t.Fatal("late CREATE replaced original", e)
		}
	})
	if err = api.CoreV1().Pods(target.Name).Delete(ctx, pod.Name, meta.DeleteOptions{GracePeriodSeconds: ptr.To[int64](0), Preconditions: &meta.Preconditions{UID: &pod.UID, ResourceVersion: &pod.ResourceVersion}}); err != nil {
		t.Fatal("qualified terminal deletion denied", err)
	}
	if _, err = api.CoreV1().Pods(target.Name).Get(ctx, pod.Name, meta.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatal("terminal admission fixture Pod remains", err)
	}
}
