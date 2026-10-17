package integration

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	admission "k8s.io/api/admissionregistration/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// The final closure below is a fixture-admin guard transition, not the product
// one-use handover. The Pod remains gated and never acquires provider secrets.
// It qualifies continuous key occupancy across staging removal separately from
// the still-pending product launch/retirement and historical-cleanliness proof.
func qualifyInitialGatedPreparation(t *testing.T, ctx context.Context, kc *rest.Config, api kubernetes.Interface, observer, probe *kube.PermissionClient, c contracts.InitialPreparer, install func(*admission.ValidatingAdmissionPolicy, *admission.ValidatingAdmissionPolicyBinding) contracts.OwnerDeploymentGuard, uncertain bool) func() {
	t.Helper()
	delayed := &delayedPreparationCreate{path: "/api/v1/namespaces/" + c.Plan.Workload.Namespace + "/pods", name: c.Plan.Workload.Name}
	effect := rest.CopyConfig(kc)
	if uncertain {
		effect.Wrap(func(next http.RoundTripper) http.RoundTripper { delayed.next = next; return delayed })
	}
	fresh := func() *kube.InitialPreparer {
		p, e := kube.NewInitialPreparer(effect, observer, probe, c)
		if e != nil {
			t.Fatal(e)
		}
		return p
	}
	if uncertain {
		if _, e := fresh().PrepareGatedPod(ctx); e == nil {
			t.Fatal("delayed original Pod CREATE reported success")
		}
	}
	owner := fresh()
	defer owner.Close()
	state, e := owner.PrepareGatedPod(ctx)
	if e != nil || state.Activation == nil || state.Activation.Pod.Receipt == nil {
		t.Fatal("native gated Pod resume", e)
	}
	pod, e := api.CoreV1().Pods(c.Plan.Workload.Namespace).Get(ctx, c.Plan.Workload.Name, meta.GetOptions{})
	if e != nil || string(pod.UID) != state.Activation.Pod.Receipt.UID || pod.Spec.NodeName != "" || len(pod.Spec.SchedulingGates) != 1 || pod.Status.StartTime != nil {
		t.Fatal("gated native UID/spec", e)
	}
	t.Run("continuation-pod-delete-denied", func(t *testing.T) {
		e := api.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name, meta.DeleteOptions{DryRun: []string{meta.DryRunAll}, Preconditions: &meta.Preconditions{UID: &pod.UID}})
		if e == nil || !strings.Contains(e.Error(), c.Plan.ContinuityName) {
			t.Fatal("continuity did not keep Pod name occupied", e)
		}
	})
	replay, e := fresh().PrepareGatedPod(ctx)
	if e != nil || replay.Activation.Pod.Receipt.UID != string(pod.UID) || replay.Activation.Pod.SpecDigest != state.Activation.Pod.SpecDigest {
		t.Fatal("original native Pod receipt changed", e)
	}
	if !uncertain {
		t.Run("healthy-native-request-drain", func(t *testing.T) {
			if len(state.Activation.Pod.Requests) != 1 || state.Activation.Pod.Requests[0].Completion == nil || state.Activation.Pod.Requests[0].Completion.Outcome != "created" {
				t.Fatal("actual native CREATE did not produce its own positive completion")
			}
			if e = owner.DrainPodCreateRequests(ctx); e != nil {
				t.Fatal("healthy native CREATE did not drain", e)
			}
		})
		return func() {}
	}
	if e = owner.DrainPodCreateRequests(ctx); !errors.Is(e, kube.ErrInitialPreparationRequestsUnresolved) {
		t.Fatal("native later CREATE erased original uncertainty", e)
	}
	return func() {
		t.Run("late-pod-create-after-fixture-guard-transition", func(t *testing.T) {
			reference := func(kind, name string) string {
				for _, r := range state.Creates {
					if r.Kind == kind && r.Name == name {
						return r.Receipt.UID
					}
				}
				t.Fatal("fixture receipt missing")
				return ""
			}
			p := cfg.InitialWorkloadAdministration{Name: c.Plan.Workload.WorkloadGuard, Configuration: c.Plan.Workload.Configuration, Witness: c.Plan.Workload.Witness, FleetSource: c.Plan.Workload.FleetSource, ControlNamespace: cfg.NamespaceRef{Name: pod.Namespace, UID: reference("Namespace", pod.Namespace)}, PodName: pod.Name, PodUID: string(pod.UID), PodSpecDigest: kube.InstallationPodSpecDigest(pod.Spec), WriterAccount: c.Plan.Workload.WriterAccount, WriterAccountUID: reference("ServiceAccount", c.Plan.Workload.WriterAccount), ProbeAccount: c.Plan.Workload.ProbeAccount, ProbeAccountUID: reference("ServiceAccount", c.Plan.Workload.ProbeAccount)}
			for _, a := range c.Plan.Administrators {
				p.Administrators = append(p.Administrators, cfg.KubernetesActor{Kind: a.Kind, Name: a.Name})
			}
			policy, binding, e := kube.InitialWorkloadAdmission(p)
			if e != nil {
				t.Fatal(e)
			}
			install(policy, binding)
			current, e := api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Get(ctx, c.Staging.Name, meta.GetOptions{})
			if e != nil || string(current.UID) != c.Staging.BindingUID {
				t.Fatal("original staging binding changed", e)
			}
			if e = api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Delete(ctx, current.Name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &current.UID}}); e != nil {
				t.Fatal(e)
			}
			status, e := delayed.release(ctx)
			if e != nil || status != 409 {
				t.Fatal("late Pod create replaced occupied key", status, e)
			}
			currentPod, e := api.CoreV1().Pods(pod.Namespace).Get(ctx, pod.Name, meta.GetOptions{})
			if e != nil || currentPod.UID != pod.UID || len(currentPod.Spec.SchedulingGates) != 1 || currentPod.Spec.NodeName != "" || currentPod.Status.StartTime != nil {
				t.Fatal("late create launched or replaced original", e)
			}
			if _, e = fresh().PrepareGatedPod(ctx); e == nil {
				t.Fatal("old staging authority survived transition")
			}
		})
	}
}
