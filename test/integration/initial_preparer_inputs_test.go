package integration

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func TestInitialPreparationPublicInputsWithRealKubernetes(t *testing.T) {
	initialPreparationSupervisorNative(t, true, false, func(ctx context.Context, kc *rest.Config, api kubernetes.Interface, admin, probe *kube.PermissionClient, c contracts.InitialPreparer) {
		// Only Kubernetes public preparation is qualified here. These unused provider
		// endpoints are synthetic public input, not provider readiness or authority.
		native := rest.CopyConfig(kc)
		if e := rest.LoadTLSFiles(native); e != nil {
			t.Fatal(e)
		}
		block, _ := pem.Decode(native.CAData)
		if block == nil || block.Type != "CERTIFICATE" {
			t.Fatal("native fixture root unavailable")
		}
		roots := [][]byte{block.Bytes}
		var fleet contracts.FleetSettings
		raw, e := os.ReadFile("../../examples/fleet-settings.json")
		if e != nil || json.Unmarshal(raw, &fleet) != nil {
			t.Fatal("synthetic fleet unavailable", e)
		}
		fleet.InstallationID = c.Plan.InstallationID
		c.Services = &contracts.InitialPreparationServices{Format: contracts.InitialPreparationServicesFormat, Fleet: fleet, Kubernetes: contracts.OwnerProviderEndpoint{Endpoint: native.Host, Roots: roots}, Postgres: contracts.OwnerPostgresEndpoint{Host: "sql.example.test", Port: 5432, Database: "asservat", Roots: roots, MaxConnections: 2}, AuditStore: contracts.OwnerAuditStore{Endpoint: "https://audit.example.test", Roots: roots, Region: "test", Bucket: "audit"}, KeyService: contracts.ConfigurationKeyService{Endpoint: "https://keys.example.test", Roots: roots, AuditMount: "transit", AuditKey: "audit"}}
		// Register before any producer effect. Remove only this fixture's exact owned
		// policies. Trusted fixture teardown does not stand in for product handover.
		t.Cleanup(func() {
			cleanup, done := context.WithTimeout(context.Background(), 15*time.Second)
			defer done()
			for _, name := range []string{c.Plan.Workload.FleetGuard, c.Plan.Workload.WitnessGuard, c.Plan.Workload.WorkloadGuard} {
				b, e := api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Get(cleanup, name, meta.GetOptions{})
				if e == nil {
					if b.Annotations["asservat.io/installation-id"] != c.Plan.InstallationID || b.Annotations["asservat.io/preparation-request"] != c.Plan.RequestID {
						t.Error("refusing foreign public binding cleanup")
						continue
					}
					if e = api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Delete(cleanup, name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &b.UID}}); e != nil && !apierrors.IsNotFound(e) {
						t.Error(e)
					}
				} else if !apierrors.IsNotFound(e) {
					t.Error(e)
				}
				p, e := api.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(cleanup, name, meta.GetOptions{})
				if e == nil {
					if p.Annotations["asservat.io/installation-id"] != c.Plan.InstallationID || p.Annotations["asservat.io/preparation-request"] != c.Plan.RequestID {
						t.Error("refusing foreign public policy cleanup")
						continue
					}
					if e = api.AdmissionregistrationV1().ValidatingAdmissionPolicies().Delete(cleanup, name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &p.UID}}); e != nil && !apierrors.IsNotFound(e) {
						t.Error(e)
					}
				} else if !apierrors.IsNotFound(e) {
					t.Error(e)
				}
			}
		})
		p, e := kube.NewInitialPreparer(native, admin, probe, c)
		if e != nil {
			t.Fatal(e)
		}
		defer p.Close()
		deadline := time.Now().Add(30 * time.Second)
		var root contracts.InitialPreparationRoot
		for {
			root, e = p.PrepareFinalInputs(ctx)
			if e == nil {
				break
			}
			if !errors.Is(e, cfg.ErrUnavailable) || !time.Now().Before(deadline) {
				t.Fatal("native public preparation", e)
			}
			// Pending native policy compilation gets exact lookup; no pending object
			// receives another POST. Every iteration reacquires original guard checks.
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(50 * time.Millisecond):
			}
		}
		if root.Activation == nil || root.Activation.Inputs == nil || len(root.Activation.Inputs.Creates) != 9 {
			t.Fatal("public inventory incomplete")
		}
		cm, e := api.CoreV1().ConfigMaps(c.Plan.Workload.Namespace).Get(ctx, c.Plan.Workload.Configuration, meta.GetOptions{})
		if e != nil || cm.Immutable == nil || !*cm.Immutable {
			t.Fatal("startup not immutable", e)
		}
		startup, e := contracts.DecodeInitialInstaller(strings.NewReader(cm.Data["deployment.json"]))
		if e != nil || startup.Pod.UID != root.Activation.Pod.Receipt.UID || startup.PodSpecDigest != root.Activation.Pod.SpecDigest || startup.Witness.UID != root.Activation.Inputs.Creates[0].Receipt.UID || startup.FleetSource.UID != root.Activation.Inputs.Creates[1].Receipt.UID {
			t.Fatal("native startup identities", e)
		}
		for _, g := range []contracts.OwnerDeploymentGuard{startup.WorkloadGuard, startup.WitnessGuard, startup.FleetGuard} {
			policy, e := api.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, g.Name, meta.GetOptions{})
			if e != nil || string(policy.UID) != g.PolicyUID || policy.Generation != g.PolicyGeneration || policy.Status.ObservedGeneration != g.PolicyGeneration || policy.Status.TypeChecking == nil || len(policy.Status.TypeChecking.ExpressionWarnings) != 0 {
				t.Fatal("native policy pin not ready", e)
			}
			binding, e := api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Get(ctx, g.Name, meta.GetOptions{})
			if e != nil || string(binding.UID) != g.BindingUID || binding.ResourceVersion != g.BindingResourceVersion {
				t.Fatal("native binding pin changed", e)
			}
		}
		second, e := kube.NewInitialPreparer(native, admin, probe, c)
		if e != nil {
			t.Fatal(e)
		}
		defer second.Close()
		replay, e := second.PrepareFinalInputs(ctx)
		if e != nil || !reflect.DeepEqual(root, replay) {
			t.Fatal("native public-input replay changed provenance", e)
		}
		pod, e := api.CoreV1().Pods(c.Plan.Workload.Namespace).Get(ctx, c.Plan.Workload.Name, meta.GetOptions{})
		if e != nil || len(pod.Spec.SchedulingGates) != 1 || pod.Spec.NodeName != "" || pod.Status.StartTime != nil {
			t.Fatal("public preparation launched Pod", e)
		}
		if e = second.DrainPodCreateRequests(ctx); e != nil {
			t.Fatal("native public preparation lost healthy request completion", e)
		}
	})
}
