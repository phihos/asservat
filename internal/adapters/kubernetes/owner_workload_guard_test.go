package kubernetes

import (
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"k8s.io/client-go/rest"
)

// Helm-native installation (2026-11-13): Current performs no admission-policy,
// probe or dry-run request, and its digest is the same stable function of the
// plan, pin and cluster that persisted protection_digest values were built from.
func TestOwnerWorkloadProtectionCurrentIsStableWithoutAdmissionRequests(t *testing.T) {
	start := time.Now().UTC()
	plan := cfg.OwnerWorkloadAdministration{Name: "owner-workload", Deployment: "hub", DeploymentUID: ownerID(5), ControlNamespace: cfg.NamespaceRef{Name: "owners", UID: ownerID(4)}, Administrators: []cfg.KubernetesActor{{Kind: "User", Name: "installer"}}}
	pin := GuardPin{PolicyUID: ownerID(1), PolicyGeneration: 1, BindingUID: ownerID(2), BindingResourceVersion: "20"}
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.NotFound(w, r)
	}))
	defer server.Close()
	config := &rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
	now := func() time.Time { return start }
	reader, e := NewPermissionClient(config, permissionCluster, plan.ControlNamespace, now)
	if e != nil {
		t.Fatal(e)
	}
	probe, e := NewPermissionClient(config, permissionCluster, plan.ControlNamespace, now)
	if e != nil {
		t.Fatal(e)
	}
	guard, e := NewOwnerWorkloadProtection(reader, probe, plan, pin)
	if e != nil {
		t.Fatal(e)
	}
	if guard.digest != artifact.Digest(contracts.WorkloadSourceDigest(permissionCluster, plan.ControlNamespace.Name, plan.Deployment)) {
		t.Fatal("protection digest changed its derivation")
	}
	digest, until, e := guard.Current(context.Background())
	if e != nil || digest != guard.digest || !until.Equal(start.Add(OwnerProtectionReuse)) {
		t.Fatal("current protection without admission guard", e)
	}
	bounded, cancel := context.WithDeadline(context.Background(), start.Add(10*time.Second))
	defer cancel()
	if _, until, e = guard.Current(bounded); e != nil || !until.Equal(start.Add(10*time.Second)) {
		t.Fatal("protection validity exceeded the caller deadline", e)
	}
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if _, _, e = guard.Current(canceled); !errors.Is(e, cfg.ErrUnavailable) {
		t.Fatal("canceled caller accepted", e)
	}
	again, e := guard.WithClients(reader, probe)
	if e != nil || again.digest != guard.digest {
		t.Fatal("rebuilt protection changed its digest", e)
	}
	if requests.Load() != 0 {
		t.Fatal("protection issued Kubernetes requests", requests.Load())
	}
}

func TestOwnerWorkloadProbePlanRejectsAmbiguousScope(t *testing.T) {
	for _, mode := range []string{"empty-source", "wildcard-source", "foreign-account", "duplicate", "too-many"} {
		t.Run(mode, func(t *testing.T) {
			plan := cfg.OwnerWorkloadAdministration{Name: "owner-workload", Deployment: "hub", DeploymentUID: ownerID(5), ControlNamespace: cfg.NamespaceRef{Name: "owners", UID: ownerID(4)}, Administrators: []cfg.KubernetesActor{{Kind: "User", Name: "installer"}}, ConfigurationProbes: []cfg.OwnerConfigurationProbe{{ConfigMap: "owner-pool", ServiceAccount: "source-probe"}}}
			switch mode {
			case "empty-source":
				plan.ConfigurationProbes[0].ConfigMap = ""
			case "wildcard-source":
				plan.ConfigurationProbes[0].ConfigMap = "*"
			case "foreign-account":
				plan.ConfigurationProbes[0].ServiceAccount = "other/source-probe"
			case "duplicate":
				plan.ConfigurationProbes = append(plan.ConfigurationProbes, plan.ConfigurationProbes[0])
			case "too-many":
				plan.ConfigurationProbes = make([]cfg.OwnerConfigurationProbe, 9)
			}
			if _, _, err := OwnerWorkloadAdmission(plan); err == nil {
				t.Fatal("unsafe source probe scope accepted")
			}
		})
	}
}

func TestOwnerSchedulingLeasePlanRejectsAmbiguousScope(t *testing.T) {
	for _, mode := range []string{"empty-lease", "wildcard-lease", "foreign-account", "duplicate", "too-many"} {
		t.Run(mode, func(t *testing.T) {
			plan := cfg.OwnerWorkloadAdministration{Name: "owner-workload", Deployment: "hub", DeploymentUID: ownerID(5), ControlNamespace: cfg.NamespaceRef{Name: "owners", UID: ownerID(4)}, Administrators: []cfg.KubernetesActor{{Kind: "User", Name: "installer"}}, SchedulingLeases: []cfg.OwnerSchedulingLease{{Lease: "reconcile", ServiceAccount: "reconciler"}}}
			switch mode {
			case "empty-lease":
				plan.SchedulingLeases[0].Lease = ""
			case "wildcard-lease":
				plan.SchedulingLeases[0].Lease = "*"
			case "foreign-account":
				plan.SchedulingLeases[0].ServiceAccount = "other/reconciler"
			case "duplicate":
				plan.SchedulingLeases = append(plan.SchedulingLeases, plan.SchedulingLeases[0])
			case "too-many":
				plan.SchedulingLeases = make([]cfg.OwnerSchedulingLease, 5)
			}
			if _, _, err := OwnerWorkloadAdmission(plan); err == nil {
				t.Fatal("unsafe scheduling scope accepted")
			}
		})
	}
}

// ADR-193: one exact credential Secret UPDATE exception for one account.
func TestOwnerCredentialSecretPlan(t *testing.T) {
	plan := cfg.OwnerWorkloadAdministration{Name: "connector-workload", Deployment: "connector", DeploymentUID: ownerID(5), ControlNamespace: cfg.NamespaceRef{Name: "region", UID: ownerID(4)}, Administrators: []cfg.KubernetesActor{{Kind: "User", Name: "installer"}}, CredentialSecrets: []cfg.OwnerCredentialSecret{{Secret: "cluster-credential", ServiceAccount: "connector"}}}
	policy, _, err := OwnerWorkloadAdmission(plan)
	if err != nil || !strings.Contains(policy.Spec.Validations[0].Expression, `request.resource.resource == 'secrets' && variables.subResource == '' && request.name == "cluster-credential" && request.userInfo.username == "system:serviceaccount:region:connector"`) {
		t.Fatal("credential Secret exception missing", err)
	}
	for _, mutate := range []func(*cfg.OwnerWorkloadAdministration){
		func(p *cfg.OwnerWorkloadAdministration) { p.CredentialSecrets[0].Secret = "*" },
		func(p *cfg.OwnerWorkloadAdministration) { p.CredentialSecrets[0].ServiceAccount = "other/connector" },
		func(p *cfg.OwnerWorkloadAdministration) {
			p.CredentialSecrets = append(p.CredentialSecrets, cfg.OwnerCredentialSecret{Secret: "second", ServiceAccount: "connector"})
		},
	} {
		bad := plan
		bad.CredentialSecrets = slices.Clone(plan.CredentialSecrets)
		mutate(&bad)
		if _, _, err := OwnerWorkloadAdmission(bad); err == nil {
			t.Fatal("unsafe credential Secret scope accepted")
		}
	}
}
