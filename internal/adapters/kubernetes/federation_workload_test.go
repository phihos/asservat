package kubernetes

import (
	"slices"
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

// ADR-193: the federation runs Restricted with only its own projected inputs;
// its RBAC reads the owner guard and names one dry-run probe target.
func TestFederationWorkloadIsRestrictedAndNarrow(t *testing.T) {
	installation := "10000000-0000-4000-8000-000000000001"
	ns := contracts.WorkerObjectReference{Name: "asservat-hub", UID: "10000000-0000-4000-8000-000000000002"}
	d := contracts.FederationDeployment{Format: contracts.FederationDeploymentFormat, InstallationID: installation, ClusterID: "10000000-0000-4000-8000-000000000003", PermissionRootID: "10000000-0000-4000-8000-000000000004",
		Port: contracts.FederationPort, Concurrency: 2, Owner: &contracts.OwnerGuardInputs{Namespace: ns, WorkloadGuard: contracts.OwnerDeploymentGuard{Name: "hub-guard"}},
		ProviderAuthentication: &contracts.FederationProviderAuthentication{Namespace: ns, ServiceAccount: contracts.WorkerObjectReference{Name: contracts.FederationServiceAccountName(installation)},
			AuditCredentials: contracts.WorkerObjectReference{Name: contracts.FederationAuditSecretName(installation)}}}
	image := "registry.example/asservat@sha256:" + strings.Repeat("a", 64)
	w, err := BuildFederationWorkload(ns.Name, image, "hub-owner", "owner-account", d, "NodePort", 31446)
	if err != nil {
		t.Fatal(err)
	}
	p := w.Deployment.Spec.Template.Spec
	c := p.Containers[0]
	if *p.AutomountServiceAccountToken || !*p.SecurityContext.RunAsNonRoot || !*c.SecurityContext.ReadOnlyRootFilesystem || *c.SecurityContext.AllowPrivilegeEscalation || c.SecurityContext.Capabilities.Drop[0] != "ALL" || c.Command[1] != "hub-federation" {
		t.Fatal("federation Pod not Restricted")
	}
	files := map[string]bool{}
	for _, source := range p.Volumes[0].Projected.Sources {
		if source.ConfigMap != nil {
			for _, item := range source.ConfigMap.Items {
				files[item.Path] = true
			}
		}
		if source.Secret != nil {
			for _, item := range source.Secret.Items {
				files[item.Path] = true
			}
		}
		if source.ServiceAccountToken != nil {
			files[source.ServiceAccountToken.Path] = true
		}
	}
	for _, want := range []string{"federation.json", contracts.FederationAuditKeysFile, "sql-federation-connector-read.json", "audit-storage.json", "tls.crt", "tls.key", contracts.FederationProviderTokenFile, "kube-observer.token", "kube-probe.token"} {
		if !files[want] {
			t.Fatal("missing projected input", want)
		}
	}
	for _, rule := range w.Role.Rules {
		for _, verb := range rule.Verbs {
			if verb == "update" && (len(rule.ResourceNames) != 1 || rule.ResourceNames[0] != "hub-owner") {
				t.Fatal("update beyond the owner probe target")
			}
			if verb == "create" || verb == "delete" || verb == "patch" {
				t.Fatal("federation can write the hub namespace")
			}
		}
	}
	accountRead := false
	for _, rule := range w.Role.Rules {
		if slices.Contains(rule.Resources, "serviceaccounts") {
			if len(rule.APIGroups) != 1 || rule.APIGroups[0] != "" || len(rule.Resources) != 1 || len(rule.Verbs) != 1 || rule.Verbs[0] != "get" || len(rule.ResourceNames) != 1 || rule.ResourceNames[0] != "owner-account" {
				t.Fatal("owner account read is not exact GET-only")
			}
			accountRead = true
		}
	}
	if !accountRead {
		t.Fatal("rendered federation role cannot perform OwnerEndpoints' required owner ServiceAccount GET")
	}

	if w.Service.Spec.Ports[0].NodePort != 31446 {
		t.Fatal("pinned node port not applied")
	}
	if _, err = BuildFederationWorkload(ns.Name, image, "hub-owner", "owner-account", d, "LoadBalancer", 31446); err == nil {
		t.Fatal("node port accepted for a LoadBalancer")
	}
	if _, err = BuildFederationWorkload(ns.Name, image, "hub-owner", "owner-account", d, "ClusterIP", 0); err == nil {
		t.Fatal("non-L4 Service accepted")
	}
	if _, err = BuildFederationWorkload(ns.Name, "registry.example/asservat:latest", "hub-owner", "owner-account", d, "NodePort", 0); err == nil {
		t.Fatal("unpinned image accepted")
	}
}

func TestFederationWorkloadRejectsInvalidOwnerAccount(t *testing.T) {
	installation := "10000000-0000-4000-8000-000000000001"
	ns := contracts.WorkerObjectReference{Name: "asservat-hub"}
	d := contracts.FederationDeployment{InstallationID: installation, Port: contracts.FederationPort, Owner: &contracts.OwnerGuardInputs{Namespace: ns}, ProviderAuthentication: &contracts.FederationProviderAuthentication{Namespace: ns, ServiceAccount: contracts.WorkerObjectReference{Name: contracts.FederationServiceAccountName(installation)}}}
	for _, account := range []string{"", "*", "other/account", "Owner", strings.Repeat("a", 254)} {
		if _, err := BuildFederationWorkload(ns.Name, "registry.example/asservat@sha256:"+strings.Repeat("a", 64), "hub-owner", account, d, "NodePort", 31446); err == nil {
			t.Fatalf("invalid owner account accepted: %q", account)
		}
	}
}
