package kubernetes

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

// ADR-203: the publisher mounts its inputs, its own SQL logins and its two
// operator credentials; it has no Service, and its only write is the dry-run
// probe target of each guard it proves.
func TestPublisherWorkloadMountsAndReadsOnlyItsOwn(t *testing.T) {
	installation := ownerID(1)
	name := contracts.PublisherName(installation)
	ns := contracts.WorkerObjectReference{Name: "hub", UID: ownerID(4)}
	identity := PublisherIdentity{Account: contracts.WorkerObjectReference{Name: name, UID: ownerID(5)},
		AuditCredentials: contracts.WorkerObjectReference{Name: name + "-audit", UID: ownerID(6)}, EvidenceCredentials: contracts.WorkerObjectReference{Name: name + "-evidence", UID: ownerID(7)}}
	d := contracts.PublisherDeployment{Format: contracts.PublisherDeploymentFormat, InstallationID: installation, ClusterID: ownerID(2), PermissionRootID: ownerID(3), Namespace: ns,
		ClusterCatalog:         contracts.OwnerPublicGuardedSource{Source: contracts.WorkerObjectReference{Name: contracts.OwnerClusterCatalogName(installation), UID: ownerID(8)}, Guard: contracts.OwnerDeploymentGuard{Name: "catalog-guard"}},
		Owner:                  contracts.OwnerGuardInputs{Namespace: ns, WorkloadGuard: contracts.OwnerDeploymentGuard{Name: "workload-guard"}},
		ProviderAuthentication: contracts.PublisherProviderAuthentication{Format: contracts.PublisherProviderAuthenticationFormat, Namespace: ns, ServiceAccount: identity.Account},
		PollSeconds:            2, Batch: 8}
	image := "registry.synthetic.invalid/asservat@sha256:" + strings.Repeat("a", 64)
	w, err := BuildPublisherWorkload("hub", image, "asservat-owner", d, identity)
	if err != nil {
		t.Fatal(err)
	}
	if w.Service != nil {
		t.Fatal("publisher has a Service")
	}
	var mounted []string
	tokens := map[string]string{}
	for _, s := range w.Deployment.Spec.Template.Spec.Volumes[0].Projected.Sources {
		if s.Secret != nil {
			mounted = append(mounted, s.Secret.Name)
		}
		if s.ServiceAccountToken != nil {
			tokens[s.ServiceAccountToken.Path] = s.ServiceAccountToken.Audience
		}
	}
	if strings.Join(mounted, ",") != contracts.PublisherRuntimeProjectionName(installation)+","+name+"-audit,"+name+"-evidence" {
		t.Fatal("publisher mounts", mounted)
	}
	if len(tokens) != 3 || tokens[contracts.PublisherProviderTokenFile] != contracts.PublisherProviderAudience(installation, ownerID(2)) || tokens[contracts.PublisherKubernetesToken] != "" || tokens[contracts.PublisherProbeToken] != "" {
		t.Fatal("tokens", tokens)
	}
	var input contracts.PublisherDeployment
	if json.Unmarshal([]byte(w.Inputs.Data[contracts.PublisherDeploymentFile]), &input) != nil || input.ClusterCatalog.Source != d.ClusterCatalog.Source || *w.Inputs.Immutable != true {
		t.Fatal("inputs")
	}
	if c := w.Deployment.Spec.Template.Spec.Containers[0]; strings.Join(c.Command, " ") != "/asservat publisher" || len(c.Ports) != 0 {
		t.Fatal("container", c.Command, c.Ports)
	}
	for _, r := range append(w.Role.Rules, w.ClusterRole.Rules...) {
		if slices.Contains(r.Resources, "secrets") || slices.Contains(r.Verbs, "create") || slices.Contains(r.Verbs, "delete") || slices.Contains(r.Verbs, "watch") {
			t.Fatal("publisher rule too broad", r)
		}
		if slices.Contains(r.Verbs, "update") && (len(r.ResourceNames) != 1 || r.ResourceNames[0] != "asservat-owner" && r.ResourceNames[0] != d.ClusterCatalog.Source.Name) {
			t.Fatal("update beyond the probe targets", r)
		}
	}
	for label, mutate := range map[string]func(*contracts.PublisherDeployment, *PublisherIdentity){
		"other namespace": func(c *contracts.PublisherDeployment, _ *PublisherIdentity) { c.Namespace.Name = "other" },
		"other account": func(c *contracts.PublisherDeployment, _ *PublisherIdentity) {
			c.ProviderAuthentication.ServiceAccount.Name = "other"
		},
		"other audit Secret": func(_ *contracts.PublisherDeployment, i *PublisherIdentity) { i.AuditCredentials.Name = "other" },
		"other catalog":      func(c *contracts.PublisherDeployment, _ *PublisherIdentity) { c.ClusterCatalog.Source.Name = "other" },
		"no workload guard":  func(c *contracts.PublisherDeployment, _ *PublisherIdentity) { c.Owner.WorkloadGuard.Name = "" },
		"evidence as audit": func(_ *contracts.PublisherDeployment, i *PublisherIdentity) {
			i.EvidenceCredentials.Name = name + "-audit"
		},
	} {
		c, i := d, identity
		mutate(&c, &i)
		if _, err := BuildPublisherWorkload("hub", image, "asservat-owner", c, i); err == nil {
			t.Fatal("accepted:", label)
		}
	}
	if _, err := BuildPublisherWorkload("hub", "registry.synthetic.invalid/asservat:latest", "asservat-owner", d, identity); err == nil {
		t.Fatal("unpinned image accepted")
	}
}
