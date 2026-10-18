package kubernetes

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

// ADR-198 decision 1: the key service mounts its inputs, its own logins and
// serving key only; RBAC is named gets of its key configuration, key Secret
// and namespace, with no list, watch or write.
func TestKeyServiceWorkloadMountsAndReadsOnlyItsOwn(t *testing.T) {
	installation := ownerID(1)
	d := contracts.KeyServiceDeployment{Format: contracts.KeyServiceDeploymentFormat, InstallationID: installation, ClusterID: ownerID(2), PermissionRootID: ownerID(3), Port: contracts.KeyServicePort,
		Namespace: contracts.WorkerObjectReference{Name: "hub", UID: ownerID(4)}, KeySource: contracts.WorkerObjectReference{Name: contracts.LocalArtifactKeyConfigurationName(installation), UID: ownerID(5)}, KeyID: "artifact", RecoveryEpoch: ownerID(6), Concurrency: 8}
	image := "registry.synthetic.invalid/asservat@sha256:" + strings.Repeat("a", 64)
	keySecret := contracts.LocalArtifactKeySecretName(installation)
	w, err := BuildKeyServiceWorkload("hub", image, d, keySecret, "NodePort", 31448)
	if err != nil {
		t.Fatal(err)
	}
	var mounted []string
	for _, s := range w.Deployment.Spec.Template.Spec.Volumes[0].Projected.Sources {
		if s.Secret != nil {
			mounted = append(mounted, s.Secret.Name)
		}
	}
	if strings.Join(mounted, ",") != contracts.KeyServiceRuntimeProjectionName(installation)+","+contracts.KeyServiceServingSecretName(installation) {
		t.Fatal("key service mounts", mounted)
	}
	var input contracts.KeyServiceDeployment
	if json.Unmarshal([]byte(w.Inputs.Data["key-service.json"]), &input) != nil || input.KeySource != d.KeySource || *w.Inputs.Immutable != true {
		t.Fatal("inputs")
	}
	for _, r := range append(w.Role.Rules, w.ClusterRole.Rules...) {
		if len(r.Verbs) != 1 || r.Verbs[0] != "get" || len(r.ResourceNames) != 1 {
			t.Fatal("key service rule is not a named get", r)
		}
	}
	if r := w.Role.Rules[1]; r.Resources[0] != "secrets" || r.ResourceNames[0] != keySecret {
		t.Fatal("key Secret read", r)
	}
	if p := w.Service.Spec.Ports[0]; p.Port != contracts.KeyServicePort || p.NodePort != 31448 {
		t.Fatal("service", p)
	}
	for name, mutate := range map[string]func(*contracts.KeyServiceDeployment){
		"other namespace": func(c *contracts.KeyServiceDeployment) { c.Namespace.Name = "other" },
		"other port":      func(c *contracts.KeyServiceDeployment) { c.Port = 9446 },
		"no key source":   func(c *contracts.KeyServiceDeployment) { c.KeySource.Name = "" },
	} {
		c := d
		mutate(&c)
		if _, err := BuildKeyServiceWorkload("hub", image, c, keySecret, "NodePort", 31448); err == nil {
			t.Fatal("accepted:", name)
		}
	}
	if _, err := BuildKeyServiceWorkload("hub", "registry.synthetic.invalid/asservat:latest", d, keySecret, "NodePort", 31448); err == nil {
		t.Fatal("unpinned image accepted")
	}
	// ADR-204: only with downloads does the Pod get its probe token and the
	// catalog, guard and topology reads; the catalog's update serves only its
	// denied dry-run probe.
	tokens := func(w *FederationWorkload) (out []string) {
		for _, s := range w.Deployment.Spec.Template.Spec.Volumes[0].Projected.Sources {
			if s.ServiceAccountToken != nil {
				out = append(out, s.ServiceAccountToken.Path)
			}
		}
		return out
	}
	if !slices.Equal(tokens(w), []string{"kube-observer.token"}) {
		t.Fatal("probe token without downloads", tokens(w))
	}
	d.Downloads = &contracts.KeyServiceDownloads{ClusterCatalog: contracts.OwnerPublicGuardedSource{Source: contracts.WorkerObjectReference{Name: contracts.OwnerClusterCatalogName(installation), UID: ownerID(7)}, Guard: contracts.OwnerDeploymentGuard{Name: "cluster-catalog-guard"}},
		RetentionTopologies: []contracts.OwnerNativeTopology{{TargetClusterID: d.ClusterID, Name: "hub-topology", UID: ownerID(8), SHA256: strings.Repeat("1", 64)}}}
	downloads, err := BuildKeyServiceWorkload("hub", image, d, keySecret, "NodePort", 31448)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(tokens(downloads), []string{"kube-observer.token", "kube-probe.token"}) || len(downloads.Role.Rules) != 4 || len(downloads.ClusterRole.Rules) != 2 {
		t.Fatal("downloads workload", tokens(downloads))
	}
	catalog, topology, guard := downloads.Role.Rules[2], downloads.Role.Rules[3], downloads.ClusterRole.Rules[1]
	if !slices.Equal(catalog.ResourceNames, []string{contracts.OwnerClusterCatalogName(installation)}) || !slices.Equal(catalog.Verbs, []string{"get", "update"}) ||
		!slices.Contains(topology.ResourceNames, "hub-topology") || !slices.Contains(topology.ResourceNames, contracts.OwnerClusterSourceName(installation, 1, "topology")) || !slices.Equal(topology.Verbs, []string{"get"}) ||
		!slices.Equal(guard.ResourceNames, []string{"cluster-catalog-guard"}) || !slices.Equal(guard.Verbs, []string{"get"}) {
		t.Fatal("downloads RBAC", catalog, topology, guard)
	}
}
