package kubernetes

import (
	"reflect"
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

func TestProvisionedHubWorkerKeepsSeparateCredentialProjections(t *testing.T) {
	p := workerWorkloadPlan()
	installation := ownerID(1)
	legacy, err := BuildHubWorkerWorkload(p)
	if err != nil {
		t.Fatal(err)
	}
	w, err := BuildProvisionedHubWorkerWorkload(p, installation)
	if err != nil {
		t.Fatal(err)
	}
	if *w.Deployment.Spec.Replicas != 0 || !reflect.DeepEqual(w.Role, legacy.Role) || !reflect.DeepEqual(w.Binding, legacy.Binding) || !reflect.DeepEqual(w.ClusterRole, legacy.ClusterRole) || !reflect.DeepEqual(w.ClusterBinding, legacy.ClusterBinding) || !reflect.DeepEqual(w.Account, legacy.Account) {
		t.Fatal("credential composition enabled a workload or expanded its API authority")
	}
	expected := "asservat-configuration-runtime-" + strings.ReplaceAll(installation, "-", "")
	paths := map[string]string{}
	for _, source := range w.Deployment.Spec.Template.Spec.Volumes[0].Projected.Sources {
		if source.Secret == nil {
			continue
		}
		if source.Secret.Optional == nil || *source.Secret.Optional {
			t.Fatal("required credential projection became optional")
		}
		for _, item := range source.Secret.Items {
			if item.Key != item.Path || paths[item.Path] != "" {
				t.Fatal("credential path alias or overlapping projection")
			}
			paths[item.Path] = source.Secret.Name
		}
	}
	if len(paths) != 7 {
		t.Fatal("unexpected credential projection inventory", len(paths))
	}
	for _, path := range []string{contracts.ConfigurationRuntimeRoleManifestFile, "sql-fleet.json", "sql-configuration.json", "sql-audit.json"} {
		if paths[path] != expected {
			t.Fatal("SQL credential or provenance came from a caller-selected provider Secret")
		}
	}
	for _, path := range []string{"audit-storage.json", "audit-wrap.token", "audit-unwrap.token"} {
		if paths[path] != p.Credentials {
			t.Fatal("provider credential entered the SQL role projection")
		}
	}
	// Remove the independently expected projection delta, then compare the
	// entire generated workload. Security, tokens, limits and command must match.
	w.Deployment.Spec.Template.Spec.Volumes = legacy.Deployment.Spec.Template.Spec.Volumes
	if !reflect.DeepEqual(w, legacy) {
		t.Fatal("projection composition altered another workload boundary")
	}
}

func TestProvisionedHubWorkerRejectsSharedOrUnboundProjection(t *testing.T) {
	p := workerWorkloadPlan()
	if _, err := BuildProvisionedHubWorkerWorkload(p, ""); err == nil {
		t.Fatal("missing installation accepted")
	}
	p.Credentials = "asservat-configuration-runtime-" + strings.ReplaceAll(ownerID(1), "-", "")
	if _, err := BuildProvisionedHubWorkerWorkload(p, ownerID(1)); err == nil {
		t.Fatal("provider and SQL role projection merged")
	}
}
