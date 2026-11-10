package kubernetes

import (
	"encoding/json"
	rbac "k8s.io/api/rbac/v1"
	"reflect"
	"slices"
	"testing"

	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
)

func ownerProviderInstalledSelection() contracts.OwnerProviderSelection {
	p := installedOwnerPlan()
	return contracts.OwnerProviderSelection{AuthMount: "owner-auth", AuthMountAccessor: "auth_original", AuditCredentials: contracts.WorkerObjectReference{Name: contracts.OwnerProviderAuditSecretName(p.InstallationID), UID: ownerID(149)}}
}

func TestProviderInstalledOwnerSeparatesSQLStorageAndNativeAuthentication(t *testing.T) {
	p, selection := installedOwnerPlan(), ownerProviderInstalledSelection()
	v1, err := BuildInstalledOwnerWorkload(p)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(v1)
	w, err := BuildProviderOwnerWorkload(p, ownerID(2), selection)
	if err != nil {
		t.Fatal(err)
	}
	pod := w.Deployment.Spec.Template.Spec
	if *w.Deployment.Spec.Replicas != 0 || len(pod.Containers) != 1 || len(pod.InitContainers) != 0 || !reflect.DeepEqual(pod.SecurityContext, v1.Deployment.Spec.Template.Spec.SecurityContext) || !reflect.DeepEqual(pod.Tolerations, v1.Deployment.Spec.Template.Spec.Tolerations) {
		t.Fatal("fresh provider template changes launch/security/native identity")
	}
	sources := pod.Volumes[0].Projected.Sources
	if len(sources) != len(v1.Deployment.Spec.Template.Spec.Volumes[0].Projected.Sources)+2 || len(sources[1].Secret.Items) != 1+len(contracts.OwnerIdentityRolePurposes()) {
		t.Fatal("unexpected identity/provider projection graph")
	}
	keys := []string{contracts.OwnerIdentityRoleManifestFile, "sql-owner-runtime.json"}
	for i, item := range sources[1].Secret.Items {
		if item.Key != keys[i] || item.Path != item.Key {
			t.Fatal("SQL identity projection includes or redirects another credential")
		}
	}
	audit, auth := sources[len(sources)-2].Secret, sources[len(sources)-1].ServiceAccountToken
	if audit == nil || audit.Name != selection.AuditCredentials.Name || audit.Name == p.Credentials || audit.Optional != nil && *audit.Optional || !reflect.DeepEqual(audit.Items, []core.KeyToPath{{Key: contracts.OwnerProviderAuditCredentialFile, Path: contracts.OwnerProviderAuditCredentialFile}}) {
		t.Fatal("storage material aliases immutable SQL credentials or is optional")
	}
	if auth == nil || auth.Path != contracts.OwnerProviderTokenFile || auth.Audience != contracts.OwnerProviderAudience(p.InstallationID, ownerID(2)) || auth.ExpirationSeconds == nil || *auth.ExpirationSeconds != 600 {
		t.Fatal("native provider JWT is not fixed to original scope")
	}
	for _, rule := range w.Role.Rules {
		if slices.Contains(rule.Resources, "secrets") && (!reflect.DeepEqual(rule.Verbs, []string{"get"}) || len(rule.ResourceNames) == 0) {
			t.Fatal("provider profile widened Secret authority")
		}
	}
	// ADR-185: exactly the audit Secret, the guarded public sources (get and
	// update for the dry-run probe), the two settings and the immutable slot
	// topologies (ADR-196 decision 7), and their guards.
	public := contracts.OwnerPublicGuardedSources(p.InstallationID)
	guards := make([]string, 0, len(public)+1)
	for _, name := range public {
		guards = append(guards, name+"-guard")
	}
	// ADR-210: and the capacity processing source with its own guard.
	_, _, _, processing, processingGuard := CapacitySourceNames(p.InstallationID)
	public, guards = append(public, processing), append(guards, processingGuard)
	extra := w.Role.Rules[len(v1.Role.Rules):]
	// ADR-228: and get on hub-held DebugPolicies; REQ-CPR-001: and get on
	// organization CaptureProfiles; no other verb or resource.
	if len(extra) != 5 || !reflect.DeepEqual(extra[3], rbac.PolicyRule{APIGroups: []string{"asservat.io"}, Resources: []string{"debugpolicies"}, Verbs: []string{"get"}}) || !reflect.DeepEqual(extra[4], rbac.PolicyRule{APIGroups: []string{"asservat.io"}, Resources: []string{"captureprofiles"}, Verbs: []string{"get", "list"}}) || !reflect.DeepEqual(extra[1].ResourceNames, public) || !reflect.DeepEqual(extra[1].Verbs, []string{"get", "update"}) || !reflect.DeepEqual(extra[2].ResourceNames, append([]string{contracts.OwnerBrowserSettingsName(p.InstallationID), contracts.OwnerIdentitySettingsName(p.InstallationID)}, contracts.OwnerClusterTopologyNames(p.InstallationID)...)) || !reflect.DeepEqual(extra[2].Verbs, []string{"get"}) {
		t.Fatal("unexpected provider privilege graph")
	}
	cluster := w.ClusterRole.Rules
	base := len(v1.ClusterRole.Rules)
	if len(cluster) != base+4 || !reflect.DeepEqual(cluster[:base], v1.ClusterRole.Rules) || !reflect.DeepEqual(cluster[base].ResourceNames, guards) || !reflect.DeepEqual(cluster[base].Verbs, []string{"get"}) {
		t.Fatal("unexpected provider cluster privileges")
	}
	// ADR-190 decision 7: metadata reads for the hub cluster's capacity
	// observation and get on its selector guard; never a write. ADR-247: the
	// permission workload journal also watches Deployments/StatefulSets and
	// the workload metadata guard is read like the selector guard.
	_, selector, _, _, _ := CapacitySourceNames(p.InstallationID)
	for _, r := range cluster[base+1:] {
		workloads := reflect.DeepEqual(r.Resources, []string{"deployments", "statefulsets"}) && reflect.DeepEqual(r.Verbs, []string{"get", "list", "watch"})
		if !workloads && !reflect.DeepEqual(r.Verbs, []string{"get", "list"}) && !(reflect.DeepEqual(r.Verbs, []string{"get"}) && reflect.DeepEqual(r.ResourceNames, []string{selector, WorkloadGuardName(p.InstallationID)})) {
			t.Fatal("capacity observation grants more than reads", r)
		}
	}
	// Rebuilding v1 after mutation of the fresh result must retain its bytes.
	sources[1].Secret.Items[0].Key = "changed"
	again, err := BuildInstalledOwnerWorkload(p)
	after, _ := json.Marshal(again)
	if err != nil || string(before) != string(after) {
		t.Fatal("v2 changed original v1 template bytes", err)
	}
}

func TestProviderOwnerFleetReadScope(t *testing.T) {
	p := installedOwnerPlan()
	p.FleetGuard = "fleet-settings-guard"
	p.FleetSource = "fleet-settings"
	w, err := BuildProviderOwnerWorkload(p, ownerID(2), ownerProviderInstalledSelection())
	if err != nil {
		t.Fatal(err)
	}
	configMaps, guards := 0, 0
	for _, rule := range w.Role.Rules {
		if slices.Contains(rule.ResourceNames, p.FleetSource) {
			configMaps++
			if !reflect.DeepEqual(rule.APIGroups, []string{""}) || !reflect.DeepEqual(rule.Resources, []string{"configmaps"}) || !reflect.DeepEqual(rule.Verbs, []string{"get", "update"}) {
				t.Fatal("fleet source received unrelated Role authority", rule)
			}
		}
		if slices.Contains(rule.ResourceNames, p.FleetGuard) {
			t.Fatal("fleet guard is readable in the wrong scope", rule)
		}
	}
	for _, rule := range w.ClusterRole.Rules {
		if slices.Contains(rule.ResourceNames, p.FleetSource) {
			t.Fatal("fleet source received cluster-wide authority", rule)
		}
		if slices.Contains(rule.ResourceNames, p.FleetGuard) {
			guards++
			if !reflect.DeepEqual(rule.APIGroups, []string{"admissionregistration.k8s.io"}) || !reflect.DeepEqual(rule.Resources, []string{"validatingadmissionpolicies", "validatingadmissionpolicybindings"}) || !reflect.DeepEqual(rule.Verbs, []string{"get"}) {
				t.Fatal("fleet guard received unrelated ClusterRole authority", rule)
			}
		}
	}
	if configMaps != 1 || guards != 1 {
		t.Fatalf("fleet read scope counts = (%d, %d), want (1, 1)", configMaps, guards)
	}
}

func TestProviderInstalledOwnerRejectsCredentialScopeSubstitution(t *testing.T) {
	for _, name := range []string{"secret-name", "missing-uid", "auth-path", "token-mount", "accessor", "cluster"} {
		t.Run(name, func(t *testing.T) {
			p, selected, cluster := installedOwnerPlan(), ownerProviderInstalledSelection(), ownerID(2)
			switch name {
			case "secret-name":
				selected.AuditCredentials.Name = p.Credentials
			case "missing-uid":
				selected.AuditCredentials.UID = ""
			case "auth-path":
				selected.AuthMount = "auth/other"
			case "token-mount":
				selected.AuthMount = "token"
			case "accessor":
				selected.AuthMountAccessor = ""
			case "cluster":
				cluster = ""
			}
			if _, err := BuildProviderOwnerWorkload(p, cluster, selected); err == nil {
				t.Fatal("invalid original selection produced a workload")
			}
		})
	}
}
