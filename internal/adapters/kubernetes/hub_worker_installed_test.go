package kubernetes

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
)

// This is synthetic original provenance, not a journal migration or API proof.
func installedWorkerResourceFixture(t *testing.T) (*InitialRuntimeResources, contracts.InitialRuntimeResourceState) {
	t.Helper()
	s, v := initialRuntimeResourceFixture(t)
	s.workerLayout, v.WorkerLayout = contracts.HubWorkerInstalledLayout, contracts.HubWorkerInstalledLayout
	for i := range v.Objects {
		obj, err := s.object(v, i)
		if err != nil {
			t.Fatal(err)
		}
		v.Objects[i].TemplateDigest = preparationDigest(obj.object)
	}
	return s, v
}

func TestInstalledWorkerOriginalTemplateSeparatesPendingProjections(t *testing.T) {
	s, v := installedWorkerResourceFixture(t)
	obj, err := s.object(v, 11)
	if err != nil {
		t.Fatal(err)
	}
	d := obj.object.(*apps.Deployment)
	if *d.Spec.Replicas != 0 {
		t.Fatal("builder launched worker")
	}
	sources := d.Spec.Template.Spec.Volumes[0].Projected.Sources
	if len(sources) != 11 {
		t.Fatalf("fixed projection count %d", len(sources))
	}
	// ADR-205: the evidence delete Secret is optional, like the projections.
	if deletion := sources[9].Secret; deletion == nil || deletion.Name != contracts.EvidenceDeleteCredentialName(s.initial.InstallationID) || deletion.Optional == nil || !*deletion.Optional || len(deletion.Items) != 1 {
		t.Fatal("evidence delete credential projection", sources[9])
	}
	token := sources[10].ServiceAccountToken
	if token == nil || token.Path != contracts.HubWorkerClusterObservationTokenFile || token.Audience != "https://asservat."+s.initial.InstallationID+"/cluster-observation" || token.ExpirationSeconds == nil || *token.ExpirationSeconds != 600 || len(d.Spec.Template.Spec.Containers[0].Env) != 1 || d.Spec.Template.Spec.Containers[0].Env[0].Name != contracts.OwnerPodUIDEnvironment || d.Spec.Template.Spec.Containers[0].Env[0].ValueFrom == nil || d.Spec.Template.Spec.Containers[0].Env[0].ValueFrom.FieldRef == nil || d.Spec.Template.Spec.Containers[0].Env[0].ValueFrom.FieldRef.FieldPath != "metadata.uid" {
		t.Fatal("local observation projection changed audience or native Pod provenance")
	}
	for i, name := range []string{contracts.CapacityRuntimeProjectionName(s.initial.InstallationID), contracts.HubWorkerCleanupProjectionName(s.initial.InstallationID), contracts.PermissionRuntimeProjectionName(s.initial.InstallationID)} {
		p := sources[6+i].Secret
		if p == nil || p.Name != name || p.Optional == nil || !*p.Optional {
			t.Fatal("pending projection prevents configuration-first startup")
		}
		directory := []string{contracts.CapacityWorkerProjectionDirectory, contracts.HubWorkerCleanupProjectionDirectory, contracts.PermissionWorkerProjectionDirectory}[i]
		for _, item := range p.Items {
			if item.Path != directory+"/"+item.Key || strings.Contains(item.Key, "root-setup") || strings.Contains(item.Key, "sql-public-") || item.Key == contracts.PublicAuditKeysFile {
				t.Fatal("projection crosses fixed compartment")
			}
		}
	}
	for i := 0; i < 6; i++ {
		if sources[i].Secret != nil && (sources[i].Secret.Optional == nil || *sources[i].Secret.Optional) {
			t.Fatal("configuration credentials became optional")
		}
	}
	legacy, old := initialRuntimeResourceFixture(t)
	legacyObject, _ := legacy.object(old, 11)
	if reflect.DeepEqual(legacyObject.object, obj.object) || s.valid(old) || legacy.valid(v) {
		t.Fatal("legacy journal reinterpreted as final installed template")
	}
	oldBytes, _ := json.Marshal(old)
	if strings.Contains(string(oldBytes), "workerLayout") {
		t.Fatal("legacy omission changed")
	}
}

func TestInstalledWorkerRejectsPreDeletionTemplateDigest(t *testing.T) {
	s, v := installedWorkerResourceFixture(t)
	if !s.valid(v) {
		t.Fatal("current installed journal fixture is invalid")
	}
	obj, err := s.object(v, 11)
	if err != nil {
		t.Fatal(err)
	}
	old := obj.object.(*apps.Deployment).DeepCopy()
	volume := old.Spec.Template.Spec.Volumes[0].Projected
	volume.Sources = slices.DeleteFunc(volume.Sources, func(source core.VolumeProjection) bool {
		return source.Secret != nil && source.Secret.Name == contracts.EvidenceDeleteCredentialName(s.initial.InstallationID)
	})
	for i := range volume.Sources {
		if secret := volume.Sources[i].Secret; secret != nil && secret.Name == contracts.PermissionRuntimeProjectionName(s.initial.InstallationID) {
			secret.Items = slices.DeleteFunc(secret.Items, func(item core.KeyToPath) bool { return strings.HasPrefix(item.Key, "sql-context-cleanup") })
		}
	}
	before := v.Objects[11].TemplateDigest
	v.Objects[11].TemplateDigest = preparationDigest(old)
	if v.Objects[11].TemplateDigest == before || s.valid(v) {
		t.Fatal("older installed template rebound to the current layout")
	}
}

func TestInstalledWorkerActivationRetainsOriginalJournalAndGuard(t *testing.T) {
	s, v := installedWorkerResourceFixture(t)
	in, err := s.inventory(v)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := contracts.InitialRuntimeResourceSnapshot{State: v, UID: ownerID(1940)}
	a, err := BuildHubWorkerActivation(s.initial.InstallationID, snapshot, in)
	if err != nil {
		t.Fatal(err)
	}
	if a.Resources.UID != snapshot.UID || a.SetupID != v.SetupID || a.BindingDigest != v.BindingDigest || !a.CreatedAt.Equal(v.CreatedAt) || !a.Until.Equal(v.Until) || a.Deployment != in.WorkerDeployment || a.ServiceAccount != in.WorkerAccount || a.WorkloadGuard.PolicyUID != in.WorkloadGuard.PolicyUID {
		t.Fatal("generator changed original identities or interval")
	}
	in.WorkloadGuard.Administrators[0].Name = "mutated caller"
	if a.WorkloadGuard.Administrators[0].Name == "mutated caller" {
		t.Fatal("generator retained mutable caller guard")
	}
}

func TestInstalledWorkerActivationRejectsUnacknowledgedOrChangedOriginal(t *testing.T) {
	for _, mode := range []string{"legacy", "unknown-layout", "pending-object", "refill", "duplicate-operation", "different-worker", "different-guard", "different-history"} {
		t.Run(mode, func(t *testing.T) {
			s, v := installedWorkerResourceFixture(t)
			in, err := s.inventory(v)
			if err != nil {
				t.Fatal(err)
			}
			snapshot := contracts.InitialRuntimeResourceSnapshot{State: v, UID: ownerID(1941)}
			switch mode {
			case "legacy":
				snapshot.State.WorkerLayout = ""
			case "unknown-layout":
				snapshot.State.WorkerLayout += "-future"
			case "pending-object":
				snapshot.State.Objects[11].Receipt = nil
			case "refill":
				snapshot.State.Until = snapshot.State.Until.AddDate(0, 0, 1)
			case "duplicate-operation":
				snapshot.State.Objects[1].OperationID = snapshot.State.Objects[0].OperationID
			case "different-worker":
				in.WorkerDeployment.UID = ownerID(1942)
			case "different-guard":
				in.WorkloadGuard.BindingUID = ownerID(1942)
			case "different-history":
				in.BridgeAdministration.Owner.InitialHistoryProbe.Namespace = in.BridgeAdministration.Owner.ControlNamespace
			}
			if _, err = BuildHubWorkerActivation(s.initial.InstallationID, snapshot, in); err == nil {
				t.Fatal("changed or pending original became installed input")
			}
		})
	}
}
