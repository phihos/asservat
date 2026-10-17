package kubernetes

import (
	"encoding/json"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

// This regression compiles against the prior implementation: the new explicit
// public capability used to disappear during DTO decoding/template composition.
func TestInitialRegistryRequestedActivationPullIsNotSilentlyOmitted(t *testing.T) {
	p := initialWorkloadPlan()
	raw, _ := json.Marshal(map[string]any{"namespace": p.Namespace, "name": p.Name, "writerAccount": p.WriterAccount, "probeAccount": p.ProbeAccount, "configuration": p.Configuration, "credentials": p.Credentials, "image": p.Image, "witness": p.Witness, "fleetSource": p.FleetSource, "witnessGuard": p.WitnessGuard, "fleetGuard": p.FleetGuard, "workloadGuard": p.WorkloadGuard, "registryAuthentication": "dockerconfigjson/v1"})
	var workload contracts.InitialPreparationWorkload
	if json.Unmarshal(raw, &workload) != nil {
		t.Fatal("fixture decode failed")
	}
	w, err := BuildInitialInstallerWorkload(preparerWorkload(contracts.InitialPreparationPlan{Workload: workload}))
	if err != nil {
		t.Fatal(err)
	}
	if len(w.Pod.Spec.ImagePullSecrets) != 1 || w.Pod.Spec.ImagePullSecrets[0].Name != p.Credentials {
		t.Fatal("explicit registry capability silently omitted from original activation Pod")
	}
}
