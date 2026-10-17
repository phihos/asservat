package kubernetes

import (
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"encoding/json"
	admission "k8s.io/api/admissionregistration/v1"
	"reflect"
	"testing"
)

func TestInstalledCapacityProbeDerivedBeforeOriginalGuardClaim(t *testing.T) {
	s, v := installedOwnerResourceFixture(t)
	inv, e := s.inventory(v)
	if e != nil {
		t.Fatal(e)
	}
	p := inv.BridgeAdministration.Owner
	want := cfg.OwnerCapacityProbe{ServiceAccount: inv.WorkerAccount.Name, ServiceAccountUID: inv.WorkerAccount.UID}
	if p.CapacityProbe == nil || *p.CapacityProbe != want || len(p.ConfigurationProbes) != 3 || len(inv.BridgeAdministration.SourceProbes) != 3 {
		t.Fatal("original worker proof not bound")
	}
	built, e := s.object(v, 17)
	if e != nil {
		t.Fatal(e)
	}
	policy, _, e := OwnerWorkloadAdmission(p)
	if e != nil || !reflect.DeepEqual(policy.Spec, built.object.(*admission.ValidatingAdmissionPolicy).Spec) {
		t.Fatal("inventory differs from original guard", e)
	}
	a, e := BuildHubWorkerActivation(s.initial.InstallationID, contracts.InitialRuntimeResourceSnapshot{State: v, UID: ownerID(4090)}, inv)
	if e != nil {
		t.Fatal(e)
	}
	input := contracts.HubWorkerDeployment{InstallationID: s.initial.InstallationID, Namespace: inv.Namespace, FleetSource: inv.FleetSource, OwnerSource: inv.OwnerSource, OwnerGuard: inv.OwnerSourceGuard, LeaderLease: inv.LeaderLease, Activation: a}
	if !HubWorkerActivationBound(input) || !reflect.DeepEqual(capacityActivationAdministration(input), p) {
		t.Fatal("activation loses original guard")
	}
	inv.BridgeAdministration.Owner.CapacityProbe.ServiceAccountUID = ownerID(4091)
	if a.CapacityProbe.ServiceAccount.UID != want.ServiceAccountUID {
		t.Fatal("activation retains mutable source")
	}
	for _, mode := range []string{"missing-probe", "different-name", "different-uid", "wrong-configmap", "extra-probe", "reordered-probes"} {
		t.Run(mode, func(t *testing.T) {
			b, _ := json.Marshal(input)
			var bad contracts.HubWorkerDeployment
			if json.Unmarshal(b, &bad) != nil {
				t.Fatal("clone")
			}
			switch mode {
			case "missing-probe":
				bad.Activation.CapacityProbe = nil
			case "different-name":
				bad.Activation.CapacityProbe.ServiceAccount.Name = "other"
			case "different-uid":
				bad.Activation.CapacityProbe.ServiceAccount.UID = ownerID(4092)
			case "wrong-configmap":
				bad.Activation.ConfigurationProbes[2].ConfigMap = "arbitrary"
			case "extra-probe":
				bad.Activation.ConfigurationProbes = append(bad.Activation.ConfigurationProbes, bad.Activation.ConfigurationProbes[2])
			case "reordered-probes":
				bad.Activation.ConfigurationProbes[0], bad.Activation.ConfigurationProbes[2] = bad.Activation.ConfigurationProbes[2], bad.Activation.ConfigurationProbes[0]
			}
			if HubWorkerActivationBound(bad) {
				t.Fatal("changed original accepted")
			}
		})
	}
}

func TestInstalledCapacityProbeLegacyOmissionCannotBeAdopted(t *testing.T) {
	s, v := installedWorkerResourceFixture(t)
	inv, e := s.inventory(v)
	if e != nil {
		t.Fatal(e)
	}
	if inv.BridgeAdministration.Owner.CapacityProbe != nil || len(inv.BridgeAdministration.Owner.ConfigurationProbes) != 2 {
		t.Fatal("legacy expanded")
	}
	inv.BridgeAdministration.Owner.CapacityProbe = &cfg.OwnerCapacityProbe{ServiceAccount: inv.WorkerAccount.Name, ServiceAccountUID: inv.WorkerAccount.UID}
	if _, e = BuildHubWorkerActivation(s.initial.InstallationID, contracts.InitialRuntimeResourceSnapshot{State: v, UID: ownerID(4093)}, inv); e == nil {
		t.Fatal("legacy adopted installed facet")
	}
	installed, state := installedOwnerResourceFixture(t)
	iin, e := installed.inventory(state)
	if e != nil {
		t.Fatal(e)
	}
	iin.BridgeAdministration.Owner.CapacityProbe = nil
	if _, e = BuildHubWorkerActivation(installed.initial.InstallationID, contracts.InitialRuntimeResourceSnapshot{State: state, UID: ownerID(4094)}, iin); e == nil {
		t.Fatal("installed guard lost original facet")
	}
}
