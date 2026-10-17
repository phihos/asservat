package bootstrap

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

func TestConfigurationInstallerGeneratedInputRetainsExactHistoryCapability(t *testing.T) {
	original, owner, worker := configurationRoleInputPair(t)
	owner.InitialHistoryProbe = &contracts.OwnerInitialHistoryProbe{Namespace: contracts.WorkerObjectReference{Name: "original-bootstrap", UID: "10000000-0000-4000-8000-000000000081"}, ServiceAccount: contracts.WorkerObjectReference{Name: "original-history", UID: "10000000-0000-4000-8000-000000000082"}, Configuration: "original-inputs"}
	b, e := BuildConfigurationRoleInstallerInput(owner, worker, original.OwnerDeployment, original.Roles.Deployment, original.Roles.ServiceAccount, original.Roles.InitialClaimID)
	if e != nil {
		t.Fatal(e)
	}
	in, e := contracts.DecodeConfigurationRoleInstaller(bytes.NewReader(b))
	if e != nil || !reflect.DeepEqual(in.InitialHistoryProbe, owner.InitialHistoryProbe) {
		t.Fatal("generated continuation lost protected history capability", e)
	}
	plan, _, e := configurationRoleInstallerPlan(in)
	if e != nil || plan.InitialHistoryProbe == nil || plan.InitialHistoryProbe.Namespace.UID != owner.InitialHistoryProbe.Namespace.UID || plan.InitialHistoryProbe.ServiceAccountUID != owner.InitialHistoryProbe.ServiceAccount.UID || plan.InitialHistoryProbe.Configuration != owner.InitialHistoryProbe.Configuration {
		t.Fatal("runtime reconstructed a different namespace policy", e)
	}
	in.InitialHistoryProbe.ServiceAccount.UID = ""
	if _, _, e = configurationRoleInstallerPlan(in); e == nil {
		t.Fatal("history account name replaced original UID")
	}
}

func TestConfigurationInstallerHistoryOmissionPreservesOriginalJSON(t *testing.T) {
	original, _, _ := configurationRoleInputPair(t)
	b, e := json.Marshal(original)
	if e != nil {
		t.Fatal(e)
	}
	var wire map[string]json.RawMessage
	if json.Unmarshal(b, &wire) != nil {
		t.Fatal("decode")
	}
	if _, ok := wire["initialHistoryProbe"]; ok {
		t.Fatal("legacy projection acquired a history capability")
	}
	in, e := contracts.DecodeConfigurationRoleInstaller(bytes.NewReader(b))
	if e != nil {
		t.Fatal(e)
	}
	again, e := json.Marshal(in)
	if e != nil || !bytes.Equal(b, again) {
		t.Fatal("legacy projection changed through round trip", e)
	}
}
