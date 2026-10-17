package kubernetes

import (
	"context"
	"encoding/json"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

func TestInstalledWorkerProjectionReaderOwnsCompleteOriginalInput(t *testing.T) {
	f := newCapacityReaderFixture(t)
	raw, err := json.Marshal(f.reader.input)
	if err != nil {
		t.Fatal(err)
	}
	var input contracts.HubWorkerDeployment
	if json.Unmarshal(raw, &input) != nil {
		t.Fatal("fixture input copy")
	}
	input.Kubernetes.Roots = [][]byte{{1, 2, 3}} // public byte ownership only; no TLS authority comes from this synthetic field
	input.Activation.WorkloadGuard.Administrators = append([]contracts.OwnerDeploymentActor(nil), input.Activation.WorkloadGuard.Administrators...)
	want, _ := json.Marshal(input)
	reader, err := NewInstalledWorkerProjectionReader(f.reader.client, f.reader.guard.probe, input)
	if err != nil {
		t.Fatal(err)
	}
	// Every mutation is caller-side, after construction and before observation.
	// These values are not accepted source changes and cannot rewrite pins.
	input.Activation.Resources.UID = ownerID(2190)
	input.Activation.WorkloadGuard.Administrators[0].Name = "foreign-administrator"
	input.Activation.ConfigurationProbes[0].ConfigMap = "foreign-source"
	input.Kubernetes.Roots[0][0] = 99
	got, _ := json.Marshal(reader.input)
	if string(got) != string(want) {
		t.Error("caller mutation changed the reader's original protected input")
	}
	claim, ready, _, err := reader.ReadCapacity(context.Background())
	if err != nil || !ready || claim.Receipt == nil || claim.Receipt.Secret.UID != f.state.CapacityProjection.Receipt.Secret.UID {
		t.Errorf("caller mutation changed independently observed original receipt: ready=%v err=%v", ready, err)
	}
}
