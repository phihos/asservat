package kubernetes

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// Adds explicit synthetic late projection receipts to the complete worker2
// loopback fixture. It never creates real setup/SQL authority or a launched Pod.
func newWorkerProjectionOperationFixture(t *testing.T) *configurationProviderRuntimeFixture {
	t.Helper()
	f := newConfigurationProviderRuntimeFixture(t)
	base := "/api/v1/namespaces/" + f.input.Namespace.Name + "/secrets/"
	f.mu.Lock()
	defer f.mu.Unlock()
	journal := f.objects[base+f.input.Activation.Resources.Name].(*core.Secret)
	var state contracts.InitialRuntimeResourceState
	if err := json.Unmarshal(journal.Data["state.json"], &state); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	setup := contracts.CapacityRootSetupReceipt{Format: contracts.CapacityRootSetupFormat, OperationID: ownerID(19000), InstallationID: f.input.InstallationID, InitialClaimID: ownerID(19001), PermissionRootID: ownerID(19002), RoleRootUID: ownerID(19003), RoleSetupID: ownerID(19004), InputDigest: strings.Repeat("a", 64), DatabaseOID: 42, PostmasterAt: now.Add(-time.Hour), ClaimedAt: now, Until: now.Add(5 * time.Second)}
	state.CapacityProjection = &contracts.CapacityRuntimeProjectionClaim{OperationID: ownerID(19005), PublicDigest: strings.Repeat("b", 64), Setup: setup, ClaimedAt: now, Until: now.Add(5 * time.Second), Receipt: &contracts.CapacityRuntimeProjectionReceipt{Secret: contracts.WorkerObjectReference{Name: contracts.CapacityRuntimeProjectionName(f.input.InstallationID), UID: ownerID(19006)}, ResourceVersion: "19006", ObservedAt: now}}
	state.CleanupProjection = &contracts.CaptureCleanupProjectionClaim{OperationID: ownerID(19007), PublicDigest: strings.Repeat("c", 64), Setup: setup, ClaimedAt: now, Until: now.Add(5 * time.Second), Receipt: &contracts.CaptureCleanupProjectionReceipt{Secret: contracts.WorkerObjectReference{Name: contracts.HubWorkerCleanupProjectionName(f.input.InstallationID), UID: ownerID(19008)}, ResourceVersion: "19008", ObservedAt: now}}
	if !workerProjectionStateValid(f.input.InstallationID, state, now) {
		t.Fatal("projection state pure preflight")
	}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	journal.Data["state.json"] = raw
	for _, p := range []struct {
		ref         contracts.WorkerObjectReference
		rv          string
		annotations map[string]string
	}{
		{state.CapacityProjection.Receipt.Secret, state.CapacityProjection.Receipt.ResourceVersion, capacityProjectionAnnotations(string(journal.UID), state.SetupID, state.CapacityProjection)},
		{state.CleanupProjection.Receipt.Secret, state.CleanupProjection.Receipt.ResourceVersion, map[string]string{"asservat.io/runtime-resource-uid": string(journal.UID), "asservat.io/runtime-resource-setup": state.SetupID, "asservat.io/projection-id": state.CleanupProjection.OperationID, "asservat.io/projection-public": state.CleanupProjection.PublicDigest}},
	} {
		f.objects[base+p.ref.Name] = &meta.PartialObjectMetadata{TypeMeta: meta.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadata"}, ObjectMeta: meta.ObjectMeta{Name: p.ref.Name, Namespace: f.input.Namespace.Name, UID: types.UID(p.ref.UID), ResourceVersion: p.rv, Annotations: p.annotations}}
	}
	return f
}

func TestWorkerProjectionOperationCountsBothCurrentPassesAndOneDenial(t *testing.T) {
	for _, purpose := range []string{"capacity", "cleanup"} {
		t.Run(purpose, func(t *testing.T) {
			f := newWorkerProjectionOperationFixture(t)
			beforeS, beforeP := f.observer.Load(), f.probe.Load()
			var op *WorkerProjectionOperation
			var err error
			if purpose == "capacity" {
				op, _, err = f.reader.worker.BeginCapacityProjectionOperation(t.Context())
			} else {
				op, _, err = f.reader.worker.BeginCleanupProjectionOperation(t.Context())
			}
			if err != nil {
				t.Fatal(err)
			}
			defer op.Close()
			if err = op.Finish(op.Context()); err != nil {
				t.Fatal(err)
			}
			if s, p := f.observer.Load()-beforeS, f.probe.Load()-beforeP; s != 21 || p != 3 {
				t.Fatalf("actual native request count S=%d P=%d want21/3", s, p)
			}
			if f.denials[0].Load() != 1 || f.denials[1].Load() != 0 || f.denials[2].Load() != 0 {
				t.Fatal("projection borrowed unrelated source denial or repeated final proof")
			}
			if op.Finish(op.Context()) == nil {
				t.Fatal("one-use final repeated")
			}
		})
	}
}

func TestWorkerProjectionOperationFinalRejectsChangedOriginalFacts(t *testing.T) {
	for _, kind := range []string{"journal", "worker", "metadata"} {
		t.Run(kind, func(t *testing.T) {
			f := newWorkerProjectionOperationFixture(t)
			op, claim, err := f.reader.worker.BeginCapacityProjectionOperation(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer op.Close()
			f.mu.Lock()
			switch kind {
			case "journal":
				j := f.objects["/api/v1/namespaces/"+f.input.Namespace.Name+"/secrets/"+f.input.Activation.Resources.Name].(*core.Secret)
				var state contracts.InitialRuntimeResourceState
				if json.Unmarshal(j.Data["state.json"], &state) != nil {
					f.mu.Unlock()
					t.Fatal("journal decode")
				}
				state.CapacityProjection.PublicDigest = strings.Repeat("d", 64)
				j.Data["state.json"], _ = json.Marshal(state)
			case "worker":
				f.objects["/apis/apps/v1/namespaces/"+f.input.Namespace.Name+"/deployments/"+f.input.Activation.Deployment.Name].(*apps.Deployment).Spec.Template.Spec.Containers[0].Image = "foreign"
			case "metadata":
				f.objects["/api/v1/namespaces/"+f.input.Namespace.Name+"/secrets/"+claim.Receipt.Secret.Name].(*meta.PartialObjectMetadata).UID = types.UID(ownerID(19099))
			}
			f.mu.Unlock()
			if op.Finish(context.Background()) == nil {
				t.Fatal("changed original accepted at final")
			}
			if op.Context().Err() == nil || !op.FreshUntil().IsZero() {
				t.Fatal("known changed final left native operation usable")
			}
		})
	}
}
