package kubernetes

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

// ADR-187: a fresh reader after the guard bridge recomputes the bridge's guard
// from the original input and journal receipts. Journal bytes only select the
// candidate, and only the exact bridge phases are admitted.
func TestBridgedHandoverSelectsComputedBridgeGuard(t *testing.T) {
	f, preparer, original := handoverConflictFixture(t)
	effects := rootPinEffects(t, preparer, original)
	resources, err := NewInstalledOwnerRuntimeResources(context.Background(), preparer, effects, [][]byte{ownerConfigurationTestRoot(t, time.Now())})
	if err != nil {
		t.Fatal(err)
	}
	defer resources.Close()
	now := time.Now().UTC().Truncate(time.Microsecond)
	state := contracts.InitialRuntimeResourceState{Format: contracts.InitialRuntimeResourcesFormat, BindingDigest: resources.binding, SetupID: ownerID(8800), WorkerLayout: contracts.HubWorkerInstalledLayout, OwnerLayout: contracts.OwnerInstalledLayout, CreatedAt: now, Until: now.Add(30 * time.Minute), Objects: []contracts.InitialRuntimeResourceClaim{}}
	for i, item := range initialRuntimeResourceItems {
		object, e := resources.object(state, i)
		if e != nil {
			t.Fatal(e)
		}
		state.Objects = append(state.Objects, contracts.InitialRuntimeResourceClaim{Item: item, OperationID: ownerID(8810 + i), TemplateDigest: preparationDigest(object.object), ClaimedAt: now, Until: now.Add(5 * time.Second), Receipt: &contracts.InitialRuntimeResourceReceipt{UID: ownerID(8850 + i), ResourceVersion: "1", Generation: 1}})
	}
	inventory, err := resources.inventory(state)
	if err != nil {
		t.Fatal(err)
	}
	c := resources.initial
	_, want, err := initialRuntimeBridgeGuards(preparer, c, inventory.BridgeAdministration)
	if err != nil {
		t.Fatal(err)
	}
	policyPath := "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/" + c.WorkloadGuard.Name
	f.mu.Lock()
	policy := f.objects[policyPath]
	f.mu.Unlock()
	if policy == nil {
		t.Fatal("fixture has no workload guard policy")
	}
	setPolicy := func(generation int64, uid string) {
		f.mu.Lock()
		defer f.mu.Unlock()
		m := f.objects[policyPath]["metadata"].(map[string]any)
		m["generation"], m["uid"] = generation, uid
	}
	base := c.WorkloadGuard.PolicyGeneration
	// Before the bridge nothing is selected and the journal is not needed.
	if g, phase, e := preparer.bridgedFinal(context.Background(), false); e != nil || g != nil || phase != 0 {
		t.Fatal("pre-bridge reader selected a bridge guard", phase, e)
	}
	raw, _ := json.Marshal(state)
	name := "asservat-runtime-resources-" + strings.ReplaceAll(c.InstallationID, "-", "")
	f.mu.Lock()
	f.objects["/api/v1/namespaces/"+c.Namespace.Name+"/secrets/"+name] = map[string]any{"apiVersion": "v1", "kind": "Secret", "metadata": map[string]any{"name": name, "namespace": c.Namespace.Name, "uid": ownerID(8899), "resourceVersion": "1"}, "type": "Opaque", "data": map[string]any{"state.json": base64.StdEncoding.EncodeToString(raw)}}
	f.mu.Unlock()
	for _, tc := range []struct {
		name       string
		generation int64
		uid        string
		probe      bool
		phase      int
	}{
		{"retained", base + 2, c.WorkloadGuard.PolicyUID, false, 2},
		{"probe-for-producer", base + 1, c.WorkloadGuard.PolicyUID, true, 1},
		{"probe-for-passive", base + 1, c.WorkloadGuard.PolicyUID, false, -1},
		{"beyond-bridge", base + 3, c.WorkloadGuard.PolicyUID, true, -1},
		{"replaced-policy", base + 2, ownerID(8898), false, -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setPolicy(tc.generation, tc.uid)
			g, phase, e := preparer.bridgedFinal(context.Background(), tc.probe)
			if tc.phase < 0 {
				if e == nil {
					t.Fatal("bridge reader admitted an unknown guard", phase)
				}
				return
			}
			if e != nil || phase != tc.phase || g == nil || g.pin != want[tc.phase].pin || !equalJSON(g.policy, want[tc.phase].policy) {
				t.Fatal("bridge reader did not select the computed guard", phase, e)
			}
		})
	}
}
