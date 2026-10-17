package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
)

// The existing synthetic provider/API/SQL fixture runs the actual complete
// projection producer. Read the ConfigMap it created, as the started process
// does; do not construct a second deployment input or invent journal receipts.
// This proves producer/reader compatibility and the launch interleaving only,
// not native admission, provider authorization or deployed startup availability.
func TestOwnerIdentityProviderJournalAcrossOriginalLaunchReceipt(t *testing.T) {
	f := newOwnerProjectionOperationFixture(t)
	out := projectionFinalizeThrough(t, f, 7)
	if out.Status != OwnerProjectionAdvancePending || out.Snapshot.State.OwnerLaunch == nil || out.Snapshot.State.OwnerLaunch.Receipt != nil || f.launches.Load() != 1 {
		t.Fatal("actual original launch did not precede its separate receipt")
	}
	path := "/api/v1/namespaces/" + f.resources.initial.Namespace.Name + "/configmaps/" + out.Snapshot.State.OwnerIdentity.Receipt.Configuration.Name
	f.api.mu.Lock()
	raw, err := json.Marshal(f.api.objects[path])
	f.api.mu.Unlock()
	if err != nil {
		t.Fatal("mounted original configuration encoding", err)
	}
	var config core.ConfigMap
	if json.Unmarshal(raw, &config) != nil {
		t.Fatal("mounted original configuration decoding")
	}
	input, err := contracts.DecodeOwnerDeployment(bytes.NewBufferString(config.Data["deployment.json"]))
	if err != nil || input.Observation == nil || input.Observation.Activation == nil {
		t.Fatal("mounted original activation", err)
	}
	reader := &InstalledOwnerIdentityReader{client: f.root.bridge.source.client, input: input, activation: *input.Observation.Activation}
	t.Run("pending-original-launch", func(t *testing.T) {
		call, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		before := projectionEffectCounts(f)
		_, err := reader.journal(call)
		if !errors.Is(err, cfg.ErrUnavailable) || errors.Is(err, cfg.ErrChanged) {
			t.Fatalf("valid original launch awaiting its receipt must be unavailable, not changed: %v", err)
		}
		if projectionEffectCounts(f) != before {
			t.Fatal("startup reader performed an effect")
		}
	})
	// Continue the actual producer once even if the pending assertion failed:
	// the complete control independently identifies which side is incompatible.
	if err := f.projection.ExecuteLaunch(context.Background()); err != nil {
		t.Fatal("original receipt execution", err)
	}
	complete, err := f.projection.Finalize(context.Background())
	if err != nil || complete.Status != OwnerProjectionAdvanceComplete || complete.Snapshot.State.OwnerLaunch.Receipt == nil {
		t.Fatal("original receipt finalization", err)
	}
	t.Run("acknowledged-original-launch", func(t *testing.T) {
		call, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		before := projectionEffectCounts(f)
		state, err := reader.journal(call)
		if err != nil || !equalJSON(state, complete.Snapshot.State) {
			t.Fatal("actual completed provider journal rejected", err)
		}
		if projectionEffectCounts(f) != before {
			t.Fatal("startup reader performed an effect")
		}
	})
}
