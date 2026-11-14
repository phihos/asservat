package kubernetes

import (
	"bytes"
	"encoding/json"
	"sync/atomic"
	"testing"

	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
)

type ownerIdentityComposedFixture struct {
	*ownerIdentityProducerFixture
	lose                                                  atomic.Int32 // 1 credentials CREATE, 2 configuration CREATE, 3 launch PUT.
	credentialCreates, configurationCreates, launchWrites atomic.Int32
}

func (f *ownerIdentityComposedFixture) resourceState(t *testing.T) contracts.InitialRuntimeResourceState {
	t.Helper()
	f.api.mu.Lock()
	raw, _ := json.Marshal(f.api.objects[f.resources.path()])
	f.api.mu.Unlock()
	var object core.Secret
	if json.Unmarshal(raw, &object) != nil {
		t.Fatal("resource wire")
	}
	defer clearRuntimeProjection(object.Data)
	state, e := contracts.DecodeInitialRuntimeResourceState(bytes.NewReader(object.Data["state.json"]))
	if e != nil {
		t.Fatal("resource state", e)
	}
	return state
}
