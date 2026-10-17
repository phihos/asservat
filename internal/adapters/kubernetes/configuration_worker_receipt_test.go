package kubernetes

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

// Concrete immutable-object readback only. Original journals, SQL and native
// authority are synthetic and this helper does not stand in for Advance.
func configurationWorkerReceiptFixture(t *testing.T, mode string) (*ConfigurationWorkerInputs, contracts.InitialRuntimeResourceSnapshot, []byte, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	installation, state, _ := configurationWorkerInputStateFixture(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	state.CreatedAt, state.Until = now.Add(-time.Minute), now.Add(29*time.Minute)
	state.WorkerInputs.ClaimedAt, state.WorkerInputs.Until = now.Add(-10*time.Second), now.Add(-5*time.Second)
	originalReceipt := *state.WorkerInputs.Receipt
	state.WorkerInputs.Receipt = nil
	reads, writes := &atomic.Int32{}, &atomic.Int32{}
	var producer *ConfigurationWorkerInputs
	snapshot := contracts.InitialRuntimeResourceSnapshot{State: state, UID: ownerID(15100), ResourceVersion: "71"}
	body := []byte(`{"synthetic":"exact-public-config"}`)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writes.Add(1)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		reads.Add(1)
		if r.URL.Path != "/api/v1/namespaces/control/configmaps/"+producer.resources.names.WorkerInputs {
			t.Error("read escaped original fixed object")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if mode == "missing" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if mode == "unknown" {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = conn.Close()
			return
		}
		object := producer.inputObject(snapshot, body)
		object.UID, object.ResourceVersion = types.UID(originalReceipt.Configuration.UID), originalReceipt.ResourceVersion
		switch mode {
		case "different body":
			object.Data["deployment.json"] = `{"synthetic":"changed"}`
		case "different operation":
			object.Annotations["asservat.io/projection-id"] = ownerID(15101)
		case "replacement after receipt":
			object.UID = types.UID(ownerID(15102))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(object)
	}))
	t.Cleanup(server.Close)
	client, err := NewPermissionClient(&rest.Config{Host: server.URL, BearerToken: "synthetic-observer", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}, permissionCluster, cfg.NamespaceRef{Name: "control", UID: ownerID(15103)}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	producer = &ConfigurationWorkerInputs{resources: &InitialRuntimeResources{initial: contracts.InitialInstaller{InstallationID: installation}, names: runtimeResourceNames(installation), preparer: &InitialPreparer{protection: &configMapProtection{observer: &PermissionClient{now: func() time.Time { return now }}}}},
		roles: &ConfigurationRuntimeRoleRoot{client: client, input: contracts.ConfigurationRuntimeRoles{Namespace: contracts.WorkerObjectReference{Name: "control", UID: ownerID(15103)}}}}
	if mode == "replacement after receipt" || mode == "existing receipt" {
		originalReceipt.ObservedAt = state.WorkerInputs.ClaimedAt.Add(time.Second)
		snapshot.State.WorkerInputs.Receipt = &originalReceipt
	}
	return producer, snapshot, body, reads, writes
}

func TestConfigurationWorkerHistoricalReceiptUsesActualLaterObservationWithoutCreate(t *testing.T) {
	s, original, body, reads, writes := configurationWorkerReceiptFixture(t, "valid")
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := s.createInput(ctx, original, body); err == nil || writes.Load() != 0 {
		t.Fatal("expired original claim admitted another CREATE")
	}
	receipt, err := s.readInput(ctx, original, body)
	if err != nil {
		t.Fatal(err)
	}
	if !receipt.ObservedAt.Equal(s.resources.now()) || !receipt.ObservedAt.After(original.State.WorkerInputs.Until) {
		t.Fatal("historical observation backdated or confused with create authority")
	}
	next := original.State
	claim := *next.WorkerInputs
	claim.Receipt = &receipt
	next.WorkerInputs = &claim
	if !configurationWorkerInputTransition(original.State, next) || !configurationWorkerInputsStateValid(s.resources.initial.InstallationID, next, s.resources.now()) {
		t.Fatal("exact historical acknowledgement rejected by closed state/transition contract")
	}
	late := next
	lateClaim, lateReceipt := *claim.Receipt, claim
	lateClaim.ObservedAt = late.Until
	lateReceipt.Receipt = &lateClaim
	late.WorkerInputs = &lateReceipt
	if configurationWorkerInputsStateValid(s.resources.initial.InstallationID, late, late.Until) {
		t.Fatal("new receipt accepted at or beyond original parent end")
	}
	if !claim.Until.Equal(original.State.WorkerInputs.Until) || claim.OperationID != original.State.WorkerInputs.OperationID || reads.Load() != 1 || writes.Load() != 0 {
		t.Fatal("readback replayed or renewed the original attempt")
	}
}

func TestConfigurationWorkerUnknownOrChangedReadbackCannotAcknowledge(t *testing.T) {
	for _, mode := range []string{"missing", "unknown", "different body", "different operation", "replacement after receipt"} {
		t.Run(mode, func(t *testing.T) {
			s, original, body, reads, writes := configurationWorkerReceiptFixture(t, mode)
			ctx, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			if receipt, err := s.readInput(ctx, original, body); err == nil || receipt != (contracts.ConfigurationWorkerInputReceipt{}) {
				t.Fatal("unknown or changed readback produced a positive receipt")
			}
			if reads.Load() != 1 || writes.Load() != 0 {
				t.Fatal("uncertain read retried or acquired another effect")
			}
		})
	}
}

func TestConfigurationWorkerExistingReceiptRetainsOriginalTimestamp(t *testing.T) {
	s, original, body, _, writes := configurationWorkerReceiptFixture(t, "existing receipt")
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	receipt, err := s.readInput(ctx, original, body)
	if err != nil || receipt != *original.State.WorkerInputs.Receipt || writes.Load() != 0 {
		t.Fatal("passive replay replaced the original positive receipt", err)
	}
}
