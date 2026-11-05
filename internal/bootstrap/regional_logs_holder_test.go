package bootstrap

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

func logsHolderExpectation(t *testing.T) (artifact.ContextExpectation, artifact.PinnedPod) {
	t.Helper()
	_, _, reader, profile, _, now := profileHolderFixture(t)
	e := profileWriterExpectation(t, profile, now)
	e.Profile = nil
	e.NativeType, e.DataClass = artifact.LogsArtifact, "raw"
	e.TriggeredAt = now.Add(-time.Second)
	e.Logs = &artifact.LogCapture{ActionID: e.ActionID, BeforeMillis: 10000, Streams: "combined", TimeoutMillis: 10000, MaxNativeBytes: e.Registration.NativeLimit}
	pin := reader.plan.Pin
	pin.NodeName = ""
	if err := e.Validate(); err != nil {
		t.Fatal("logs holder fixture", err)
	}
	return e, pin
}
func logsHolderClient(t *testing.T, handler http.Handler) *kube.SavedLogClient {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	client, err := kube.NewSavedLogClient(&rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}})
	if err != nil {
		t.Fatal(err)
	}
	return client
}
func waitLogsOutcome(t *testing.T, h *ConnectorRecordings, e artifact.ContextExpectation) evidence.RecordingCollection {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		out, err := h.Collect(argumentCollect(e))
		if err != nil {
			t.Fatal(err)
		}
		if out.State != evidence.RecordingPending {
			return out
		}
		select {
		case <-deadline.C:
			t.Fatal("logs owner did not join")
		case <-tick.C:
		}
	}
}
func TestRegionalLogsOwnerStreamsStoresAndJoinsStop(t *testing.T) {
	for _, mode := range []string{"stored", "stop", "owner-close"} {
		t.Run(mode, func(t *testing.T) {
			e, pin := logsHolderExpectation(t)
			var podGets, logGets, puts atomic.Int32
			entered := make(chan struct{})
			client := logsHolderClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v1/namespaces/app/pods/app-0" {
					podGets.Add(1)
					_ = json.NewEncoder(w).Encode(core.Pod{ObjectMeta: meta.ObjectMeta{Name: pin.Name, Namespace: pin.Namespace, UID: types.UID(pin.UID)}, Spec: core.PodSpec{Containers: []core.Container{{Name: "main"}}}, Status: core.PodStatus{ContainerStatuses: []core.ContainerStatus{{Name: "main", ContainerID: "containerd://original"}}}})
					return
				}
				logGets.Add(1)
				_, _ = w.Write([]byte("synthetic original\n"))
				w.(http.Flusher).Flush()
				close(entered)
				if mode != "stored" {
					<-r.Context().Done()
				}
			}))
			prepared := preparedSnapshot(t, e, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { snapshotPUT(t, w, r, puts.Add(1)) }))
			owner, cancelOwner := context.WithCancel(t.Context())
			defer cancelOwner()
			h := NewConnectorRecordings(nil, nil, time.Now, func(string) {})
			h.configureLogs(owner, e.CaptureUID, client, e.CaptureUID, e.CaptureUID)
			t.Cleanup(h.closeLogs)
			call, cancelCall := context.WithTimeout(t.Context(), time.Second)
			p := h.PrepareLogs(prepared, e)
			if _, err := p.StartLogs(call, pin, time.Now().Add(-time.Millisecond), time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			cancelCall() // The acknowledged async effect belongs to the connector owner.
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("logs source never opened")
			}
			if _, err := p.StartLogs(t.Context(), pin, time.Now(), time.Now().Add(time.Second)); err == nil {
				t.Fatal("prepared keys reused")
			}
			if mode == "stop" {
				stop := argumentStop(e)
				call, done := context.WithTimeout(t.Context(), time.Second)
				defer done()
				wrong := stop
				wrong.WriterEpoch = "22222222-2222-4222-8222-222222222222"
				if err := h.CancelRecording(call, wrong); err == nil {
					t.Fatal("replacement writer stopped owner")
				}
				if err := h.CancelRecording(call, stop); err != nil {
					t.Fatal(err)
				}
			} else if mode == "owner-close" {
				h.closeLogs()
			}
			out := waitLogsOutcome(t, h, e)
			if mode == "stored" {
				if out.State != evidence.RecordingStored || !out.Valid(e.Registration) || puts.Load() != 4 || podGets.Load() != 2 || logGets.Load() != 1 {
					t.Fatal("actual streaming writer incomplete", out, puts.Load(), podGets.Load(), logGets.Load())
				}
				call, done := context.WithTimeout(t.Context(), time.Second)
				defer done()
				if err := h.CancelRecording(call, argumentStop(e)); err != nil {
					t.Fatal(err)
				}
				after, _ := h.Collect(argumentCollect(e))
				if after.State != evidence.RecordingStored {
					t.Fatal("stored result replaced by cancellation")
				}
			} else if mode == "stop" {
				if out.State != evidence.RecordingCancelled || out.LogsCancellation == nil || !out.Valid(e.Registration) || puts.Load() != 0 {
					t.Fatal("stop lacks joined typed no-publication proof", out, puts.Load())
				}
				again, _ := h.Collect(argumentCollect(e))
				if *again.LogsCancellation != *out.LogsCancellation {
					t.Fatal("proof renewed")
				}
			} else if out.State != evidence.RecordingFailed || puts.Load() != 0 {
				t.Fatal("shutdown published or invented user Stop", out)
			}
			h.mu.Lock()
			defer h.mu.Unlock()
			if h.storing != 0 || !h.logs[e.CaptureUID].joined {
				t.Fatal("joined owner retained storage slot")
			}
		})
	}
}
func TestRegionalLogsPreStartStopConvertsExistingSlotAtGlobalCeiling(t *testing.T) {
	e, pin := logsHolderExpectation(t)
	var calls atomic.Int32
	client := logsHolderClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	h := NewConnectorRecordings(nil, nil, time.Now, func(string) {})
	h.configureLogs(t.Context(), e.CaptureUID, client, e.CaptureUID, e.CaptureUID)
	call, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := h.CancelRecording(call, argumentStop(e)); err != nil {
		t.Fatal(err)
	}
	if out, _ := h.Collect(argumentCollect(e)); out.State != evidence.RecordingPending {
		t.Fatal("absence invented termination")
	}
	h.mu.Lock()
	for i := 1; i < maxHeldRecordings; i++ {
		h.held[fmt.Sprint(i)] = &heldRecording{expires: e.Registration.WriteUntil.Add(recordingRetain)}
	}
	h.mu.Unlock()
	if _, err := h.PrepareLogs(&objectstore.PreparedArtifact{}, e).StartLogs(call, pin, time.Now().Add(-time.Millisecond), time.Now().Add(time.Second)); err != nil {
		t.Fatal("existing cancellation slot could not settle at ceiling", err)
	}
	out, _ := h.Collect(argumentCollect(e))
	if out.State != evidence.RecordingCancelled || out.LogsCancellation == nil || calls.Load() != 0 {
		t.Fatal("late start escaped existing stop", out, calls.Load())
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.heldCountLocked() != maxHeldRecordings {
		t.Fatal("global count changed during conversion")
	}
}

func TestRegionalLogsUsesOriginalAcceptedStartTimeout(t *testing.T) {
	e, pin := logsHolderExpectation(t)
	var calls atomic.Int32
	client := logsHolderClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	h := NewConnectorRecordings(nil, nil, time.Now, func(string) {})
	h.configureLogs(t.Context(), e.CaptureUID, client, e.CaptureUID, e.CaptureUID)
	defer h.closeLogs()
	call, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	// The original API CAS predates a delayed delivery. Its accepted lifetime
	// is already over even though the parent write reservation remains live.
	if _, err := h.PrepareLogs(&objectstore.PreparedArtifact{}, e).StartLogs(call, pin, time.Now().Add(-11*time.Second), time.Now().Add(time.Second)); err == nil || calls.Load() != 0 || len(h.logs) != 0 {
		t.Fatal("late start renewed original action lifetime", err)
	}
	// A queued start can still acknowledge, but it cannot wait past the same
	// original deadline for the requested after-window or open a source.
	e.Logs.AfterMillis = 1000
	e.TriggeredAt = time.Now().UTC().Truncate(time.Microsecond)
	if _, err := h.PrepareLogs(&objectstore.PreparedArtifact{}, e).StartLogs(call, pin, time.Now().Add(-9500*time.Millisecond), time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	out := waitLogsOutcome(t, h, e)
	if out.State != evidence.RecordingFailed || calls.Load() != 0 {
		t.Fatal("requested window escaped accepted timeout", out)
	}
}

func TestRegionalLogsReconnectAcceptsFreshCaptureAndPreservesJoinedOutcome(t *testing.T) {
	e, pin := logsHolderExpectation(t)
	entered := make(chan struct{})
	var logGets, puts atomic.Int32
	client := logsHolderClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/namespaces/app/pods/app-0" {
			_ = json.NewEncoder(w).Encode(core.Pod{ObjectMeta: meta.ObjectMeta{Name: pin.Name, Namespace: pin.Namespace, UID: types.UID(pin.UID)}, Spec: core.PodSpec{Containers: []core.Container{{Name: "main"}}}, Status: core.PodStatus{ContainerStatuses: []core.ContainerStatus{{Name: "main", ContainerID: "containerd://original"}}}})
			return
		}
		first := logGets.Add(1) == 1
		_, _ = w.Write([]byte("synthetic original\n"))
		w.(http.Flusher).Flush()
		if first {
			close(entered)
			<-r.Context().Done()
		}
	}))
	h := NewConnectorRecordings(nil, nil, time.Now, func(string) {})
	owner, cancel := context.WithCancel(t.Context())
	defer cancel()
	h.configureLogs(owner, e.CaptureUID, client, e.CaptureUID, e.CaptureUID)
	t.Cleanup(h.closeLogs)
	prepared := preparedSnapshot(t, e, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { snapshotPUT(t, w, r, puts.Add(1)) }))
	if _, err := h.PrepareLogs(prepared, e).StartLogs(t.Context(), pin, time.Now(), time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("first owner did not open source")
	}
	h.closeLogs()
	old := waitLogsOutcome(t, h, e)
	if old.State != evidence.RecordingFailed || puts.Load() != 0 {
		t.Fatal("closed owner published or lost failure", old, puts.Load())
	}
	fresh, _ := logsHolderExpectation(t)
	fresh.CaptureUID = "20000000-0000-4000-8000-000000000001"
	fresh.Registration.Location.AttemptID = "20000000-0000-4000-8000-000000000002"
	fresh.Registration.Location.ArtifactID = "20000000-0000-4000-8000-000000000003"
	if err := fresh.Validate(); err != nil {
		t.Fatal(err)
	}
	nextOwner, stop := context.WithCancel(t.Context())
	defer stop()
	h.configureLogs(nextOwner, e.CaptureUID, client, e.CaptureUID, "20000000-0000-4000-8000-000000000004")
	next := preparedSnapshot(t, fresh, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { snapshotPUT(t, w, r, puts.Add(1)) }))
	if _, err := h.PrepareLogs(next, fresh).StartLogs(t.Context(), pin, time.Now(), time.Now().Add(time.Second)); err != nil {
		t.Fatal("reconnected owner refused fresh capture", err)
	}
	if got := waitLogsOutcome(t, h, fresh); got.State != evidence.RecordingStored || !got.Valid(fresh.Registration) || puts.Load() != 4 || logGets.Load() != 2 {
		t.Fatal("fresh owner did not store exactly once", got, puts.Load(), logGets.Load())
	}
	if got := waitLogsOutcome(t, h, e); got.State != old.State || got.Failure != old.Failure {
		t.Fatal("reconnect replaced original terminal outcome", got)
	}
}
