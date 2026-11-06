package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

func savedLogsFixture() (artifact.PinnedPod, *core.Pod) {
	pin := artifact.PinnedPod{Namespace: "app", NamespaceUID: "original-namespace", Name: "workload", UID: "original-pod"}
	pod := &core.Pod{ObjectMeta: meta.ObjectMeta{Namespace: pin.Namespace, Name: pin.Name, UID: types.UID(pin.UID)}}
	pod.Spec.Containers = []core.Container{{Name: "main"}}
	pod.Spec.InitContainers = []core.Container{{Name: "init"}}
	pod.Spec.EphemeralContainers = []core.EphemeralContainer{{EphemeralContainerCommon: core.EphemeralContainerCommon{Name: "debug"}}}
	pod.Status.ContainerStatuses = []core.ContainerStatus{{Name: "main", ContainerID: "containerd://main-2", RestartCount: 2, LastTerminationState: core.ContainerState{Terminated: &core.ContainerStateTerminated{ContainerID: "containerd://main-1"}}}}
	pod.Status.InitContainerStatuses = []core.ContainerStatus{{Name: "init", ContainerID: "containerd://init", State: core.ContainerState{Terminated: &core.ContainerStateTerminated{ContainerID: "containerd://init"}}}}
	pod.Status.EphemeralContainerStatuses = []core.ContainerStatus{{Name: "debug", ContainerID: "containerd://debug", RestartCount: 1}}
	return pin, pod
}

func TestSavedLogSnapshotWholePodOriginsAndInstanceChanges(t *testing.T) {
	pin, pod := savedLogsFixture()
	before, err := savedLogSnapshot(pin, pod)
	if err != nil || len(before.Origins()) != 6 || !before.SameInstances(before) {
		t.Fatal("whole-Pod snapshot", err)
	}
	kinds := map[string]int{}
	unknownPrevious := false
	for _, o := range before.Origins() {
		kinds[o.ContainerKind]++
		if o.Stream != "combined" || !o.WellFormed() {
			t.Fatal("invented stream or invalid source", o)
		}
		if o.ContainerKind == "ephemeral" && o.Source == "previous" {
			unknownPrevious = o.RuntimeID == nil && before.Available(o.OriginID)
		}
	}
	if kinds["regular"] != 2 || kinds["init"] != 2 || kinds["ephemeral"] != 2 || !unknownPrevious {
		t.Fatal("origins lost kind or invented previous runtime", kinds)
	}
	for _, change := range []string{"pod", "restart", "current", "previous", "added-container"} {
		after := pod.DeepCopy()
		switch change {
		case "pod":
			after.UID = "replacement"
		case "restart":
			after.Status.ContainerStatuses[0].RestartCount++
		case "current":
			after.Status.ContainerStatuses[0].ContainerID = "replacement"
		case "previous":
			after.Status.ContainerStatuses[0].LastTerminationState.Terminated.ContainerID = "replacement"
		case "added-container":
			after.Spec.Containers = append(after.Spec.Containers, core.Container{Name: "added"})
		}
		got, err := savedLogSnapshot(pin, after)
		if err == nil && before.SameInstances(got) {
			t.Fatal("changed source retained original provenance", change)
		}
	}
	clone := before.Origins()
	*clone[0].RuntimeID = "modified"
	if *before.Origins()[0].RuntimeID == "modified" {
		t.Fatal("origin metadata alias escaped snapshot")
	}
}

func TestSavedLogSnapshotSixtyFourMembersNotPerContainerBudget(t *testing.T) {
	pin, pod := savedLogsFixture()
	pod.Spec.InitContainers, pod.Spec.EphemeralContainers = nil, nil
	pod.Status.InitContainerStatuses, pod.Status.EphemeralContainerStatuses = nil, nil
	pod.Spec.Containers, pod.Status.ContainerStatuses = nil, nil
	for i := 0; i < 64; i++ {
		pod.Spec.Containers = append(pod.Spec.Containers, core.Container{Name: fmt.Sprintf("c-%02d", i)})
	}
	s, err := savedLogSnapshot(pin, pod)
	if err != nil || len(s.Origins()) != artifact.LogMaxOrigins {
		t.Fatal("qualified whole-Pod ceiling", err)
	}
	pod.Spec.Containers = append(pod.Spec.Containers, core.Container{Name: "extra"})
	if _, err := savedLogSnapshot(pin, pod); err == nil {
		t.Fatal("unbounded runtime fanout")
	}
}

func TestSavedLogSnapshotPreservesAcceptedController(t *testing.T) {
	pin, pod := savedLogsFixture()
	pin.ControllerUID = "original-controller"
	controller := true
	pod.OwnerReferences = []meta.OwnerReference{{UID: types.UID(pin.ControllerUID), Controller: &controller}}
	if _, err := savedLogSnapshot(pin, pod); err != nil {
		t.Fatal("exact controller refused", err)
	}
	for _, mode := range []string{"changed", "missing", "duplicate"} {
		other := pod.DeepCopy()
		switch mode {
		case "changed":
			other.OwnerReferences[0].UID = "replacement"
		case "missing":
			other.OwnerReferences = nil
		case "duplicate":
			other.OwnerReferences = append(other.OwnerReferences, other.OwnerReferences[0])
		}
		if _, err := savedLogSnapshot(pin, other); err == nil {
			t.Fatal("accepted controller changed", mode)
		}
	}
}

func TestSavedLogClientTLSExactOptionsLosslessAndBounded(t *testing.T) {
	pin, pod := savedLogsFixture()
	raw := append([]byte("2026-11-05T12:00:00Z \n\xff\x00"), bytes.Repeat([]byte("long"), 600000)...)
	gets, logs := 0, 0
	since := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Error("unexpected mutation", r.Method)
		}
		switch r.URL.Path {
		case "/api/v1/namespaces/app/pods/workload":
			gets++
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(pod)
		case "/api/v1/namespaces/app/pods/workload/log":
			logs++
			q := r.URL.Query()
			if q.Get("container") != "main" || q.Get("previous") != "true" || q.Get("timestamps") != "true" || q.Get("sinceTime") != since.Format(time.RFC3339) || q.Get("stream") != "" || q.Get("follow") != "" || q.Get("limitBytes") != fmt.Sprint(len(raw)) {
				t.Error("changed finite API selection", q)
			}
			_, _ = w.Write(raw)
		default:
			t.Error("unexpected API request", r.URL)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	c, err := NewSavedLogClient(&rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := c.Snapshot(t.Context(), pin)
	if err != nil {
		t.Fatal(err)
	}
	var id uint16
	for _, o := range snapshot.Origins() {
		if o.ContainerName == "main" && o.Source == "previous" {
			id = o.OriginID
		}
	}
	body, err := c.Open(t.Context(), snapshot, id, since, int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(body)
	closeErr := body.Close()
	if err != nil || closeErr != nil || !bytes.Equal(got, raw) || gets != 1 || logs != 1 || len(got) <= 2<<20 {
		t.Fatal("stream lost bytes or used status response ceiling", err, closeErr, gets, logs, len(got))
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := c.Open(ctx, snapshot, id, since, 1); err == nil || logs != 1 {
		t.Fatal("cancelled source performed API call")
	}
	if _, err := NewSavedLogClient(&rest.Config{Host: strings.Replace(server.URL, "https", "http", 1)}); err == nil {
		t.Fatal("plaintext API accepted")
	}
}
