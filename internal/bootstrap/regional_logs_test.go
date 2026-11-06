package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	logcodec "asservat.local/asservat/internal/adapters/logs"
	"asservat.local/asservat/internal/domain/artifact"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

func TestSavedLogsCollectionOriginalWindowLosslessAndSourceChange(t *testing.T) {
	for _, mode := range []string{"stable", "changed", "previous-unavailable"} {
		t.Run(mode, func(t *testing.T) {
			pin := artifact.PinnedPod{Namespace: "app", NamespaceUID: "original-ns", Name: "original", UID: "original-pod"}
			anchor := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Second)
			stamp := anchor.Add(-time.Second).Format(time.RFC3339Nano)
			kept := append([]byte(stamp+" \n"), []byte("\xff\x00\n")...)
			kept = append(kept, bytes.Repeat([]byte{'x'}, 10000)...)
			kept = append(kept, '\n')
			body := append([]byte(anchor.Add(time.Hour).Format(time.RFC3339Nano)+" outside\n"), kept...)
			podGets, logGets := 0, 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Error("unexpected mutation")
				}
				if r.URL.Path == "/api/v1/namespaces/app/pods/original" {
					podGets++
					pod := core.Pod{ObjectMeta: meta.ObjectMeta{Name: pin.Name, Namespace: pin.Namespace, UID: types.UID(pin.UID)}, Spec: core.PodSpec{Containers: []core.Container{{Name: "main"}}}, Status: core.PodStatus{ContainerStatuses: []core.ContainerStatus{{Name: "main", ContainerID: "containerd://current", RestartCount: 1, LastTerminationState: core.ContainerState{Terminated: &core.ContainerStateTerminated{ContainerID: "containerd://previous"}}}}}}
					if mode == "changed" && podGets == 2 {
						pod.Status.ContainerStatuses[0].ContainerID = "replacement"
					}
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(pod)
					return
				}
				if r.URL.Path != "/api/v1/namespaces/app/pods/original/log" {
					t.Error("unexpected source", r.URL)
					w.WriteHeader(404)
					return
				}
				logGets++
				if mode == "previous-unavailable" && r.URL.Query().Get("previous") == "true" {
					w.WriteHeader(404)
					return
				}
				_, _ = w.Write(body)
			}))
			defer server.Close()
			client, err := kube.NewSavedLogClient(&rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}})
			if err != nil {
				t.Fatal(err)
			}
			request := artifact.LogCapture{ActionID: "a0123456789abcdef01234567", BeforeMillis: 60000, Streams: "combined", TimeoutMillis: 10000, MaxNativeBytes: 256 << 10}
			var native bytes.Buffer
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			err = captureSavedLogs(ctx, client, pin, request, anchor, &native, time.Now)
			if podGets != 2 || logGets != 2 {
				t.Fatal("collection added reads/retries", podGets, logGets)
			}
			if mode == "changed" {
				if !errors.Is(err, kube.ErrTargetChanged) {
					t.Fatal("source change did not invalidate entire artifact", err)
				}
				if _, walkErr := logcodec.Walk(t.Context(), bytes.NewReader(native.Bytes()), request.MaxNativeBytes, logcodec.Visitor{}); walkErr == nil {
					t.Fatal("changed source emitted a complete native footer")
				}
				return
			}
			if err != nil {
				t.Fatal("finite source acquisition", err)
			}
			var reconstructed [2]bytes.Buffer
			var coverage []artifact.LogCoverage
			footer, err := logcodec.Walk(t.Context(), bytes.NewReader(native.Bytes()), request.MaxNativeBytes, logcodec.Visitor{Fragment: func(f artifact.LogFragment) error {
				b, err := f.Bytes()
				if err == nil {
					_, _ = reconstructed[f.OriginID].Write(b)
				}
				return err
			}, Coverage: func(c artifact.LogCoverage) error { coverage = append(coverage, c); return nil }})
			if err != nil || footer.Origins != 2 || len(coverage) != 2 || !bytes.Equal(reconstructed[0].Bytes(), kept) {
				t.Fatal("lost invalid/empty/long bytes or timestamp filtering", err)
			}
			if mode == "stable" && !bytes.Equal(reconstructed[1].Bytes(), kept) {
				t.Fatal("previous origin lost bytes")
			}
			if mode == "previous-unavailable" && (reconstructed[1].Len() != 0 || coverage[1].FetchOutcome != "unavailable") {
				t.Fatal("missing previous logs became complete empty evidence")
			}
		})
	}
}
