package kubernetes

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	batch "k8s.io/api/batch/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

// Actual client-go requests and historical identity/spec checks, synthetic GC
// transitions only. No cluster, controller, SQL retirement or collector runs.
func TestWorkerRetirementObservesOneAcknowledgedForegroundDelete(t *testing.T) {
	for _, mode := range []string{"async", "absent", "cancel", "expired", "wrong-uid", "replacement", "foreign-pod", "delete-denied", "pending", "attempt-cap", "retirement-expired"} {
		t.Run(mode, func(t *testing.T) {
			worker, job, pod, _, _ := historicalWorkerFixture(t)
			job.Status = batch.JobStatus{Failed: 1, Conditions: []batch.JobCondition{{Type: batch.JobFailed, Status: core.ConditionTrue, Reason: batch.JobReasonBackoffLimitExceeded}}}
			pod.Status = core.PodStatus{Phase: core.PodFailed, ContainerStatuses: []core.ContainerStatus{{Name: "acquisition", State: core.ContainerState{Terminated: &core.ContainerStateTerminated{ContainerID: "containerd://old", Reason: "Error", FinishedAt: meta.NewTime(time.Now().Add(-time.Minute))}}}}}
			at := time.Now().Add(-time.Minute)
			termination := value.DownloadWorkerTermination{Worker: worker, TerminationDigest: artifact.Digest{1}, ObservedAt: at, FreshUntil: at.Add(5 * time.Second)}
			if !termination.Valid(at) || termination.Valid(time.Now()) {
				t.Fatal("historical termination fixture")
			}
			var ctx context.Context
			var cancel context.CancelFunc
			var gets, lists, deletes atomic.Int32
			var clockJump atomic.Int64
			missing := func(w http.ResponseWriter) {
				w.WriteHeader(404)
				_ = json.NewEncoder(w).Encode(meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Reason: meta.StatusReasonNotFound, Code: 404})
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/jobs/"):
					deletes.Add(1)
					if mode == "retirement-expired" {
						clockJump.Store(int64(6 * time.Second))
					}
					var options meta.DeleteOptions
					if json.NewDecoder(r.Body).Decode(&options) != nil || options.Preconditions == nil || options.Preconditions.UID == nil || string(*options.Preconditions.UID) != worker.Job.UID || options.PropagationPolicy == nil || *options.PropagationPolicy != meta.DeletePropagationForeground {
						t.Error("delete lost original UID/foreground policy")
					}
					if mode == "delete-denied" {
						w.WriteHeader(403)
						return
					}
					if mode == "cancel" {
						cancel()
					}
					_ = json.NewEncoder(w).Encode(meta.Status{Status: "Success"})
				case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/jobs/"):
					n := gets.Add(1)
					if mode == "absent" || n > 1 && mode != "pending" && mode != "attempt-cap" && mode != "replacement" && (mode != "async" || n > 2) {
						missing(w)
						return
					}
					current := job.DeepCopy()
					if mode == "wrong-uid" || mode == "replacement" && n > 1 {
						current.UID = "replacement"
					}
					if n > 1 {
						deleted := meta.Now()
						current.DeletionTimestamp = &deleted
					}
					_ = json.NewEncoder(w).Encode(current)
				case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/pods"):
					n := lists.Add(1)
					var items []core.Pod
					if mode == "foreign-pod" || mode == "async" && n == 1 {
						p := *pod.DeepCopy()
						if mode == "foreign-pod" {
							p.UID = "foreign"
						}
						items = append(items, p)
					}
					_ = json.NewEncoder(w).Encode(core.PodList{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "PodList"}, ListMeta: meta.ListMeta{ResourceVersion: "1"}, Items: items})
				default:
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
					w.WriteHeader(500)
				}
			}))
			defer server.Close()
			client, err := NewPermissionClient(&rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}, worker.Intent.Profile.ClusterID, cfg.NamespaceRef{Name: worker.Intent.Profile.Namespace, UID: worker.Intent.Profile.NamespaceUID}, func() time.Time { return time.Now().Add(time.Duration(clockJump.Load())) })
			if err != nil {
				t.Fatal(err)
			}
			driver := &DownloadWorkerJobs{profile: worker.Intent.Profile, client: client}
			// Anchor the original test interval after TLS/client/schema setup.
			ctx, cancel = context.WithTimeout(t.Context(), 500*time.Millisecond)
			defer cancel()
			if mode == "attempt-cap" {
				cancel()
				ctx, cancel = context.WithTimeout(t.Context(), 3*time.Second)
				defer cancel()
			}
			if mode == "expired" {
				cancel()
			}
			began := time.Now()
			out, err := driver.RetireDownloadWorker(ctx, termination)
			want := mode == "async" || mode == "absent"
			if (err == nil) != want || want && (!out.Valid(time.Now()) || out.Termination != termination) {
				t.Fatal("actual foreground retirement", mode, err, gets.Load(), lists.Load(), deletes.Load())
			}
			if err != nil {
				wantCause := artifact.ErrDownloadUnavailable
				if mode == "wrong-uid" || mode == "replacement" {
					wantCause = artifact.ErrIntegrity
				}
				if !errors.Is(err, wantCause) {
					t.Fatal("retirement diagnostic changed original cause", mode, err)
				}
			}
			if deletes.Load() > 1 || mode == "async" && (deletes.Load() != 1 || gets.Load() < 3 || lists.Load() < 2) {
				t.Fatal("cleanup replayed delete or skipped actual asynchronous proof", gets.Load(), lists.Load(), deletes.Load())
			}
			limit := time.Second
			if mode == "attempt-cap" {
				limit = 2500 * time.Millisecond
				if gets.Load() != 21 || deletes.Load() != 1 {
					t.Fatal("fixed attempt cap not exercised", gets.Load(), deletes.Load())
				}
			}
			if time.Since(began) > limit || gets.Load() > 21 || lists.Load() > 20 {
				t.Fatal("cleanup exceeded original bound/call cap", gets.Load(), lists.Load())
			}
			if (mode == "wrong-uid" || mode == "expired" || mode == "absent") && deletes.Load() != 0 {
				t.Fatal("deleted an unowned/absent object")
			}
		})
	}
}
