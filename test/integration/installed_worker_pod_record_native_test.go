package integration

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/authorization"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// installedWorkerPods records every API-server state of query-worker Pods
// from before the query starts. A joined single-batch worker can exit and be
// retired by the product before the fixture's first poll returns, so a later
// GET cannot observe its admitted limits. The watch is an operator-side
// observation only; it supplies no product input or authority.
type installedWorkerPods struct {
	mu   sync.Mutex
	seen map[types.UID][]core.Pod
}

func installedRecordWorkerPods(t *testing.T, ctx context.Context, api kubernetes.Interface) *installedWorkerPods {
	t.Helper()
	r := &installedWorkerPods{seen: map[types.UID][]core.Pod{}}
	record := func(obj any) {
		if pod, ok := obj.(*core.Pod); ok {
			r.mu.Lock()
			r.seen[pod.UID] = append(r.seen[pod.UID], *pod.DeepCopy())
			r.mu.Unlock()
		}
	}
	factory := informers.NewSharedInformerFactoryWithOptions(api, 0, informers.WithTweakListOptions(func(o *meta.ListOptions) {
		o.LabelSelector = "asservat.io/query-worker"
	}))
	informer := factory.Core().V1().Pods().Informer()
	if _, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{AddFunc: record, UpdateFunc: func(_, obj any) { record(obj) }}); err != nil {
		t.Fatal("query worker Pod recorder", err)
	}
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop); factory.Shutdown() })
	factory.Start(stop)
	synced, end := context.WithTimeout(ctx, 30*time.Second)
	defer end()
	if !cache.WaitForCacheSync(synced.Done(), informer.HasSynced) {
		t.Fatal("query worker Pod recorder did not sync")
	}
	return r
}

// memoryLimit requires every recorded state of the exact bound Pod to carry
// one container with the same memory limit, and returns it.
func (r *installedWorkerPods) memoryLimit(b value.AcquisitionWorkerBinding) (int64, error) {
	r.mu.Lock()
	states := r.seen[types.UID(b.PodUID)]
	r.mu.Unlock()
	if len(states) == 0 {
		return 0, errors.New("bound query worker Pod was never observed")
	}
	var limit int64
	for i, pod := range states {
		if pod.Name != b.Pod || pod.Namespace != b.Namespace || len(pod.Spec.Containers) != 1 {
			return 0, errors.New("observed query worker Pod differs from its binding")
		}
		memory := pod.Spec.Containers[0].Resources.Limits.Memory().Value()
		if i > 0 && memory != limit {
			return 0, errors.New("query worker Pod memory limit changed")
		}
		limit = memory
	}
	return limit, nil
}
