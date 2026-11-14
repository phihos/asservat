package bootstrap

import (
	"context"
	"fmt"
	"os"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/metadata/metadatainformer"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

// Watched resources of the connector's deliveries (ADR-329, ADR-330).
var (
	accessBindingsResource = schema.GroupVersionResource{Group: "asservat.io", Version: "v1alpha1", Resource: "accessbindings"}
	capacityResources      = []schema.GroupVersionResource{{Version: "v1", Resource: "namespaces"}, {Group: "apps", Version: "v1", Resource: "deployments"}, {Group: "apps", Version: "v1", Resource: "statefulsets"}, {Version: "v1", Resource: "pods"}}
)

const (
	// deliverySpacing coalesces bursts: at most one delivery per second.
	deliverySpacing = time.Second
	// deliveryRetry retries a failed delivery; a success waits for a change.
	deliveryRetry = 5 * time.Second
)

// resourceWatch is a metadata informer set whose every event signals
// trigger (coalesced). It holds the watched objects' metadata.
type resourceWatch struct {
	trigger   chan struct{}
	informers []cache.SharedIndexInformer
}

func startResourceWatch(ctx context.Context, config *rest.Config, resources []schema.GroupVersionResource) (*resourceWatch, error) {
	client, err := metadata.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	factory := metadatainformer.NewSharedInformerFactory(client, 0)
	w := &resourceWatch{trigger: make(chan struct{}, 1)}
	signal := func() {
		select {
		case w.trigger <- struct{}{}:
		default:
		}
	}
	handler := cache.ResourceEventHandlerFuncs{AddFunc: func(any) { signal() }, UpdateFunc: func(any, any) { signal() }, DeleteFunc: func(any) { signal() }}
	for _, r := range resources {
		informer := factory.ForResource(r).Informer()
		if _, err = informer.AddEventHandler(handler); err != nil {
			return nil, err
		}
		w.informers = append(w.informers, informer)
	}
	factory.Start(ctx.Done())
	return w, nil
}

// synced waits for the initial LISTs.
func (w *resourceWatch) synced(ctx context.Context) bool {
	var s []cache.InformerSynced
	for _, i := range w.informers {
		s = append(s, i.HasSynced)
	}
	return cache.WaitForCacheSync(ctx.Done(), s...)
}

func (w *resourceWatch) items(i int) []*metav1.PartialObjectMetadata {
	var out []*metav1.PartialObjectMetadata
	for _, o := range w.informers[i].GetStore().List() {
		if m, ok := o.(*metav1.PartialObjectMetadata); ok {
			out = append(out, m)
		}
	}
	return out
}

// deliverOnChange sends a delivery when the watched state changed, at most
// once per deliverySpacing: build returns the current delivery's digest and
// its send. Every conversation carries the hub's stored digest, so the
// first send after the process starts (or after a failure) only compares
// when nothing changed meanwhile. A failed send is retried after
// deliveryRetry; nothing is resent periodically.
func deliverOnChange(ctx context.Context, enrolled <-chan struct{}, trigger <-chan struct{}, name string, build func(context.Context) (string, func(context.Context) error, error)) {
	select {
	case <-ctx.Done():
		return
	case <-enrolled:
	}
	last, outcome, pending := "", "ok", true
	var sent time.Time
	for {
		var retry <-chan time.Time
		if pending {
			if wait := deliverySpacing - time.Since(sent); wait > 0 && !sleepContext(ctx, wait) {
				return
			}
			digest, send, err := build(ctx)
			if err == nil && digest != last {
				sent, err = time.Now(), send(ctx)
				if err == nil {
					last = digest
				} else {
					last = ""
				}
			}
			pending = err != nil
			if pending {
				retry = time.After(deliveryRetry)
			}
			if cause := regionalOutcome(err); cause != outcome && ctx.Err() == nil {
				outcome = cause
				fmt.Fprintln(os.Stderr, "connector "+name+" delivery: "+cause)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-trigger:
			pending = true
		case <-retry:
			pending = true
		}
	}
}

// staticAccessBindings and staticCapacity answer a conversation with the
// delivery built before it.
type staticAccessBindings contracts.AccessBindingDelivery

func (s staticAccessBindings) AccessBindingDelivery(context.Context) (contracts.AccessBindingDelivery, error) {
	return contracts.AccessBindingDelivery(s), nil
}

type staticCapacity contracts.CapacityDelivery

func (s staticCapacity) CapacityDelivery(context.Context, []string) (contracts.CapacityDelivery, error) {
	return contracts.CapacityDelivery(s), nil
}

// runDeliveries watches this cluster's AccessBindings (and, with capacity
// keys, its capacity metadata) and delivers each on change (ADR-329/330).
func (r *Regional) runDeliveries(ctx context.Context, enrolled <-chan struct{}) {
	var joins []func()
	if r.bindings != nil {
		bindings, err := startResourceWatch(ctx, r.watchConfig, []schema.GroupVersionResource{accessBindingsResource})
		if err != nil {
			fmt.Fprintln(os.Stderr, "connector access binding watch unavailable")
		} else {
			joins = append(joins, goJoined(func() {
				if !bindings.synced(ctx) {
					return
				}
				deliverOnChange(ctx, enrolled, bindings.trigger, "access binding", func(ctx context.Context) (string, func(context.Context) error, error) {
					d, err := r.bindings.AccessBindingDelivery(ctx)
					return d.Digest(), func(ctx context.Context) error {
						return r.lifecycle.DeliverAccessBindings(ctx, staticAccessBindings(d))
					}, err
				})
			}))
		}
	}
	if len(r.capacityKeys) != 0 {
		capacity, err := startResourceWatch(ctx, r.watchConfig, capacityResources)
		if err != nil {
			fmt.Fprintln(os.Stderr, "connector capacity watch unavailable")
		} else {
			joins = append(joins, goJoined(func() {
				if !capacity.synced(ctx) {
					return
				}
				deliverOnChange(ctx, enrolled, capacity.trigger, "capacity", func(context.Context) (string, func(context.Context) error, error) {
					d, err := kube.CapacityDeliveryFromCache(r.capacityKeys, capacity.items(0), capacity.items(1), capacity.items(2), capacity.items(3))
					return d.Digest(), func(ctx context.Context) error {
						return r.lifecycle.DeliverCapacity(ctx, staticCapacity(d), r.capacityKeys)
					}, err
				})
			}))
		}
	}
	<-ctx.Done()
	for _, join := range joins {
		join()
	}
}
