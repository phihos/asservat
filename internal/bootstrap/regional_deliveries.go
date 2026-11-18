package bootstrap

import (
	"context"
	"fmt"
	"os"
	"time"

	"asservat.local/asservat/internal/contracts"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/metadata/metadatainformer"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

// Watched resources of the connector's deliveries (ADR-329, ADR-334).
var (
	accessBindingsResource = schema.GroupVersionResource{Group: "asservat.io", Version: "v1alpha1", Resource: "accessbindings"}
)

const (
	// deliverySpacing coalesces bursts: at most one delivery per second.
	deliverySpacing = time.Second
	// deliveryRetry retries a failed delivery; a success waits for a change.
	deliveryRetry = 5 * time.Second
)

// The regional informer coalesces AccessBinding changes into delivery signals.
func watchRegionalBindings(ctx context.Context, config *rest.Config) (cache.SharedIndexInformer, <-chan struct{}, error) {
	client, err := metadata.NewForConfig(config)
	if err != nil {
		return nil, nil, err
	}
	informer := metadatainformer.NewFilteredMetadataInformer(client, accessBindingsResource, "", 0, nil, nil).Informer()
	changes := make(chan struct{}, 1)
	signal := func() {
		select {
		case changes <- struct{}{}:
		default:
		}
	}
	handler := cache.ResourceEventHandlerFuncs{AddFunc: func(any) { signal() }, UpdateFunc: func(any, any) { signal() }, DeleteFunc: func(any) { signal() }}
	if _, err = informer.AddEventHandler(handler); err != nil {
		return nil, nil, err
	}
	go informer.RunWithContext(ctx)
	return informer, changes, nil
}

// deliverOnChange sends a delivery when the watched state changed, at most
// once per deliverySpacing: build returns the current delivery's digest and
// its send. Every conversation carries the hub's stored digest, so the
// first send after an authenticated reconnect only compares digests when
// the hub has retained the delivery. A failed send is retried after
// deliveryRetry; nothing is resent periodically.
func deliverOnChange(ctx context.Context, resync <-chan struct{}, trigger <-chan struct{}, name string, build func(context.Context) (string, func(context.Context) error, error)) {
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
		case <-resync:
			// A new authenticated connection can point to a hub that
			// discarded this registration’s previously accepted delivery.
			last, pending = "", true
		case <-trigger:
			pending = true
		case <-retry:
			pending = true
		}
	}
}

// staticAccessBindings answers a conversation with the
// delivery built before it.
type staticAccessBindings contracts.AccessBindingDelivery

func (s staticAccessBindings) AccessBindingDelivery(context.Context) (contracts.AccessBindingDelivery, error) {
	return contracts.AccessBindingDelivery(s), nil
}

// runDeliveries watches this cluster's AccessBindings and delivers them on
// change (ADR-329/330).
func (r *Regional) runDeliveries(ctx context.Context, resync <-chan struct{}) {
	var joins []func()
	if r.bindings != nil {
		bindings, changes, err := watchRegionalBindings(ctx, r.watchConfig)
		if err != nil {
			fmt.Fprintln(os.Stderr, "connector access binding watch unavailable")
		} else {
			joins = append(joins, goJoined(func() {
				if !cache.WaitForCacheSync(ctx.Done(), bindings.HasSynced) {
					return
				}
				deliverOnChange(ctx, resync, changes, "access binding", func(ctx context.Context) (string, func(context.Context) error, error) {
					d, err := r.bindings.AccessBindingDelivery(ctx)
					return d.Digest(), func(ctx context.Context) error {
						return r.lifecycle.DeliverAccessBindings(ctx, staticAccessBindings(d))
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
