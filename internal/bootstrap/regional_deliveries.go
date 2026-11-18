package bootstrap

import (
	"context"
	"os"
	"time"

	app "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/configuration"
)

const (
	deliverySpacing = time.Second     // Coalesce changes before the next complete LIST.
	deliveryRetry   = 5 * time.Second // Retry failed reads or conversations only.
)

type regionalBindingSource interface {
	AccessBindingDelivery(context.Context) (contracts.AccessBindingDelivery, error)
	WatchConfiguration(context.Context, string, string) (app.SettingsWatch, error)
}

type regionalBindingHub interface {
	bindingRevision(context.Context) (string, error)
	deliverAccessBindings(context.Context, string, contracts.AccessBindingDelivery) (string, error)
}

func (r *Regional) runDeliveries(ctx context.Context, resync <-chan struct{}) {
	deliverRegionalBindings(ctx, resync, r.bindings, r.lifecycle)
}

func deliverRegionalBindings(ctx context.Context, resync <-chan struct{}, source regionalBindingSource, hub regionalBindingHub) {
	report := eventLog(os.Stderr, "connector access binding delivery")
	var revision string
	for ctx.Err() == nil {
		var err error
		if revision == "" {
			revision, err = hub.bindingRevision(ctx)
			if err != nil || revision == "" {
				revision = ""
				if err == nil {
					err = value.ErrUnavailable
				}
				report(regionalOutcome(err))
				waitForDeliveryRetry(ctx, resync)
				continue
			}
		}
		var lost bool
		revision, lost, err = followRegionalBindings(ctx, resync, source, hub, revision)
		if ctx.Err() != nil {
			return
		}
		if err == nil { // A reconnect starts with the current hub revision.
			revision = ""
			continue
		}
		report(regionalOutcome(err))
		if !lost { // A failed transfer says nothing about the source.
			revision = ""
			waitForDeliveryRetry(ctx, resync)
			continue
		}

		// A failed LIST or lost watch belongs to the same predecessor as the
		// observation. Never withdraw a newer successful report on its behalf.
		for ctx.Err() == nil {
			ack, err := hub.deliverAccessBindings(ctx, revision, contracts.AccessBindingDelivery{Unavailable: true})
			if err == nil {
				revision = ack
				waitForDeliveryRetry(ctx, resync)
				break
			}
			current, err := hub.bindingRevision(ctx)
			if err == nil && current != "" && current != revision {
				revision = current
				break // Reread Kubernetes before using the new predecessor.
			}
			waitForDeliveryRetry(ctx, resync)
		}
	}
}

func waitForDeliveryRetry(ctx context.Context, resync <-chan struct{}) {
	select {
	case <-ctx.Done():
	case <-resync:
	case <-time.After(deliveryRetry):
	}
}

// Each successful transfer returns the predecessor for the next observation.
// The two watches share that observation: losing either invalidates it even
// while the next LIST or hub transfer is blocked.
func followRegionalBindings(ctx context.Context, resync <-chan struct{}, source regionalBindingSource, hub regionalBindingHub, revision string) (string, bool, error) {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	d, err := source.AccessBindingDelivery(ctx)
	if err != nil {
		return revision, true, err
	}
	local, err := source.WatchConfiguration(ctx, "accessbindings", d.ResourceVersion)
	if err != nil {
		return revision, true, err
	}
	cluster, err := source.WatchConfiguration(ctx, "clusteraccessbindings", d.ClusterResourceVersion)
	if err != nil {
		return revision, true, err
	}
	go func() {
		select {
		case <-ctx.Done():
		case <-local.Lost:
			cancel(value.ErrChanged)
		case <-cluster.Lost:
			cancel(value.ErrChanged)
		}
	}()
	lost := func() bool {
		select {
		case <-local.Lost:
			return true
		case <-cluster.Lost:
			return true
		default:
			return false
		}
	}
	for {
		if lost() {
			return revision, true, value.ErrChanged
		}
		ack, err := hub.deliverAccessBindings(ctx, revision, d)
		if err != nil {
			// A watch can also interrupt this transfer. Its outcome is unknown.
			return revision, lost(), err
		}
		revision = ack
		var next <-chan time.Time
	waitForChange:
		for {
			select {
			case <-ctx.Done():
				return revision, true, context.Cause(ctx)
			case <-resync:
				return revision, false, nil
			case <-local.Changed:
			case <-cluster.Changed:
			case <-next:
				break waitForChange
			}
			if next == nil {
				next = time.After(deliverySpacing)
			}
		}
		d, err = source.AccessBindingDelivery(ctx)
		if err != nil {
			return revision, true, err
		}
	}
}
