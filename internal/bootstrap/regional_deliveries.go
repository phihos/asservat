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
	AccessBindingReader
	WatchConfiguration(context.Context, string, string) (app.SettingsWatch, error)
}

type staticAccessBindings contracts.AccessBindingDelivery

func (s staticAccessBindings) AccessBindingDelivery(context.Context) (contracts.AccessBindingDelivery, error) {
	return contracts.AccessBindingDelivery(s), nil
}

func (r *Regional) runDeliveries(ctx context.Context, resync <-chan struct{}) {
	deliverRegionalBindings(ctx, resync, r.bindings, func(ctx context.Context, d contracts.AccessBindingDelivery) error {
		return r.lifecycle.DeliverAccessBindings(ctx, staticAccessBindings(d))
	})
}

func deliverRegionalBindings(ctx context.Context, resync <-chan struct{}, source regionalBindingSource, send func(context.Context, contracts.AccessBindingDelivery) error) {
	last := ""
	report := eventLog(os.Stderr, "connector access binding delivery")
	publish := func(ctx context.Context, d contracts.AccessBindingDelivery, force bool) bool {
		digest := d.Digest()
		if !force && digest == last && last != "" {
			return true
		}
		if err := send(ctx, d); err != nil {
			last = ""
			report(regionalOutcome(err))
			return false
		}
		last = digest
		return true
	}
	for ctx.Err() == nil {
		err := followRegionalBindings(ctx, resync, source, publish)
		if ctx.Err() != nil {
			return
		}
		report(regionalOutcome(err))
		// Withdraw the previous observation before starting any replacement
		// LIST. If the hub cannot acknowledge it, retry the withdrawal first.
		for {
			acknowledged := publish(ctx, contracts.AccessBindingDelivery{Unavailable: true}, false)
			select {
			case <-ctx.Done():
				return
			case <-resync:
				last = ""
				continue
			case <-time.After(deliveryRetry):
			}
			if acknowledged {
				break
			}
		}
	}
}

// Each collection has its own LIST cursor. Both histories must be observable
// before a complete snapshot is sent. Their loss interrupts even a blocked
// refresh, so a stale read cannot restore an old allow or hide a removed deny.
func followRegionalBindings(ctx context.Context, resync <-chan struct{}, source regionalBindingSource, publish func(context.Context, contracts.AccessBindingDelivery, bool) bool) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	d, err := source.AccessBindingDelivery(ctx)
	if err != nil {
		return err
	}
	local, err := source.WatchConfiguration(ctx, "accessbindings", d.ResourceVersion)
	if err != nil {
		return err
	}
	cluster, err := source.WatchConfiguration(ctx, "clusteraccessbindings", d.ClusterResourceVersion)
	if err != nil {
		return err
	}

	// Loss interrupts both an in-flight LIST and an in-flight hub conversation.
	go func() {
		select {
		case <-ctx.Done():
		case <-local.Lost:
			cancel(value.ErrChanged)
		case <-cluster.Lost:
			cancel(value.ErrChanged)
		}
	}()
	force := false
	for {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-local.Lost:
			return value.ErrChanged
		case <-cluster.Lost:
			return value.ErrChanged
		default:
		}
		var next <-chan time.Time
		if !publish(ctx, d, force) {
			next = time.After(deliveryRetry)
		}
		force = false
	waitForChange:
		for {
			select {
			case <-ctx.Done():
				return context.Cause(ctx)
			case <-local.Changed:
			case <-cluster.Changed:
			case <-resync:
				force = true
			case <-next:
				break waitForChange
			}
			if next == nil {
				next = time.After(deliverySpacing)
			}
		}
		if d, err = source.AccessBindingDelivery(ctx); err != nil {
			return err
		}
	}
}
