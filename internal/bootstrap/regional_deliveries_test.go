package bootstrap

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	app "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/contracts"
)

type regionalTestWatch struct{ changed, lost chan struct{} }

type regionalDeliveryFixture struct {
	sync.Mutex
	current     contracts.AccessBindingDelivery
	resync      chan struct{}
	watches     map[string]regionalTestWatch
	denied      string
	block, fail bool
	reads       int
	sent        []contracts.AccessBindingDelivery
}

func (f *regionalDeliveryFixture) AccessBindingDelivery(ctx context.Context) (contracts.AccessBindingDelivery, error) {
	f.Lock()
	f.reads++
	block, current := f.block, f.current
	f.Unlock()
	if block {
		<-ctx.Done()
		return contracts.AccessBindingDelivery{}, ctx.Err()
	}
	return current, nil
}

func (f *regionalDeliveryFixture) WatchConfiguration(ctx context.Context, resource, rv string) (app.SettingsWatch, error) {
	f.Lock()
	defer f.Unlock()
	expected := map[string]string{"accessbindings": f.current.ResourceVersion, "clusteraccessbindings": f.current.ClusterResourceVersion}
	if expected[resource] != rv || rv == "" {
		panic("watch opened without matching LIST cursor")
	}
	if f.denied == resource {
		return app.SettingsWatch{}, errors.New("watch denied")
	}
	w := regionalTestWatch{make(chan struct{}, 1), make(chan struct{})}
	f.watches[resource] = w
	return app.SettingsWatch{Changed: w.changed, Lost: w.lost}, nil
}

func startRegionalDeliveryFixture(t *testing.T) *regionalDeliveryFixture {
	t.Helper()
	f := &regionalDeliveryFixture{resync: make(chan struct{}, 1), watches: make(map[string]regionalTestWatch), current: contracts.AccessBindingDelivery{ResourceVersion: "local-1", ClusterResourceVersion: "cluster-1", Items: []contracts.DeliveredAccessBinding{{Name: "original"}}}}
	go deliverRegionalBindings(t.Context(), f.resync, f, func(_ context.Context, d contracts.AccessBindingDelivery) error {
		f.Lock()
		defer f.Unlock()
		f.sent = append(f.sent, d)
		if f.fail {
			return errors.New("hub unavailable")
		}
		return nil
	})
	synctest.Wait()
	f.Lock()
	t.Cleanup(f.Unlock)
	if len(f.sent) != 1 || f.sent[0].Unavailable || len(f.watches) != 2 {
		t.Fatal("initial observation", f.sent, f.watches)
	}
	return f
}

func (f *regionalDeliveryFixture) advance(d time.Duration) {
	f.Unlock()
	synctest.Wait()
	time.Sleep(d)
	synctest.Wait()
	f.Lock()
}

func TestRegionalDeliveryComparesChangesAndResyncsWithHub(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := startRegionalDeliveryFixture(t)
		f.advance(time.Hour)
		if f.reads != 1 || len(f.sent) != 1 {
			t.Fatal("idle traffic", f.reads, f.sent)
		}
		f.watches["accessbindings"].changed <- struct{}{}
		f.watches["clusteraccessbindings"].changed <- struct{}{}
		f.advance(deliverySpacing)
		if f.reads != 2 || len(f.sent) != 1 {
			t.Fatal("unchanged burst", f.reads, f.sent)
		}
		f.resync <- struct{}{}
		f.advance(deliverySpacing)
		if f.reads != 3 || len(f.sent) != 2 {
			t.Fatal("hub digest not compared", f.reads, f.sent)
		}
		f.current.Items = []contracts.DeliveredAccessBinding{{Name: "changed"}}
		f.fail = true
		f.watches["accessbindings"].changed <- struct{}{}
		f.advance(deliverySpacing)
		if f.reads != 4 || len(f.sent) != 3 {
			t.Fatal("change not sent", f.reads, f.sent)
		}
		f.fail = false
		f.current.Items = []contracts.DeliveredAccessBinding{{Name: "latest"}}
		f.advance(deliveryRetry)
		if f.reads != 5 || len(f.sent) != 4 || f.sent[3].Items[0].Name != "latest" {
			t.Fatal("retry did not use new LIST", f.reads, f.sent)
		}
	})
}

func TestRegionalDeliveryWithdrawsBeforeRelistingAfterWatchLoss(t *testing.T) {
	for _, lost := range []string{"clusteraccessbindings", "accessbindings"} {
		t.Run(lost, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := startRegionalDeliveryFixture(t)
				f.block = true
				f.watches[lost].changed <- struct{}{}
				f.advance(deliverySpacing)
				if f.reads != 2 {
					t.Fatal("blocked refresh did not start", f.reads)
				}
				f.fail = true
				close(f.watches[lost].lost)
				f.advance(0)
				if f.reads != 2 || len(f.sent) != 2 || !f.sent[1].Unavailable {
					t.Fatal("loss hidden by blocked refresh", f.reads, f.sent)
				}
				f.advance(deliveryRetry)
				if f.reads != 2 || len(f.sent) != 3 || !f.sent[2].Unavailable {
					t.Fatal("relisted before withdrawn observation reached hub", f.reads, f.sent)
				}
				f.fail = false
				f.resync <- struct{}{}
				f.advance(0)
				if len(f.sent) != 4 || !f.sent[3].Unavailable {
					t.Fatal("reconnected hub missed withdrawal", f.sent)
				}
				f.block = false
				f.denied = lost
				f.advance(deliveryRetry)
				if f.reads != 3 || len(f.sent) != 4 {
					t.Fatal("denied watch restored snapshot", f.reads, f.sent)
				}
				f.denied = ""
				f.current.ResourceVersion, f.current.ClusterResourceVersion = "local-2", "cluster-2"
				f.advance(deliveryRetry)
				if f.reads != 4 || len(f.sent) != 5 || f.sent[4].Unavailable || f.sent[4].ResourceVersion != "local-2" {
					t.Fatal("history restoration", f.reads, f.sent)
				}
			})
		})
	}
}
