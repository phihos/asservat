package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"strings"
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
	current           contracts.AccessBindingDelivery
	resync            chan struct{}
	watches           map[string]regionalTestWatch
	denied            string
	block, fail       bool
	reads, preflights int
	revision          string
	actual            contracts.AccessBindingDelivery
	order             []string
	prev              []string
	releaseRead       chan error
	preflightError    bool
	sent              []contracts.AccessBindingDelivery
}

func (f *regionalDeliveryFixture) AccessBindingDelivery(ctx context.Context) (contracts.AccessBindingDelivery, error) {
	f.Lock()
	f.reads++
	f.order = append(f.order, "list")
	block, release, current := f.block, f.releaseRead, f.current
	f.Unlock()
	if block {
		select {
		case <-ctx.Done():
			return contracts.AccessBindingDelivery{}, ctx.Err()
		case err := <-release:
			return current, err
		}
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

func (f *regionalDeliveryFixture) bindingRevision(context.Context) (string, error) {
	f.Lock()
	defer f.Unlock()
	f.preflights++
	f.order = append(f.order, "revision")
	if f.preflightError {
		return "", errors.New("hub unavailable")
	}
	return f.revision, nil
}
func (f *regionalDeliveryFixture) deliverAccessBindings(_ context.Context, previous string, d contracts.AccessBindingDelivery) (string, error) {
	f.Lock()
	defer f.Unlock()
	f.order = append(f.order, "transfer")
	f.sent = append(f.sent, d)
	f.prev = append(f.prev, previous)
	if f.fail || previous != f.revision {
		return "", errors.New("hub unavailable or conflict")
	}
	f.actual = d
	f.revision = fmt.Sprintf("server-revision-%d", len(f.sent))
	return f.revision, nil
}

func startRegionalDeliveryFixture(t *testing.T) *regionalDeliveryFixture {
	t.Helper()
	f := &regionalDeliveryFixture{revision: "initial-revision", releaseRead: make(chan error, 1), resync: make(chan struct{}, 1), watches: make(map[string]regionalTestWatch), current: contracts.AccessBindingDelivery{ResourceVersion: "local-1", ClusterResourceVersion: "cluster-1", Items: []contracts.DeliveredAccessBinding{{Name: "original"}}}}
	go deliverRegionalBindings(t.Context(), f.resync, f, f)
	synctest.Wait()
	f.Lock()
	t.Cleanup(f.Unlock)
	if len(f.sent) != 1 || f.sent[0].Unavailable || len(f.watches) != 2 || strings.Join(f.order, ",") != "revision,list,transfer" {
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
		firstAcknowledged := f.revision
		f.watches["accessbindings"].changed <- struct{}{}
		f.watches["clusteraccessbindings"].changed <- struct{}{}
		f.advance(deliverySpacing)
		if f.reads != 2 || len(f.sent) != 2 || f.preflights != 1 || f.prev[1] != firstAcknowledged {
			t.Fatal("unchanged burst", f.reads, f.sent)
		}
		f.resync <- struct{}{}
		f.advance(deliverySpacing)
		if f.reads != 3 || len(f.sent) != 3 || f.preflights != 2 {
			t.Fatal("hub digest not compared", f.reads, f.sent)
		}
		f.current.Items = []contracts.DeliveredAccessBinding{{Name: "changed"}}
		f.fail = true
		f.watches["accessbindings"].changed <- struct{}{}
		f.advance(deliverySpacing)
		if f.reads != 4 || len(f.sent) != 4 {
			t.Fatal("change not sent", f.reads, f.sent)
		}
		f.fail = false
		f.current.Items = []contracts.DeliveredAccessBinding{{Name: "latest"}}
		f.advance(deliveryRetry)
		if f.reads != 5 || len(f.sent) != 5 || f.sent[4].Items[0].Name != "latest" {
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
				if f.reads != 2 || f.preflights != 1 || len(f.sent) != 1 {
					t.Fatal("blocked refresh contacted hub", f.reads, f.order)
				}
				token := f.revision
				f.fail = true
				close(f.watches[lost].lost)
				f.advance(0)
				if f.reads != 2 || len(f.sent) != 2 || !f.sent[1].Unavailable {
					t.Fatal("loss hidden by blocked refresh", f.reads, f.sent)
				}
				f.advance(deliveryRetry)
				if f.reads != 2 || len(f.sent) != 3 || !f.sent[2].Unavailable || f.prev[2] != token || f.prev[1] != token {
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
				if f.reads != 3 || len(f.sent) != 5 || !f.sent[4].Unavailable {
					t.Fatal("denied watch restored snapshot", f.reads, f.sent)
				}
				f.denied = ""
				f.current.ResourceVersion, f.current.ClusterResourceVersion = "local-2", "cluster-2"
				f.advance(deliveryRetry)
				if f.reads != 4 || len(f.sent) != 6 || f.sent[5].Unavailable || f.sent[5].ResourceVersion != "local-2" {
					t.Fatal("history restoration", f.reads, f.sent)
				}
			})
		})
	}
}

func TestRegionalDeliveryOlderFailedReadCannotWithdrawNewerSuccess(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := startRegionalDeliveryFixture(t)
		before := f.revision
		f.block = true
		f.watches["accessbindings"].changed <- struct{}{}
		f.advance(deliverySpacing)
		if f.reads != 2 || f.preflights != 1 || len(f.sent) != 1 {
			t.Fatal("blocked LIST contacted the hub", f.order)
		}
		// A concurrent connector committed a newer report before this LIST failed.
		f.current.Items = []contracts.DeliveredAccessBinding{{Name: "newer"}}
		f.actual = f.current
		f.revision = "newer-connector-revision"
		newer := f.revision
		f.block = false
		f.releaseRead <- errors.New("oversized LIST")
		f.advance(0)
		if len(f.sent) != 3 || !f.sent[1].Unavailable || f.prev[1] != before || f.prev[2] != newer ||
			f.actual.Unavailable || f.actual.Items[0].Name != "newer" || f.reads != 3 || f.preflights != 2 {
			t.Fatal("older negative affected newer report", f.order, f.sent, f.prev)
		}
	})
}

func TestRegionalDeliveryUnavailableHubDoesNotWithdrawSource(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := startRegionalDeliveryFixture(t)
		f.preflightError = true
		f.resync <- struct{}{}
		f.advance(0)
		f.advance(deliveryRetry)
		if len(f.sent) != 1 || f.reads != 1 || f.preflights < 3 {
			t.Fatal("hub preflight failure treated as source loss", f.order)
		}
		f.preflightError = false
		f.advance(deliveryRetry)
		if len(f.sent) != 2 || f.sent[1].Unavailable || f.reads != 2 {
			t.Fatal("freshness after reconnect", f.order)
		}
	})
}
