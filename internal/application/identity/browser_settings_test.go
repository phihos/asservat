package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/identity"
)

type settingsFixture struct {
	now                        time.Time
	fail, stale, clockRollback bool
	observed, fenced           int
	ctxErr                     error
}

func (f *settingsFixture) BrowserSettings(context.Context) (value.BrowserSettings, error) {
	s := value.BrowserSettings{RootID: "74000000-0000-4000-8000-000000000001", Epoch: "74000000-0000-4000-8000-000000000002", Issuer: "https://id.invalid", ClientID: "console", Origin: "https://console.invalid", Revision: value.Revision{UID: "settings", Generation: 1, Digest: [32]byte{1}}, MaxLifetimeSeconds: 3600, MaxLogins: 10, MaxSessions: 10, MaxLogoutEvents: 10, ObservedAt: f.now, FreshUntil: f.now.Add(5 * time.Second)}
	if f.stale {
		f.now = f.now.Add(5 * time.Second)
	}
	if f.clockRollback {
		f.now = f.now.Add(-time.Second)
	}
	if f.fail {
		return s, errors.New("synthetic source outage")
	}
	return s, nil
}
func (f *settingsFixture) ObserveBrowserSettings(context.Context, value.BrowserSettings) error {
	f.observed++
	return nil
}
func (f *settingsFixture) FenceBrowserSettings(ctx context.Context, _ time.Time) error {
	f.fenced++
	f.ctxErr = ctx.Err()
	return nil
}
func TestBrowserSettingsObserverFencesFailureAndOriginalClock(t *testing.T) {
	for _, mode := range []string{"valid", "outage", "expired", "clock-rollback"} {
		t.Run(mode, func(t *testing.T) {
			f := &settingsFixture{now: time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC), fail: mode == "outage", stale: mode == "expired", clockRollback: mode == "clock-rollback"}
			o := BrowserSettingsObserver{Source: f, Projection: f, Now: func() time.Time { return f.now }}
			e := o.Reconcile(context.Background())
			if mode == "valid" {
				if e != nil || f.observed != 1 || f.fenced != 0 {
					t.Fatal("valid observation")
				}
			} else if e == nil || f.observed != 0 || f.fenced != 1 || f.ctxErr != nil {
				t.Fatal("failure did not fence")
			}
		})
	}
}
