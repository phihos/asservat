package integration

import (
	"asservat.local/asservat/internal/contracts"
	"testing"
	"time"
)

func TestInstalledBrowserCleanupControlsKeepFiniteOriginalLifetimes(t *testing.T) {
	n := time.Date(2026, 11, 5, 12, 0, 0, 123456000, time.UTC)
	cfg := contracts.BrowserSettings{Issuer: "https://id.example.test", ClientID: "console", MaxLifetimeSeconds: 3600}
	p := newInstalledBrowserCleanupRows(cfg, n, "20000000-0000-4000-8000-000000000001")
	if p.login[0].Valid(n) || p.session[0].Valid(n) || !p.login[1].Valid(n) || !p.session[1].Valid(n) {
		t.Fatal("probe mixes expired and live metadata")
	}
	if p.login[1].ExpiresAt.Sub(n) != 4*time.Minute || p.session[1].ExpiresAt.Sub(n) != 3*time.Minute || p.logoutExpires[1].Sub(p.logoutIssued[1]) != 25*time.Hour || !p.logoutExpires[0].Before(n) {
		t.Fatal("probe changed original control/receipt lifetime")
	}
	ids := map[[32]byte]bool{}
	for i := range 2 {
		for _, id := range [][32]byte{p.login[i].ID, p.session[i].ID, p.logoutID[i]} {
			if id == ([32]byte{}) || ids[id] {
				t.Fatal("synthetic ownership IDs collide")
			}
			ids[id] = true
		}
	}
	if len(ids) != 6 || p.session[1].Principal.Issuer != cfg.Issuer || p.session[1].Principal.ClientID != cfg.ClientID {
		t.Fatal("probe escaped current source binding")
	}
}
