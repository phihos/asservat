package postgres

import (
	"encoding/json"
	"testing"
	"time"

	liveapp "asservat.local/asservat/internal/application/live"
)

func liveLimitsFixture() LiveWatchLimits {
	return LiveWatchLimits{InstallationSlots: 128, PrincipalSlots: 2, WorkloadSlots: 4, MemoryBytes: 128 << 20, InstallationRate: 8 << 20, InstallationBurst: 16 << 20, PrincipalRate: 128 << 10, PrincipalBurst: 256 << 10, WorkloadRate: 256 << 10, WorkloadBurst: 512 << 10, WatchBurst: 64 << 10, MaxOutputBytes: 16 << 20, MaxRate: 64 << 10, MaxDurationSeconds: 3600, MaxAccounts: 8192, MaxControlRecords: 65536}
}
func TestLiveWatchLimitsRequireAllProtectedBudgets(t *testing.T) {
	p := liveLimitsFixture()
	if !p.Valid() {
		t.Fatal("candidate configured limits")
	}
	for name, edit := range map[string]func(*LiveWatchLimits){
		"disabled": func(p *LiveWatchLimits) { p.InstallationSlots = 0 }, "principal": func(p *LiveWatchLimits) { p.PrincipalSlots = 0 }, "workload": func(p *LiveWatchLimits) { p.WorkloadSlots = 0 }, "memory": func(p *LiveWatchLimits) { p.MemoryBytes-- }, "global-rate": func(p *LiveWatchLimits) { p.InstallationRate = 0 }, "principal-burst": func(p *LiveWatchLimits) { p.PrincipalBurst = (24 << 10) - 1 }, "workload-rate": func(p *LiveWatchLimits) { p.WorkloadRate = 0 }, "single-batch": func(p *LiveWatchLimits) { p.WatchBurst = (24 << 10) - 1 }, "unbounded-duration": func(p *LiveWatchLimits) { p.MaxDurationSeconds = 3601 }, "no-account-bound": func(p *LiveWatchLimits) { p.MaxAccounts = 0 }, "no-history-bound": func(p *LiveWatchLimits) { p.MaxControlRecords = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			q := p
			edit(&q)
			if q.Valid() {
				t.Fatal("missing qualification admitted")
			}
		})
	}
}
func TestLiveWatchLimitsRetainLegitimateLongRefillDebt(t *testing.T) {
	p := liveLimitsFixture()
	p.PrincipalRate = 1
	p.PrincipalBurst = 1 << 30
	if !p.Valid() {
		t.Fatal("an invented refill horizon rejected a valid protected rate/burst")
	}
}
func TestLiveWatchControlKeepsOnlyBoundedDigestsAndOriginalControl(t *testing.T) {
	n := time.Now().UTC().Truncate(time.Microsecond)
	id := "10000000-0000-4000-8000-000000000001"
	c := liveapp.Control{ID: id, OwnerID: id, Fence: id, PrincipalKey: [32]byte{1}, WorkloadKey: [32]byte{2}, RequestDigest: [32]byte{3}, Revision: 1, State: "Active", AcceptedAt: n, ExpiresAt: n.Add(time.Hour), IdleUntil: n.Add(30 * time.Second), OutputLimit: 16 << 20, BytesPerSecond: 64 << 10}
	if !liveControlValid(c) {
		t.Fatal("valid original control")
	}
	b, err := json.Marshal(c)
	if err != nil || len(b) > 4096 {
		t.Fatal("control exceeds private bounded codec", len(b), err)
	}
	decoded, err := decodeLive(b)
	if err != nil || decoded != c {
		t.Fatal("control roundtrip changed original", err)
	}
	for name, edit := range map[string]func(*liveapp.Control){"no-owner": func(c *liveapp.Control) { c.OwnerID = "" }, "no-fence": func(c *liveapp.Control) { c.Fence = "" }, "identity-key": func(c *liveapp.Control) { c.PrincipalKey = [32]byte{} }, "workload-key": func(c *liveapp.Control) { c.WorkloadKey = [32]byte{} }, "query-key": func(c *liveapp.Control) { c.RequestDigest = [32]byte{} }, "long-life": func(c *liveapp.Control) { c.ExpiresAt = c.AcceptedAt.Add(time.Hour + time.Nanosecond) }, "negative-spend": func(c *liveapp.Control) { c.Spent = -1 }, "refilled-output": func(c *liveapp.Control) { c.Spent = c.OutputLimit + 1 }, "no-rate": func(c *liveapp.Control) { c.BytesPerSecond = 0 }} {
		t.Run(name, func(t *testing.T) {
			q := c
			edit(&q)
			if liveControlValid(q) {
				t.Fatal("invalid accounting control")
			}
		})
	}
	for _, state := range []string{"Paused", "Disconnected", "SourceEnded", "Closed", "Expired", "AccessLost", "Exhausted"} {
		q := c
		q.State = state
		if !liveControlValid(q) {
			t.Fatal("closed lifecycle state omitted", state)
		}
	}
	var unexpected liveapp.Control
	if _, err = decodeLive(append(b[:len(b)-1], []byte(`,"source":"must-not-be-stored"}`)...)); err == nil {
		t.Fatal("private codec accepted source/filter detail", unexpected)
	}
}
func TestLiveWatchUsesExistingHubCredentialWithoutTablePrivileges(t *testing.T) {
	if _, ok := PublicRuntimeRoleName("10000000-0000-4000-8000-000000000001", "live-watch"); ok {
		t.Fatal("new credential identity minted")
	}
	grants, ok := publicRuntimeRoleGrants("hub-runtime")
	if !ok {
		t.Fatal("hub role")
	}
	expected := publicRuntimeLiveWatchGrants()
	if len(expected) != 8 {
		t.Fatal("unexpected effect surface")
	}
	for _, want := range expected {
		if want.kind != "function" || want.privilege != "EXECUTE" {
			t.Fatal("live duty exposes table state")
		}
		found := false
		for _, g := range grants {
			if g == want {
				found = true
			}
		}
		if !found {
			t.Fatal("existing hub lacks fixed control function", want.object)
		}
	}
	for _, g := range grants {
		if g.kind == "table" && (g.object == "live_watch_root" || g.object == "live_watch_account" || g.object == "live_watch_control") {
			t.Fatal("broad live table privilege")
		}
	}
}
