package bootstrap

import (
	"testing"

	"asservat.local/asservat/internal/domain/live"
	"asservat.local/asservat/internal/domain/privacy"
)

func TestPublicLiveLimitsUseOneProtectedRootAndPreserveScopedLowerings(t *testing.T) {
	p := privacy.LiveRead{Root: privacy.LiveRootLimits{Watches: 7, PrincipalWatches: 2, WorkloadWatches: 3, Rate: 3 << 20, Burst: 7 << 20}, Ceilings: []privacy.LiveCeiling{
		{Limits: privacy.LiveLimits{Duration: 60, Output: 24 << 10, Rate: 12 << 10, Rows: 10, Buffer: 32 << 10, RowAge: 5, Replay: 1}},
		{Limits: privacy.LiveLimits{Duration: 120, Output: 2 << 20, Rate: 64 << 10, Rows: 50, Buffer: 128 << 10, RowAge: 10, Replay: 3}},
		{Limits: privacy.LiveLimits{Duration: 30, Output: 4 << 20, Rate: 24 << 10, Rows: 20, Buffer: 1 << 20, RowAge: 30, Replay: 0}},
	}}
	numeric, ceiling := publicLiveLimits(p)
	if !numeric.Valid() || !ceiling.Valid() {
		t.Fatal("valid protected mapping refused", numeric, ceiling)
	}
	if numeric.InstallationSlots != 7 || numeric.PrincipalSlots != 2 || numeric.WorkloadSlots != 3 || numeric.MemoryBytes != 7*live.MaxBufferBytes {
		t.Fatal("root slot/replay reservation changed", numeric)
	}
	for _, budget := range [][2]int64{{numeric.InstallationRate, numeric.InstallationBurst}, {numeric.PrincipalRate, numeric.PrincipalBurst}, {numeric.WorkloadRate, numeric.WorkloadBurst}} {
		if budget != [2]int64{p.Root.Rate, p.Root.Burst} {
			t.Fatal("ancestor account invented another startup budget", budget)
		}
	}
	want := live.Limits{Duration: 120, Output: 4 << 20, Rate: 64 << 10, Rows: 50, Buffer: 1 << 20, RowAge: 30, Replay: 3}
	if ceiling != want || numeric.MaxDurationSeconds != 120 || numeric.MaxOutputBytes != 4<<20 || numeric.MaxRate != 64<<10 || numeric.WatchBurst != 64<<10 {
		t.Fatal("cross-scope service maximum lost", numeric, ceiling)
	}
	if numeric.MaxAccounts != 8192 || numeric.MaxControlRecords != 65536 {
		t.Fatal("internal metadata caps became authored tuning", numeric)
	}
	for _, scope := range p.Ceilings {
		l := scope.Limits
		narrowed := ceiling.Tighten(live.Limits{Duration: l.Duration, Output: l.Output, Rate: l.Rate, Rows: l.Rows, Buffer: l.Buffer, RowAge: l.RowAge, Replay: l.Replay})
		if narrowed != (live.Limits{Duration: l.Duration, Output: l.Output, Rate: l.Rate, Rows: l.Rows, Buffer: l.Buffer, RowAge: l.RowAge, Replay: l.Replay}) {
			t.Fatal("global accounting maximum widened a source ceiling", narrowed, l)
		}
	}
}
func TestPublicLiveLimitsDoNotInventRefillHorizonOrWidenTinyWatch(t *testing.T) {
	p := privacy.LiveRead{Root: privacy.LiveRootLimits{Watches: 1, PrincipalWatches: 1, WorkloadWatches: 1, Rate: 1, Burst: 1 << 30}, Ceilings: []privacy.LiveCeiling{{Limits: privacy.LiveLimits{Duration: 1, Output: 1024, Rate: 1, Rows: 1, Buffer: 256, RowAge: 1, Replay: 0}}}}
	numeric, watch := publicLiveLimits(p)
	if !numeric.Valid() || !watch.Valid() || numeric.PrincipalRate != 1 || numeric.PrincipalBurst != 1<<30 {
		t.Fatal("legitimate long refill debt silently changed", numeric, watch)
	}
	if watch.Output != 1024 || watch.Rate != 1 || watch.Buffer != 256 || numeric.MaxOutputBytes != 24<<10 || numeric.WatchBurst != 24<<10 {
		t.Fatal("protocol storage floor widened actual watch limits", numeric, watch)
	}
	p.Root.Watches = 0
	if invalid, _ := publicLiveLimits(p); invalid.Valid() {
		t.Fatal("missing protected slot budget acquired defaults")
	}
	p.Root.Watches = 1
	p.Ceilings = nil
	if invalid, view := publicLiveLimits(p); invalid.Valid() || view.Valid() {
		t.Fatal("missing scoped limits acquired defaults")
	}
}
