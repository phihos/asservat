package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/api"
)

// cgroup writes the accounting files of a container's cgroup.
func cgroup(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// A container's use is read from its cgroup: memory as Kubernetes counts
// it, without file cache that can be dropped, and the limits if it has any.
func TestReadUsage(t *testing.T) {
	u, err := readUsage(cgroup(t, map[string]string{
		"memory.current": "420000000\n", "memory.stat": "anon 300000000\nfile 120000000\ninactive_file 20000000\n", "memory.max": "500000000\n",
		"cpu.stat": "usage_usec 9000000\nuser_usec 8000000\nnr_periods 200\nnr_throttled 50\nthrottled_usec 700\n", "cpu.max": "150000 100000\n",
	}))
	if err != nil || u.memory != 400000000 || u.limit != 500000000 || u.cpu != 9*time.Second || u.cpus != 1.5 || u.periods != 200 || u.throttled != 50 {
		t.Fatal(u, err)
	}
	u, err = readUsage(cgroup(t, map[string]string{"memory.current": "1000", "memory.max": "max", "cpu.stat": "usage_usec 5", "cpu.max": "max 100000"}))
	if err != nil || u.limit != 0 || u.cpus != 0 || u.memory != 1000 {
		t.Fatal("a container without limits", u, err)
	}
	if _, err := readUsage(t.TempDir()); err == nil || !strings.Contains(err.Error(), "cgroup v2") {
		t.Fatal("a directory that is no cgroup", err)
	}
}

// A usage condition is met once the use has been above the threshold for
// as long as asked, and again only after it has been below.
func TestGauge(t *testing.T) {
	start := time.Unix(1700000000, 0)
	at := func(seconds int) time.Time { return start.Add(time.Duration(seconds) * time.Second) }
	mib := int64(1 << 20)

	memory := newGauge(api.Condition{Kind: api.OnMemory, Params: map[string]string{"above": "80%", "seconds": "10"}})
	limited := func(used int64) usage { return usage{memory: used * mib, limit: 500 * mib} }
	for _, step := range []struct {
		second int
		used   int64
		want   string
	}{
		{0, 300, ""},  // below
		{5, 450, ""},  // above, but not for 10 seconds yet
		{10, 460, ""}, // 5 seconds above
		{15, 470, "uses 470 MiB of memory, 94 % of its limit of 500 MiB for 10s (above 80%)"},
		{20, 480, ""}, // told once
		{25, 100, ""}, // below again
		{30, 450, ""}, // above anew
		{40, 455, "uses 455 MiB of memory, 91 % of its limit of 500 MiB for 10s (above 80%)"},
	} {
		if got := memory.reading(limited(step.used), at(step.second)); got != step.want {
			t.Fatalf("memory at %d s: %q, want %q", step.second, got, step.want)
		}
	}
	// A size needs no limit and, without a time, is met at the first reading above.
	size := newGauge(api.Condition{Kind: api.OnMemory, Params: map[string]string{"above": "200Mi"}})
	if got := size.reading(usage{memory: 250 * mib}, at(0)); got != "uses 250 MiB of memory (above 200Mi)" {
		t.Fatal(got)
	}
	// A share of a limit that the container has not is never met.
	if got := newGauge(api.Condition{Kind: api.OnMemory, Params: map[string]string{"above": "1%"}}).reading(usage{memory: 250 * mib}, at(0)); got != "" {
		t.Fatal("a share without a limit:", got)
	}

	// CPU use is the CPU time between two readings.
	cpu := newGauge(api.Condition{Kind: api.OnCPU, Params: map[string]string{"above": "1.5"}})
	if got := cpu.reading(usage{cpu: 100 * time.Second}, at(0)); got != "" {
		t.Fatal("one reading tells no rate:", got)
	}
	if got := cpu.reading(usage{cpu: 105 * time.Second}, at(5)); got != "" {
		t.Fatal("one CPU:", got)
	}
	if got := cpu.reading(usage{cpu: 115 * time.Second}, at(10)); got != "uses 2.00 CPUs (above 1.5)" {
		t.Fatal(got)
	}
	share := newGauge(api.Condition{Kind: api.OnCPU, Params: map[string]string{"above": "90%"}})
	share.reading(usage{cpu: 0, cpus: 2}, at(0))
	if got := share.reading(usage{cpu: 9500 * time.Millisecond, cpus: 2}, at(5)); got != "uses 1.90 CPUs, 95 % of its limit of 2.00 (above 90%)" {
		t.Fatal(got)
	}

	// Throttling is the share of the limit's periods in which the container was held back.
	throttled := newGauge(api.Condition{Kind: api.OnThrottle, Params: map[string]string{"above": "25%"}})
	throttled.reading(usage{periods: 100, throttled: 10, cpus: 0.5}, at(0))
	if got := throttled.reading(usage{periods: 150, throttled: 15, cpus: 0.5}, at(5)); got != "" {
		t.Fatal("a tenth of the time:", got)
	}
	if got := throttled.reading(usage{periods: 200, throttled: 45, cpus: 0.5}, at(10)); got != "is held back by its CPU limit of 0.50 CPUs in 60 % of the time (above 25%)" {
		t.Fatal(got)
	}
}
