package agent

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"

	"asservat.local/asservat/internal/api"
)

// A watch for what a container uses (memory, CPU, throttling) is measured
// by the agent from the container's own accounting: the files of its
// cgroup, which every container sees under /sys/fs/cgroup and the agent
// reaches through the container's main process. That needs cgroup v2.

// gaugeEvery is how often the agent measures. Use is a level, not an event:
// the kernel only tells when a container reaches its own limits. Reading a
// few small files per container every 5 seconds costs next to nothing and
// is early enough for a container that grows towards its limit.
const gaugeEvery = 5 * time.Second

// usage is what a container's cgroup accounts at one moment.
type usage struct {
	// memory is the memory in use as Kubernetes counts it (the working set:
	// everything except file cache that can be dropped), limit its limit;
	// 0 without one.
	memory, limit int64
	// cpu is the CPU time used so far; cpus the CPU limit in CPUs, 0
	// without one.
	cpu  time.Duration
	cpus float64
	// periods counts the periods of the CPU limit so far and throttled
	// those in which the container was held back.
	periods, throttled int64
	// pressure is the share of the last 10 seconds, in percent, in which
	// some task of the container stalled for memory, CPU or I/O.
	pressure map[string]float64
	// tasks is the number of its threads and processes.
	tasks int64
	// pids are its processes, as the node numbers them.
	pids []int
	// files is the number of files its processes hold open; retransmits
	// and failures count the TCP segments that its pod sent again and the
	// connection attempts of its pod that failed, so far. They are read
	// only for the conditions that are about them.
	files, retransmits, failures int64
}

// readUsage reads a container's accounting from its cgroup directory.
func readUsage(dir string) (usage, error) {
	var u usage
	read := func(name string) (string, error) {
		b, err := os.ReadFile(filepath.Join(dir, name))
		return strings.TrimSpace(string(b)), err
	}
	// keyed returns the numbers of a file of "key value" lines.
	keyed := func(name string) (map[string]int64, error) {
		text, err := read(name)
		values := map[string]int64{}
		for _, line := range strings.Split(text, "\n") {
			if key, value, ok := strings.Cut(line, " "); ok {
				values[key], _ = strconv.ParseInt(value, 10, 64)
			}
		}
		return values, err
	}
	current, err := read("memory.current")
	if err != nil {
		return u, fmt.Errorf("the container's cgroup accounting cannot be read (it needs cgroup v2): %w", err)
	}
	u.memory, _ = strconv.ParseInt(current, 10, 64)
	if stat, err := keyed("memory.stat"); err == nil {
		u.memory = max(u.memory-stat["inactive_file"], 0)
	}
	if limit, err := read("memory.max"); err == nil && limit != "max" {
		u.limit, _ = strconv.ParseInt(limit, 10, 64)
	}
	stat, err := keyed("cpu.stat")
	if err != nil {
		return u, err
	}
	u.cpu, u.periods, u.throttled = time.Duration(stat["usage_usec"])*time.Microsecond, stat["nr_periods"], stat["nr_throttled"]
	// "some avg10=1.23 avg60=… total=…": the share of the last 10 seconds.
	u.pressure = map[string]float64{}
	for _, of := range []string{"memory", "cpu", "io"} {
		for _, field := range strings.Fields(strings.SplitN(firstOf(read(of+".pressure")), "\n", 2)[0]) {
			if share, ok := strings.CutPrefix(field, "avg10="); ok {
				u.pressure[of], _ = strconv.ParseFloat(share, 64)
			}
		}
	}
	u.tasks, _ = strconv.ParseInt(firstOf(read("pids.current")), 10, 64)
	for _, pid := range strings.Fields(firstOf(read("cgroup.procs"))) {
		if n, err := strconv.Atoi(pid); err == nil {
			u.pids = append(u.pids, n)
		}
	}
	// "quota period" in microseconds, or "max period" without a limit.
	if quota, period, ok := strings.Cut(firstOf(read("cpu.max")), " "); ok && quota != "max" {
		q, _ := strconv.ParseFloat(quota, 64)
		if p, _ := strconv.ParseFloat(period, 64); p > 0 {
			u.cpus = q / p
		}
	}
	return u, nil
}

func firstOf(s string, _ error) string { return s }

// openFiles counts the files that processes hold open, in the node's /proc.
func openFiles(proc string, pids []int) int64 {
	var n int64
	for _, pid := range pids {
		held, _ := os.ReadDir(filepath.Join(proc, strconv.Itoa(pid), "fd"))
		n += int64(len(held))
	}
	return n
}

// tcpCounters reads how many TCP segments a process's network namespace has
// sent again and how many of its connection attempts failed, from the
// kernel's counters: a line of names and a line of numbers.
func tcpCounters(proc string, pid int) (retransmits, failures int64) {
	b, _ := os.ReadFile(filepath.Join(proc, strconv.Itoa(pid), "net", "snmp"))
	var names []string
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "Tcp:" {
			continue
		}
		if names == nil {
			names = fields
			continue
		}
		for i, value := range fields {
			if i < len(names) {
				switch n, _ := strconv.ParseInt(value, 10, 64); names[i] {
				case "RetransSegs":
					retransmits = n
				case "AttemptFails":
					failures = n
				}
			}
		}
	}
	return retransmits, failures
}

// gauge follows one container's use against a usage condition.
type gauge struct {
	when    api.Condition
	above   api.Above
	held    time.Duration // how long the use must stay above
	last    usage
	at      time.Time // when last was read; zero before the first reading
	since   time.Time // since when the use is above; zero while it is not
	told    bool      // reported for this time above
	limited bool      // said once that a share needs a limit
	// grown holds the memory readings of the time over which growth is measured.
	grown []grownAt
}

type grownAt struct {
	at     time.Time
	memory int64
}

func newGauge(when api.Condition) *gauge {
	above, _ := api.ParseAbove(when.Kind, when.Params["above"]) // the hub validated it
	seconds, _ := strconv.Atoi(when.Params["seconds"])
	return &gauge{when: when, above: above, held: time.Duration(seconds) * time.Second}
}

// reading takes the container's accounting at a moment and returns what to
// report, or "": once when the use has been above the threshold for as
// long as asked, and again only after it has been below. CPU and
// throttling are rates and need two readings.
func (g *gauge) reading(u usage, now time.Time) string {
	last, elapsed := g.last, now.Sub(g.at)
	first := g.at.IsZero()
	g.last, g.at = u, now
	var is float64 // in the unit of the threshold
	var told string
	switch g.when.Kind {
	case api.OnMemory:
		is = float64(u.memory)
		told = "uses " + bytesText(u.memory) + " of memory"
		if g.above.Percent {
			if u.limit == 0 {
				return g.unlimited("memory")
			}
			is = 100 * float64(u.memory) / float64(u.limit)
			told += fmt.Sprintf(", %.0f %% of its limit of %s", is, bytesText(u.limit))
		}
	case api.OnCPU:
		if first || elapsed <= 0 {
			return ""
		}
		is = (u.cpu - last.cpu).Seconds() / elapsed.Seconds()
		told = fmt.Sprintf("uses %.2f CPUs", is)
		if g.above.Percent {
			if u.cpus == 0 {
				return g.unlimited("CPU")
			}
			told += fmt.Sprintf(", %.0f %% of its limit of %.2f", 100*is/u.cpus, u.cpus)
			is = 100 * is / u.cpus
		}
	case api.OnThrottle:
		periods := u.periods - last.periods
		if first || periods <= 0 {
			if !first && u.cpus == 0 {
				return g.unlimited("CPU")
			}
			return ""
		}
		is = 100 * float64(u.throttled-last.throttled) / float64(periods)
		told = fmt.Sprintf("is held back by its CPU limit of %.2f CPUs in %.0f %% of the time", u.cpus, is)
	case api.OnPressure:
		of := g.when.Params["of"]
		if of == "" {
			of = "memory"
		}
		is = u.pressure[of]
		told = fmt.Sprintf("stalls for %s in %.0f %% of the time", map[string]string{"memory": "memory", "cpu": "CPU", "io": "I/O"}[of], is)
	case api.OnThreads:
		is = float64(u.tasks)
		told = fmt.Sprintf("has %d threads and processes", u.tasks)
	case api.OnFiles:
		is = float64(u.files)
		told = fmt.Sprintf("holds %d files open", u.files)
	case api.OnRetransmits, api.OnTCPFailures:
		if first || elapsed <= 0 {
			return ""
		}
		if g.when.Kind == api.OnRetransmits {
			is = float64(u.retransmits-last.retransmits) / elapsed.Seconds()
			told = fmt.Sprintf("is in a pod that sends %.1f TCP segments per second again", is)
		} else {
			is = float64(u.failures-last.failures) / elapsed.Seconds()
			told = fmt.Sprintf("is in a pod of which %.1f TCP connection attempts per second fail", is)
		}
	case api.OnGrowth:
		// By how much the memory has grown from its lowest reading within the time.
		g.grown = append(g.grown, grownAt{now, u.memory})
		for len(g.grown) > 1 && now.Sub(g.grown[0].at) > g.held {
			g.grown = g.grown[1:]
		}
		lowest := g.grown[0]
		for _, reading := range g.grown {
			if reading.memory < lowest.memory {
				lowest = reading
			}
		}
		is = float64(u.memory - lowest.memory)
		if is <= g.above.Value {
			g.told = false
			return ""
		}
		if g.told {
			return ""
		}
		g.told = true
		return fmt.Sprintf("has grown by %s of memory in %s, to %s (above %s)", bytesText(u.memory-lowest.memory), now.Sub(lowest.at).Round(time.Second), bytesText(u.memory), g.when.Params["above"])
	}
	if is <= g.above.Value {
		g.since, g.told = time.Time{}, false
		return ""
	}
	if g.since.IsZero() {
		g.since = now
	}
	if g.told || now.Sub(g.since) < g.held {
		return ""
	}
	g.told = true
	if g.held > 0 {
		told += fmt.Sprintf(" for %s", now.Sub(g.since).Round(time.Second))
	}
	return told + " (above " + g.when.Params["above"] + ")"
}

// unlimited says once that a share cannot be measured without a limit.
func (g *gauge) unlimited(of string) string {
	if !g.limited {
		g.limited = true
		slog.Warn("a watch for a share of a limit meets a container without that limit: it will not record", "limit", of, "above", g.when.Params["above"])
	}
	return ""
}

func bytesText(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.0f MiB", float64(n)/(1<<20))
	default:
		return fmt.Sprintf("%.0f KiB", float64(n)/(1<<10))
	}
}

// measure reads what the pod's containers use at every interval until ctx
// ends, and reports to the hub when one meets the watch's condition. latest
// holds the pod as the agent last saw it: a restarted container is another
// process.
func (a *Agent) measure(agent, ctx context.Context, w api.Watch, latest *atomic.Pointer[corev1.Pod]) {
	gauges := map[string]*gauge{}
	every := time.NewTicker(gaugeEvery)
	defer every.Stop()
	for {
		pod := latest.Load()
		for _, c := range pod.Spec.Containers {
			if want := w.When.Params["container"]; want != "" && want != c.Name {
				continue
			}
			pid, _, err := a.containerPID(pod, c.Name)
			if err != nil {
				delete(gauges, c.Name) // not running: its successor starts anew
				continue
			}
			u, err := readUsage(filepath.Join(a.Proc, strconv.Itoa(pid), "root", "sys", "fs", "cgroup"))
			switch w.When.Kind {
			case api.OnFiles:
				u.files = openFiles(a.Proc, u.pids)
			case api.OnRetransmits, api.OnTCPFailures:
				u.retransmits, u.failures = tcpCounters(a.Proc, pid)
			}
			if err != nil {
				if gauges[c.Name] == nil {
					slog.Warn("usage watch", "watch", w.ID, "pod", pod.Name, "container", c.Name, "error", err)
					gauges[c.Name] = newGauge(w.When) // said once
				}
				continue
			}
			g := gauges[c.Name]
			if g == nil {
				g = newGauge(w.When)
				gauges[c.Name] = g
			}
			if told := g.reading(u, time.Now()); told != "" {
				go a.trigger(agent, w, pod, "container "+c.Name+" "+told)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-every.C:
		}
	}
}
