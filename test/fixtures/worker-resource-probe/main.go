//go:build ignore

// worker-resource-probe is a finite, test-only executable in the owned fixture
// image. It reads only fixed cgroup files and its own executable; no product
// entry point, credential, socket, mutation or background observer is added.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type limit struct {
	Value     int64 `json:"value"`
	Unlimited bool  `json:"unlimited"`
}
type observation struct {
	Format        string           `json:"format"`
	ObservedAt    time.Time        `json:"observed_at"`
	BinarySHA256  string           `json:"binary_sha256"`
	MemoryMax     limit            `json:"memory_max"`
	MemoryCurrent int64            `json:"memory_current"`
	MemoryPeak    int64            `json:"memory_peak"`
	SwapMax       limit            `json:"swap_max"`
	SwapCurrent   int64            `json:"swap_current"`
	MemoryEvents  map[string]int64 `json:"memory_events"`
	CPUQuota      limit            `json:"cpu_quota"`
	CPUPeriod     int64            `json:"cpu_period"`
	CPUStat       map[string]int64 `json:"cpu_stat"`
}

func readLimit(s string) (limit, error) {
	if s == "max" {
		return limit{Unlimited: true}, nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return limit{}, fmt.Errorf("invalid nonnegative cgroup limit")
	}
	return limit{Value: n}, nil
}
func counters(s string) (map[string]int64, error) {
	out := map[string]int64{}
	for _, line := range strings.Split(strings.TrimSpace(s), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || len(fields[0]) > 64 {
			return nil, fmt.Errorf("invalid cgroup counter")
		}
		n, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("invalid cgroup counter value")
		}
		if _, exists := out[fields[0]]; exists {
			return nil, fmt.Errorf("duplicate cgroup counter")
		}
		out[fields[0]] = n
	}
	return out, nil
}
func probe(directory string) (observation, error) {
	out := observation{Format: "asservat-worker-cgroup-observation/v1", ObservedAt: time.Now().UTC()}
	read := func(name string) (string, error) {
		f, err := os.Open(filepath.Join(directory, name))
		if err != nil {
			return "", err
		}
		defer f.Close()
		b, err := io.ReadAll(io.LimitReader(f, 8193))
		if err != nil || len(b) > 8192 {
			return "", fmt.Errorf("cgroup observation unavailable/bound exceeded")
		}
		return strings.TrimSpace(string(b)), nil
	}
	for name, target := range map[string]*limit{"memory.max": &out.MemoryMax, "memory.swap.max": &out.SwapMax} {
		s, err := read(name)
		if err != nil {
			return observation{}, err
		}
		*target, err = readLimit(s)
		if err != nil {
			return observation{}, err
		}
	}
	for name, target := range map[string]*int64{"memory.current": &out.MemoryCurrent, "memory.swap.current": &out.SwapCurrent} {
		s, err := read(name)
		if err != nil {
			return observation{}, err
		}
		n, err := readLimit(s)
		if err != nil || n.Unlimited {
			return observation{}, fmt.Errorf("nonfinite cgroup measurement")
		}
		*target = n.Value
	}
	s, err := read("cpu.max")
	if err != nil {
		return observation{}, err
	}
	parts := strings.Fields(s)
	if len(parts) != 2 {
		return observation{}, fmt.Errorf("invalid CPU quota")
	}
	out.CPUQuota, err = readLimit(parts[0])
	if err != nil {
		return observation{}, err
	}
	period, err := readLimit(parts[1])
	if err != nil || period.Unlimited || period.Value == 0 {
		return observation{}, fmt.Errorf("invalid CPU period")
	}
	out.CPUPeriod = period.Value
	for name, target := range map[string]*map[string]int64{"memory.events": &out.MemoryEvents, "cpu.stat": &out.CPUStat} {
		s, err := read(name)
		if err != nil {
			return observation{}, err
		}
		*target, err = counters(s)
		if err != nil {
			return observation{}, err
		}
	}
	for _, key := range []string{"oom", "oom_kill"} {
		if _, ok := out.MemoryEvents[key]; !ok {
			return observation{}, fmt.Errorf("missing memory event %s", key)
		}
	}
	for _, key := range []string{"usage_usec", "user_usec", "system_usec", "nr_periods", "nr_throttled", "throttled_usec"} {
		if _, ok := out.CPUStat[key]; !ok {
			return observation{}, fmt.Errorf("missing CPU counter %s", key)
		}
	}
	// Read the monotonic peak after current memory and the counter allocations,
	// so a changing process cannot make a later current sample exceed an older
	// peak merely because a map happened to choose the opposite read order.
	peak, err := read("memory.peak")
	if err != nil {
		return observation{}, err
	}
	n, err := readLimit(peak)
	if err != nil || n.Unlimited {
		return observation{}, fmt.Errorf("nonfinite memory peak")
	}
	out.MemoryPeak = n.Value
	return out, nil
}
func main() {
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "resource observer accepts no arguments")
		os.Exit(1)
	}
	// Hashing and this observation process are included in the worker's
	// cumulative CPU and peak memory. This is not an analyzer-only baseline.
	executable, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	f, err := os.Open(executable)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	hash := sha256.New()
	_, err = io.Copy(hash, f)
	f.Close()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	out, err := probe("/sys/fs/cgroup")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	out.BinarySHA256 = hex.EncodeToString(hash.Sum(nil))
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
