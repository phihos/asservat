//go:build ignore

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFiniteWorkerCgroupProbe(t *testing.T) {
	files := map[string]string{"memory.max": "402653184", "memory.current": "100000000", "memory.peak": "260000000", "memory.swap.max": "0", "memory.swap.current": "0", "memory.events": "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n", "cpu.max": "50000 100000", "cpu.stat": "usage_usec 1200000\nuser_usec 1100000\nsystem_usec 100000\nnr_periods 40\nnr_throttled 12\nthrottled_usec 100000\n"}
	dir := t.TempDir()
	for name, value := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	out, err := probe(dir)
	if err != nil || out.MemoryMax.Unlimited || out.MemoryMax.Value != 384<<20 || out.MemoryPeak != 260000000 || out.CPUQuota.Value*2 != out.CPUPeriod || out.CPUStat["nr_throttled"] != 12 || out.MemoryEvents["oom_kill"] != 0 {
		t.Fatal("finite cgroup observation", out, err)
	}
	for _, name := range []string{"cpu.max", "cpu.stat", "memory.events", "memory.peak"} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(dir, name), []byte("invalid"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := probe(dir); err == nil {
				t.Fatal("invalid kernel observation accepted")
			}
			os.WriteFile(filepath.Join(dir, name), []byte(files[name]), 0600)
		})
	}
	if err := os.Remove(filepath.Join(dir, "memory.peak")); err != nil {
		t.Fatal(err)
	}
	if _, err := probe(dir); err == nil {
		t.Fatal("missing peak fabricated")
	}
}
