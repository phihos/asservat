package artifact

import (
	"testing"
	"time"
)

func processFixture() ProcessInventory {
	n := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
	boot := "10000000-0000-4000-8000-000000000001"
	id := "containerd://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	return ProcessInventory{Format: ProcessFormat, PodUID: "pod", NodeUID: "node", NodeBootID: boot, Mode: ProcessMain, StartedAt: n, CompletedAt: n.Add(time.Millisecond), Origins: []ProcessOrigin{{RuntimeID: id, MainPID: 123, Outcome: "observed"}}, Processes: []ProcessRecord{{Identity: ProcessIdentity{PodUID: "pod", NodeBootID: boot, RuntimeID: id, HostPID: 123, StartTimeTicks: 10, CgroupPath: "/pod/container", CgroupID: 100}, NamespacePID: 1, ObservedAt: n, Main: true, State: "S", Threads: 2, ExecutablePath: "/app/server"}}, Gaps: []string{}}
}

func TestProcessInventoryExactSourceAndBounds(t *testing.T) {
	p := processFixture()
	if !p.Valid() {
		t.Fatal("valid inventory refused")
	}
	for name, mutate := range map[string]func(*ProcessInventory){"bare PID": func(p *ProcessInventory) { p.Processes[0].Identity.StartTimeTicks = 0 }, "wrong Pod": func(p *ProcessInventory) { p.Processes[0].Identity.PodUID = "other" }, "changed boot": func(p *ProcessInventory) { p.Processes[0].Identity.NodeBootID = "20000000-0000-4000-8000-000000000001" }, "wrong main": func(p *ProcessInventory) { p.Processes[0].Main = false }, "node cgroup": func(p *ProcessInventory) { p.Processes[0].Identity.CgroupPath = "/" }, "traversal": func(p *ProcessInventory) { p.Processes[0].Identity.CgroupPath = "/pod/../node" }, "duplicate PID": func(p *ProcessInventory) { p.Processes = append(p.Processes, p.Processes[0]) }, "unknown gap": func(p *ProcessInventory) { p.Gaps = []string{"invented"} }, "renewed deadline": func(p *ProcessInventory) { p.CompletedAt = p.StartedAt.Add(6 * time.Second) }, "unavailable source": func(p *ProcessInventory) { p.Origins[0].Outcome = "unavailable"; p.Origins[0].MainPID = 0 }} {
		t.Run(name, func(t *testing.T) {
			v := CloneProcessInventory(p)
			mutate(&v)
			if v.Valid() {
				t.Fatal("invalid source accepted")
			}
		})
	}
}

func TestProcessInventoryCloneOwnsRows(t *testing.T) {
	p := processFixture()
	v := CloneProcessInventory(p)
	v.Processes[0].Identity.HostPID = 999
	v.Origins[0].RuntimeID = "other"
	if !p.Valid() {
		t.Fatal("clone mutated source")
	}
}
