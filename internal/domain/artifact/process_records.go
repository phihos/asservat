package artifact

import (
	"path"
	"slices"
	"strings"
	"time"
)

const (
	ProcessFormat              = "asservat-processes/v1"
	ProcessNativeLimit   int64 = 2 << 20
	ProcessMaxContainers       = 64
	ProcessMaxRecords          = 256
	ProcessMain                = "podMainProcesses"
	ProcessAll                 = "allPodProcesses"
)

// ProcessIdentity names an observed process, never a bare PID or authority to
// act on it. Every consumer must revalidate the entire identity locally.
type ProcessIdentity struct {
	PodUID         string `json:"pod_uid"`
	NodeBootID     string `json:"node_boot_id"`
	RuntimeID      string `json:"runtime_id"`
	RestartCount   uint32 `json:"restart_count"`
	HostPID        uint32 `json:"host_pid"`
	StartTimeTicks uint64 `json:"start_time_ticks"`
	CgroupPath     string `json:"cgroup_path"`
	CgroupID       uint64 `json:"cgroup_id"`
}

func (p ProcessIdentity) Valid() bool {
	return logText(p.PodUID, 128) && uuid(p.NodeBootID) && processRuntimeID(p.RuntimeID) &&
		p.HostPID > 1 && p.HostPID <= 4194304 && p.StartTimeTicks > 0 && p.StartTimeTicks <= 1<<53-1 &&
		p.CgroupID > 0 && p.CgroupID <= 1<<53-1 && validProcessCgroup(p.CgroupPath)
}

func processRuntimeID(v string) bool {
	p := strings.SplitN(v, "://", 2)
	if len(p) != 2 || p[0] != "containerd" && p[0] != "cri-o" || len(p[1]) != 64 {
		return false
	}
	for _, c := range p[1] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func validProcessCgroup(p string) bool {
	return logText(p, 1024) && strings.HasPrefix(p, "/") && p != "/" && path.Clean(p) == p && !strings.Contains(p, "\\")
}

type ProcessOrigin struct {
	RuntimeID    string `json:"runtime_id"`
	RestartCount uint32 `json:"restart_count"`
	MainPID      uint32 `json:"main_pid"`
	Outcome      string `json:"outcome"`
}

type ProcessRecord struct {
	Identity       ProcessIdentity `json:"identity"`
	NamespacePID   uint32          `json:"namespace_pid"`
	ObservedAt     time.Time       `json:"observed_at"`
	ParentPID      uint32          `json:"parent_pid"`
	Main           bool            `json:"main"`
	State          string          `json:"state"`
	UID            uint32          `json:"uid"`
	Threads        uint32          `json:"threads"`
	RSSBytes       uint64          `json:"rss_bytes"`
	ExecutablePath string          `json:"executable_path"`
}

// ProcessInventory deliberately has no command line, environment, maps or
// user-memory value. Runtime IDs are provenance, never public selectors.
type ProcessInventory struct {
	Format      string          `json:"format"`
	PodUID      string          `json:"pod_uid"`
	NodeUID     string          `json:"node_uid"`
	NodeBootID  string          `json:"node_boot_id"`
	Mode        string          `json:"mode"`
	StartedAt   time.Time       `json:"started_at"`
	CompletedAt time.Time       `json:"completed_at"`
	Origins     []ProcessOrigin `json:"origins"`
	Processes   []ProcessRecord `json:"processes"`
	Gaps        []string        `json:"gaps"`
}

func (p ProcessInventory) Valid() bool {
	if p.Format != ProcessFormat || !logText(p.PodUID, 128) || !logText(p.NodeUID, 128) || !uuid(p.NodeBootID) ||
		(p.Mode != ProcessMain && p.Mode != ProcessAll) || p.StartedAt.IsZero() || p.CompletedAt.Before(p.StartedAt) ||
		p.CompletedAt.Sub(p.StartedAt) > 5*time.Second || len(p.Origins) > ProcessMaxContainers || len(p.Processes) > ProcessMaxRecords ||
		p.Origins == nil || p.Processes == nil || p.Gaps == nil || !slices.IsSorted(p.Gaps) {
		return false
	}
	if len(p.Origins) == 0 && !slices.Contains(p.Gaps, "sourceUnavailable") {
		return false
	}
	origins := map[string]ProcessOrigin{}
	for n, o := range p.Origins {
		if !processRuntimeID(o.RuntimeID) || n > 0 && p.Origins[n-1].RuntimeID >= o.RuntimeID ||
			(o.Outcome != "observed" && o.Outcome != "unavailable") || o.Outcome == "observed" && o.MainPID <= 1 || o.Outcome == "unavailable" && o.MainPID != 0 {
			return false
		}
		if o.Outcome == "unavailable" && !slices.Contains(p.Gaps, "sourceUnavailable") {
			return false
		}
		origins[o.RuntimeID] = o
	}
	mainSeen := map[string]bool{}
	for n, r := range p.Processes {
		i := r.Identity
		o, ok := origins[i.RuntimeID]
		if !i.Valid() || i.PodUID != p.PodUID || i.NodeBootID != p.NodeBootID || !ok || o.Outcome != "observed" || o.RestartCount != i.RestartCount || r.Main != (o.MainPID == i.HostPID) || p.Mode == ProcessMain && !r.Main ||
			len(r.State) != 1 || !strings.Contains("RSDZTtXxKWPI", r.State) || r.ObservedAt.Before(p.StartedAt) || r.ObservedAt.After(p.CompletedAt) || r.NamespacePID == 0 || r.NamespacePID > 4194304 || r.Threads == 0 || r.RSSBytes > 1<<53-1 || r.ExecutablePath != "" && (!logText(r.ExecutablePath, 4096) || !strings.HasPrefix(r.ExecutablePath, "/")) || n > 0 && p.Processes[n-1].Identity.HostPID >= i.HostPID {
			return false
		}
		if r.Main {
			mainSeen[i.RuntimeID] = true
		}
	}
	for _, o := range p.Origins {
		if o.Outcome == "observed" && !mainSeen[o.RuntimeID] {
			return false
		}
	}
	for n, g := range p.Gaps {
		if n > 0 && p.Gaps[n-1] == g || g != "sourceUnavailable" && g != "processGone" && g != "processLimit" && g != "containerLimit" && g != "cgroupLimit" && g != "timedOut" && g != "socketOwnersUnsupported" {
			return false
		}
	}
	return true
}

func CloneProcessInventory(p ProcessInventory) ProcessInventory {
	p.Origins = slices.Clone(p.Origins)
	p.Processes = slices.Clone(p.Processes)
	p.Gaps = slices.Clone(p.Gaps)
	return p
}
