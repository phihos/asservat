//go:build linux

// Package linux contains qualified local kernel adapters, not capture authority.
package linux

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	execution "asservat.local/asservat/internal/application/execution"
	"asservat.local/asservat/internal/domain/artifact"
)

var (
	ErrProcessChanged     = errors.New("process snapshot target changed")
	ErrProcessUnavailable = errors.New("process snapshot unavailable")
)

type ProcessSnapshots struct {
	runtime       execution.ProcessRuntimeReader
	proc, cgroups string
	now           func() time.Time
}

func NewProcessSnapshots(runtime execution.ProcessRuntimeReader) *ProcessSnapshots {
	return &ProcessSnapshots{runtime: runtime, proc: "/proc", cgroups: "/sys/fs/cgroup", now: time.Now}
}

// Capture is a finite metadata read. Nothing is returned until all participating
// runtime main identities and boot identity have been checked again. It never
// opens cmdline, environ, mem, maps, fd targets, namespaces or executables.
func (s *ProcessSnapshots) capture(ctx context.Context, r execution.ProcessSnapshotRequest) (artifact.ProcessInventory, error) {
	var zero artifact.ProcessInventory
	if s == nil || s.runtime == nil || s.now == nil || ctx == nil || ctx.Err() != nil || !r.Valid() {
		return zero, ErrProcessUnavailable
	}
	if s.now().Before(r.NotBefore) || !s.now().Before(r.Deadline) {
		return zero, context.DeadlineExceeded
	}
	call, cancel := context.WithDeadline(ctx, r.Deadline)
	defer cancel()
	started := s.now().UTC()
	boot, e := readBounded(filepath.Join(s.proc, "sys/kernel/random/boot_id"), 128)
	if e != nil || strings.TrimSpace(string(boot)) != r.NodeBootID {
		return zero, ErrProcessChanged
	}
	members, e := s.runtime.PodProcesses(call, r.Pin)
	if e != nil || len(members) > artifact.ProcessMaxContainers {
		return zero, ErrProcessUnavailable
	}
	out := artifact.ProcessInventory{Format: artifact.ProcessFormat, PodUID: r.Pin.UID, NodeUID: r.NodeUID, NodeBootID: r.NodeBootID, Mode: r.Mode, StartedAt: started, Origins: []artifact.ProcessOrigin{}, Processes: []artifact.ProcessRecord{}, Gaps: []string{"socketOwnersUnsupported"}}
	slices.SortFunc(members, func(a, b execution.ProcessRuntimeMember) int { return strings.Compare(a.ID, b.ID) })
	if len(members) == 0 {
		addGap(&out, "sourceUnavailable")
	}
	perOrigin := artifact.ProcessMaxRecords / max(1, len(members))
	seen := map[uint32]bool{}
	for n, m := range members {
		if call.Err() != nil {
			return zero, call.Err()
		}
		if m.PodUID != r.Pin.UID || m.ID == "" || n > 0 && members[n-1].ID == m.ID {
			return zero, ErrProcessChanged
		}
		o := artifact.ProcessOrigin{RuntimeID: m.ID, RestartCount: m.RestartCount, MainPID: m.MainPID, Outcome: "observed"}
		if !m.Running {
			o.MainPID = 0
			o.Outcome = "unavailable"
			out.Origins = append(out.Origins, o)
			addGap(&out, "sourceUnavailable")
			continue
		}
		main, e := s.readProcess(r, m, m.MainPID, "")
		if e != nil {
			return zero, ErrProcessChanged
		}
		ids := []uint32{m.MainPID}
		if r.Mode == artifact.ProcessAll {
			var limited bool
			ids, limited, e = s.memberPIDs(call, main.Identity.CgroupPath, perOrigin)
			if e != nil {
				return zero, ErrProcessUnavailable
			}
			if limited {
				addGap(&out, "processLimit")
			}
			// Preserve the runtime-identified main even when a descendant list
			// fills its fair share. No other source borrows that reservation.
			if !slices.Contains(ids, m.MainPID) {
				if len(ids) == perOrigin {
					ids = ids[:len(ids)-1]
				}
				ids = append(ids, m.MainPID)
			}
		}
		for _, pid := range ids {
			if call.Err() != nil {
				return zero, call.Err()
			}
			p, e := s.readProcess(r, m, pid, main.Identity.CgroupPath)
			if e != nil {
				if pid == m.MainPID {
					return zero, ErrProcessChanged
				}
				addGap(&out, "processGone")
				continue
			}
			if seen[pid] {
				return zero, ErrProcessChanged
			}
			seen[pid] = true
			out.Processes = append(out.Processes, p)
		}
		latest, e := s.runtime.CurrentProcessMember(call, m)
		if e != nil || latest != m {
			return zero, ErrProcessChanged
		}
		again, e := s.readProcess(r, m, m.MainPID, main.Identity.CgroupPath)
		if e != nil || again.Identity != main.Identity {
			return zero, ErrProcessChanged
		}
		out.Origins = append(out.Origins, o)
	}
	boot, e = readBounded(filepath.Join(s.proc, "sys/kernel/random/boot_id"), 128)
	if e != nil || strings.TrimSpace(string(boot)) != r.NodeBootID {
		return zero, ErrProcessChanged
	}
	out.CompletedAt = s.now().UTC()
	slices.SortFunc(out.Processes, func(a, b artifact.ProcessRecord) int {
		if a.Identity.HostPID < b.Identity.HostPID {
			return -1
		}
		if a.Identity.HostPID > b.Identity.HostPID {
			return 1
		}
		return 0
	})
	slices.Sort(out.Gaps)
	if call.Err() != nil {
		return zero, call.Err()
	}
	if !s.now().Before(r.Deadline) {
		return zero, context.DeadlineExceeded
	}
	b, e := json.Marshal(out)
	if e != nil || int64(len(b)) > r.NativeLimit {
		return zero, artifact.ErrLimit
	}
	if !out.Valid() {
		return zero, ErrProcessUnavailable
	}
	return out, nil
}

func addGap(p *artifact.ProcessInventory, g string) {
	if !slices.Contains(p.Gaps, g) {
		p.Gaps = append(p.Gaps, g)
	}
}

func readBounded(p string, n int64) ([]byte, error) {
	f, e := os.Open(p)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, n+1))
	if e != nil || int64(len(b)) > n {
		return nil, artifact.ErrLimit
	}
	return b, nil
}

func (s *ProcessSnapshots) readProcess(r execution.ProcessSnapshotRequest, m execution.ProcessRuntimeMember, pid uint32, parent string) (artifact.ProcessRecord, error) {
	var zero artifact.ProcessRecord
	if pid <= 1 || pid > 4194304 {
		return zero, ErrProcessChanged
	}
	dir := filepath.Join(s.proc, strconv.FormatUint(uint64(pid), 10))
	stat, e := readBounded(filepath.Join(dir, "stat"), 8192)
	if e != nil {
		return zero, e
	}
	fields, start, e := processStat(stat, pid)
	if e != nil {
		return zero, e
	}
	cg, e := readBounded(filepath.Join(dir, "cgroup"), 8192)
	if e != nil {
		return zero, e
	}
	cgroup, e := processCgroup(cg)
	if e != nil {
		return zero, e
	}
	// CRI establishes the member. Kernel cgroup identity must additionally
	// identify that full container ID, not a substring of a Pod name.
	id := strings.SplitN(m.ID, "://", 2)
	if len(id) != 2 || len(id[1]) != 64 {
		return zero, ErrProcessChanged
	}
	if parent == "" {
		base := path.Base(cgroup)
		if base != id[1] && base != "cri-containerd-"+id[1]+".scope" && base != "crio-"+id[1]+".scope" {
			return zero, ErrProcessChanged
		}
	} else if cgroup != parent && !strings.HasPrefix(cgroup, parent+"/") {
		return zero, ErrProcessChanged
	}
	cgroupFile, e := os.OpenRoot(s.cgroups)
	if e != nil {
		return zero, e
	}
	defer cgroupFile.Close()
	f, e := cgroupFile.Open(strings.TrimPrefix(cgroup, "/"))
	if e != nil {
		return zero, e
	}
	defer f.Close()
	fi, e := f.Stat()
	if e != nil || !fi.IsDir() {
		return zero, ErrProcessChanged
	}
	native, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return zero, ErrProcessUnavailable
	}
	status, e := readBounded(filepath.Join(dir, "status"), 64<<10)
	if e != nil {
		return zero, e
	}
	var uid uint64
	found := false
	var namespacePID uint64
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			v := strings.Fields(line)
			if len(v) != 5 {
				return zero, ErrProcessUnavailable
			}
			uid, e = strconv.ParseUint(v[1], 10, 32)
			if e != nil {
				return zero, e
			}
			found = true
		}
		if strings.HasPrefix(line, "NSpid:") {
			v := strings.Fields(line)
			if len(v) < 2 || v[1] != strconv.FormatUint(uint64(pid), 10) {
				return zero, ErrProcessChanged
			}
			namespacePID, e = strconv.ParseUint(v[len(v)-1], 10, 32)
			if e != nil {
				return zero, e
			}
		}
	}
	if !found || namespacePID == 0 || namespacePID > 4194304 {
		return zero, ErrProcessUnavailable
	}
	exe, e := os.Readlink(filepath.Join(dir, "exe"))
	if e != nil {
		exe = "" // kernel identity remains known; executable identity is unknown.
	}
	again, e := readBounded(filepath.Join(dir, "stat"), 8192)
	if e != nil {
		return zero, e
	}
	_, other, e := processStat(again, pid)
	if e != nil || other != start {
		return zero, ErrProcessChanged
	}
	lastGroup, e := readBounded(filepath.Join(dir, "cgroup"), 8192)
	if e != nil || string(lastGroup) != string(cg) {
		return zero, ErrProcessChanged
	}
	ppid, e1 := strconv.ParseUint(fields[1], 10, 32)
	threads, e2 := strconv.ParseUint(fields[17], 10, 32)
	pages, e3 := strconv.ParseUint(fields[21], 10, 64)
	if e1 != nil || e2 != nil || e3 != nil || pages > (1<<53-1)/uint64(os.Getpagesize()) {
		return zero, ErrProcessUnavailable
	}
	return artifact.ProcessRecord{Identity: artifact.ProcessIdentity{PodUID: r.Pin.UID, NodeBootID: r.NodeBootID, RuntimeID: m.ID, RestartCount: m.RestartCount, HostPID: pid, StartTimeTicks: start, CgroupPath: cgroup, CgroupID: native.Ino}, NamespacePID: uint32(namespacePID), ObservedAt: s.now().UTC(), ParentPID: uint32(ppid), Main: pid == m.MainPID, State: fields[0], UID: uint32(uid), Threads: uint32(threads), RSSBytes: pages * uint64(os.Getpagesize()), ExecutablePath: exe}, nil
}

func processStat(b []byte, pid uint32) ([]string, uint64, error) {
	s := string(b)
	open := strings.IndexByte(s, '(')
	close := strings.LastIndex(s, ") ")
	if open < 2 || close <= open {
		return nil, 0, ErrProcessUnavailable
	}
	n, e := strconv.ParseUint(strings.TrimSpace(s[:open]), 10, 32)
	if e != nil || uint32(n) != pid {
		return nil, 0, ErrProcessChanged
	}
	v := strings.Fields(s[close+2:])
	if len(v) < 22 {
		return nil, 0, ErrProcessUnavailable
	}
	ticks, e := strconv.ParseUint(v[19], 10, 64)
	if e != nil || ticks == 0 {
		return nil, 0, ErrProcessUnavailable
	}
	return v, ticks, nil
}

func processCgroup(b []byte) (string, error) {
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "0::") {
		return "", ErrProcessUnavailable
	}
	v := strings.TrimPrefix(lines[0], "0::")
	if path.Clean(v) != v || v == "/" || !strings.HasPrefix(v, "/") || strings.Contains(v, "\\") {
		return "", ErrProcessUnavailable
	}
	return v, nil
}

func (s *ProcessSnapshots) memberPIDs(ctx context.Context, cgroup string, limit int) ([]uint32, bool, error) {
	r, e := os.OpenRoot(s.cgroups)
	if e != nil {
		return nil, false, e
	}
	defer r.Close()
	queue := []string{strings.TrimPrefix(cgroup, "/")}
	ids := map[uint32]bool{}
	limited := false
	dirs := 0
	for len(queue) > 0 {
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
		if dirs == limit {
			limited = true
			break
		}
		dir := queue[0]
		queue = queue[1:]
		dirs++
		f, e := r.Open(dir + "/cgroup.procs")
		if e != nil {
			return nil, false, e
		}
		raw, e := io.ReadAll(io.LimitReader(f, 8193))
		f.Close()
		if e != nil {
			return nil, false, e
		}
		if len(raw) > 8192 {
			limited = true
			raw = raw[:8192]
			if i := strings.LastIndexByte(string(raw), '\n'); i >= 0 {
				raw = raw[:i]
			} else {
				raw = nil
			}
		}
		for _, p := range strings.Fields(string(raw)) {
			pid, e := strconv.ParseUint(p, 10, 32)
			if e != nil || pid <= 1 || pid > 4194304 {
				return nil, false, ErrProcessUnavailable
			}
			ids[uint32(pid)] = true
			if len(ids) > limit {
				limited = true
				break
			}
		}
		if len(ids) > limit {
			break
		}
		d, e := r.Open(dir)
		if e != nil {
			return nil, false, e
		}
		names, e := d.ReadDir(artifact.ProcessMaxRecords + 128)
		d.Close()
		if e != nil && e != io.EOF {
			return nil, false, e
		}
		if len(names) == artifact.ProcessMaxRecords+128 {
			limited = true
		}
		slices.SortFunc(names, func(a, b os.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
		for _, child := range names {
			if child.IsDir() {
				if len(queue) >= limit {
					limited = true
					break
				}
				queue = append(queue, dir+"/"+child.Name())
			}
		}
	}
	out := make([]uint32, 0, len(ids))
	for id := range ids {
		out = append(out, id)
	}
	slices.Sort(out)
	if len(out) > limit {
		out = out[:limit]
	}
	return out, limited, nil
}
