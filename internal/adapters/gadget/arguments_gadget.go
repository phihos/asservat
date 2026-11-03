//go:build gadget && linux

package gadget

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
)

type argumentMembership struct{ group, namespace uint64 }
type argumentPins struct{ group, namespace *os.File }

func (p argumentPins) close() { _ = p.group.Close(); _ = p.namespace.Close() }

func argumentCgroupPath(raw, pod string) (string, bool) {
	for _, line := range strings.Split(raw, "\n") {
		if !strings.HasPrefix(line, "0::/") {
			continue
		}
		path := strings.TrimPrefix(line, "0::")
		if filepath.Clean(path) != path || strings.Contains(path, "..") {
			return "", false
		}
		for _, marker := range []string{"pod" + pod, "pod" + strings.ReplaceAll(pod, "-", "_")} {
			at := strings.Index(path, marker)
			if at < 0 {
				continue
			}
			tail := path[at+len(marker):]
			if tail == "" || strings.HasPrefix(tail, "/") || strings.HasPrefix(tail, ".slice/") || tail == ".slice" {
				return path, true
			}
		}
	}
	return "", false
}
func argumentProcessStart(proc, pid string) (string, error) {
	b, err := os.ReadFile(filepath.Join(proc, pid, "stat"))
	if err != nil {
		return "", err
	}
	i := strings.LastIndex(string(b), ") ")
	if i < 0 {
		return "", ErrTargetNotFound
	}
	fields := strings.Fields(string(b[i+2:]))
	if len(fields) <= 19 {
		return "", ErrTargetNotFound
	}
	if n, err := strconv.ParseUint(fields[19], 10, 64); err != nil || n == 0 {
		return "", ErrTargetNotFound
	}
	return fields[19], nil
}
func argumentInode(f *os.File) (uint64, error) {
	var s unix.Stat_t
	err := unix.Fstat(int(f.Fd()), &s)
	return s.Ino, err
}

// Keep namespace/cgroup FDs open: removal cannot reuse their inode identities
// while an admitted map entry remains. A second cgroup+start read detects PID
// replacement across open; kernel cgroup membership is checked before reads.
func argumentCgroupID(f *os.File) (uint64, error) {
	var fs unix.Statfs_t
	if err := unix.Fstatfs(int(f.Fd()), &fs); err != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return 0, ErrEngineUnavailable
	}
	// Same64-bit file handle as upstream Gadget/kernel BPF selftests, resolved
	// from the pinned FD rather than an independently replaceable pathname.
	h, _, err := unix.NameToHandleAt(int(f.Fd()), "", unix.AT_EMPTY_PATH)
	if err != nil || h.Size() != 8 {
		return 0, ErrEngineUnavailable
	}
	return binary.LittleEndian.Uint64(h.Bytes()), nil
}
func argumentMembers(ctx context.Context, proc, cgroups, pod string) (map[argumentMembership]argumentPins, error) {
	return scanArgumentMembers(ctx, proc, cgroups, pod, argumentCgroupID)
}
func scanArgumentMembers(ctx context.Context, proc, cgroups, pod string, cgroupID func(*os.File) (uint64, error)) (out map[argumentMembership]argumentPins, err error) {
	out = map[argumentMembership]argumentPins{}
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	defer func() {
		if err != nil {
			for _, p := range out {
				p.close()
			}
		}
	}()
	host, e := mountNamespace(proc, 1)
	if e != nil {
		return out, e
	}
	directory, e := os.Open(proc)
	if e != nil {
		return out, e
	}
	defer directory.Close()
	for {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		entries, readErr := directory.ReadDir(128)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return out, readErr
		}
		for _, entry := range entries {
			if ctx.Err() != nil {
				return out, ctx.Err()
			}
			pid := entry.Name()
			if n, e := strconv.Atoi(pid); e != nil || n <= 1 {
				continue
			}
			raw, e := os.ReadFile(filepath.Join(proc, pid, "cgroup"))
			if e != nil {
				continue
			}
			path, match := argumentCgroupPath(string(raw), pod)
			if !match {
				continue
			}
			before, e := argumentProcessStart(proc, pid)
			if e != nil {
				continue
			}
			ns, e := os.Open(filepath.Join(proc, pid, "ns/mnt"))
			if e != nil {
				continue
			}
			group, e := os.Open(filepath.Join(cgroups, strings.TrimPrefix(path, "/")))
			if e != nil {
				_ = ns.Close()
				return out, ErrTargetNotFound
			}
			pins := argumentPins{group, ns}
			nsID, e1 := argumentInode(ns)
			groupID, e2 := cgroupID(group)
			after, e3 := argumentProcessStart(proc, pid)
			again, e4 := os.ReadFile(filepath.Join(proc, pid, "cgroup"))
			if e1 != nil || e2 != nil || e3 != nil || e4 != nil || before != after || !bytes.Equal(raw, again) || nsID == host || nsID == 0 || groupID == 0 {
				pins.close()
				continue
			}
			key := argumentMembership{groupID, nsID}
			if _, exists := out[key]; exists {
				pins.close()
				continue
			}
			if len(out) >= 128 {
				pins.close()
				return out, ErrEngineUnavailable
			}
			out[key] = pins
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
	}
	return out, nil
}

func traceArguments(parent context.Context, r ArgumentRequest, deliver func([]byte), notice func(InputNotice)) (stats ArgumentStats, err error) {
	stats.ReservedEvents, stats.ReservedBytes = r.Events, r.Bytes
	stats.CoverageUnknown = true // upstream map/record emission failures have no complete counter
	defs, err := r.definitions()
	if err != nil {
		return stats, err
	}
	ctx, cancel := context.WithDeadline(parent, r.Deadline)
	defer cancel()
	if ctx.Err() != nil {
		return stats, ctx.Err()
	}
	file, err := os.Open(ArgumentObjectPath)
	if err != nil {
		return stats, ErrEngineUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(file, ArgumentObjectBytes+1))
	_ = file.Close()
	if err != nil || len(raw) != ArgumentObjectBytes || fmt.Sprintf("%x", sha256.Sum256(raw)) != ArgumentObjectSHA256 {
		return stats, ErrEngineUnavailable
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(raw))
	if err != nil {
		return stats, ErrEngineUnavailable
	}
	if len(spec.Programs) != 2 || spec.Programs["ig_traceloop_e"] == nil || spec.Programs["ig_traceloop_x"] == nil || spec.Maps["asservat_budget"] == nil || spec.Maps["asservat_budget"].ValueSize != 64 || spec.Maps["asservat_cgroups"] == nil {
		return stats, ErrEngineUnavailable
	}
	cpus, err := ebpf.PossibleCPU()
	if err != nil || cpus < 1 || cpus > 256 {
		return stats, ErrEngineUnavailable
	}
	outer := spec.Maps["map_of_perf_buffers"]
	if outer == nil || outer.InnerMap == nil {
		return stats, ErrEngineUnavailable
	}
	outer.InnerMap.MaxEntries = uint32(cpus)
	outer.MaxEntries = 128
	for _, name := range []string{"probe_at_sys_exit", "regs_map"} {
		if spec.Maps[name] == nil {
			return stats, ErrEngineUnavailable
		}
		spec.Maps[name].MaxEntries = uint32(r.MaxTrackedThreads)
	}
	members, err := argumentMembers(ctx, "/proc", "/sys/fs/cgroup", r.PodUID)
	if err != nil || len(members) == 0 {
		return stats, ErrTargetNotFound
	}
	defer func() {
		for _, p := range members {
			p.close()
		}
	}()
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return stats, fmt.Errorf("%w: argument object or CO-RE unsupported: %v", ErrEngineUnavailable, err)
	}
	defer collection.Close()
	inner, err := ebpf.NewMap(outer.InnerMap)
	if err != nil {
		return stats, err
	}
	defer inner.Close()
	reader, err := perf.NewReader(inner, 8*os.Getpagesize())
	if err != nil {
		return stats, err
	}
	defer reader.Close()
	zero := uint32(0)
	for _, d := range defs {
		if err = collection.Maps["syscalls"].Put(uint64(d.Number), d.Lengths); err != nil {
			return stats, err
		}
		if err = collection.Maps["syscall_filters"].Put(uint64(d.Number), uint8(1)); err != nil {
			return stats, err
		}
	}
	if err = collection.Maps["syscall_enable_filters"].Put(zero, uint8(1)); err != nil {
		return stats, err
	}
	var boot unix.Timespec
	if err = unix.ClockGettime(unix.CLOCK_BOOTTIME, &boot); err != nil {
		return stats, err
	}
	initial, err := ArgumentBudgetFor(r, time.Now(), uint64(boot.Nano()))
	if err != nil {
		return stats, err
	}
	if err = collection.Maps["asservat_budget"].Put(zero, initial); err != nil {
		return stats, err
	}
	for _, name := range []string{"asservat_budget", "syscalls", "syscall_filters", "syscall_enable_filters"} {
		if err = collection.Maps[name].Freeze(); err != nil {
			return stats, err
		}
	}
	reconcile := func(next map[argumentMembership]argumentPins) error {
		groups, namespaces := map[uint64]bool{}, map[uint64]bool{}
		for key := range next {
			groups[key.group] = true
			namespaces[key.namespace] = true
		}
		for key := range members {
			if !groups[key.group] {
				if e := collection.Maps["asservat_cgroups"].Delete(key.group); e != nil && !errors.Is(e, ebpf.ErrKeyNotExist) {
					return e
				}
			}
			if !namespaces[key.namespace] {
				if e := collection.Maps["map_of_perf_buffers"].Delete(key.namespace); e != nil && !errors.Is(e, ebpf.ErrKeyNotExist) {
					return e
				}
			}
		}
		for key := range next {
			if e := collection.Maps["asservat_cgroups"].Put(key.group, uint8(1)); e != nil {
				return e
			}
			if e := collection.Maps["map_of_perf_buffers"].Put(key.namespace, uint32(inner.FD())); e != nil {
				return e
			}
		}
		return nil
	}
	if err = reconcile(members); err != nil {
		return stats, err
	}
	var links []link.Link
	defer func() {
		for _, l := range links {
			_ = l.Close()
		}
	}()
	for _, p := range [][2]string{{"sys_enter", "ig_traceloop_e"}, {"sys_exit", "ig_traceloop_x"}} {
		if ctx.Err() != nil || !time.Now().Before(r.Deadline) {
			return stats, context.DeadlineExceeded
		}
		l, e := link.AttachRawTracepoint(link.RawTracepointOptions{Name: p[0], Program: collection.Programs[p[1]]})
		if e != nil {
			return stats, e
		}
		links = append(links, l)
	}
	var mu sync.Mutex
	var lost atomic.Uint64
	var joined sync.WaitGroup
	readErrors := make(chan error, 1)
	joined.Add(1)
	go func() {
		defer joined.Done()
		for {
			record, e := reader.Read()
			if e != nil {
				if !errors.Is(e, perf.ErrClosed) && !errors.Is(e, perf.ErrFlushed) {
					select {
					case readErrors <- e:
					default:
					}
				}
				return
			}
			mu.Lock()
			if record.LostSamples > 0 {
				lost.Add(record.LostSamples)
				if notice != nil {
					notice(InputNotice{LostSamples: record.LostSamples})
				}
			} else {
				deliver(record.RawSample)
				clear(record.RawSample)
			}
			mu.Unlock()
		}
	}()
	defer func() {
		for _, l := range links {
			_ = l.Close()
		}
		links = nil
		_ = reader.Close()
		joined.Wait()
		stats.LostSamples = lost.Load()
	}()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	stats.ReservedEvents, stats.ReservedBytes = r.Events, r.Bytes
	for {
		select {
		case <-ctx.Done():
			err = ctx.Err()
		case err = <-readErrors:
		case <-tick.C:
			var current ArgumentBudget
			if err = collection.Maps["asservat_budget"].Lookup(zero, &current); err != nil || current.Stopped != 0 {
				break
			}
			var next map[argumentMembership]argumentPins
			next, err = argumentMembers(ctx, "/proc", "/sys/fs/cgroup", r.PodUID)
			if err == nil {
				err = reconcile(next)
			}
			if err != nil {
				for _, p := range next {
					p.close()
				}
				break
			}
			changed := len(next) != len(members)
			for key := range next {
				if _, ok := members[key]; !ok {
					changed = true
				}
			}
			for _, p := range members {
				p.close()
			}
			members = next
			mu.Lock()
			if changed {
				stats.CoverageUnknown = true
				if notice != nil {
					notice(InputNotice{})
				}
			}
			mu.Unlock()
			continue
		}
		break
	}
	// Detach before reading final spend. No refund follows a missing final lookup.
	for _, l := range links {
		if e := l.Close(); err == nil {
			err = e
		}
	}
	links = nil
	var final ArgumentBudget
	if e := collection.Maps["asservat_budget"].Lookup(zero, &final); e != nil {
		return stats, e
	}
	if final.Events > initial.Events || final.Bytes > initial.Bytes {
		return stats, ErrEngineUnavailable
	}
	mu.Lock()
	stats.AccountingKnown = true
	stats.ConsumedEvents = initial.Events - final.Events
	stats.ConsumedBytes = initial.Bytes - final.Bytes
	stats.Stopped = final.Stopped != 0
	mu.Unlock()
	if flushErr := reader.Flush(); flushErr != nil {
		_ = reader.Close()
		if err == nil {
			err = flushErr
		}
	}
	joined.Wait()
	stats.LostSamples = lost.Load()
	return stats, err
}
