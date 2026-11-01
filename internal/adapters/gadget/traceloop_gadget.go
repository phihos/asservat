//go:build gadget && linux

package gadget

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content/memory"
)

var traceloopBlobs = []pinnedBlob{
	{ocispec.MediaTypeImageIndex, TraceloopIndexDigest, TraceloopIndexBytes},
	{ocispec.MediaTypeImageManifest, TraceloopManifestDigest, TraceloopManifestBytes},
	{"application/vnd.gadget.config.v1+yaml", TraceloopConfigDigest, TraceloopConfigBytes},
	{"application/vnd.gadget.ebpf.program.v1+binary", TraceloopProgramDigest, TraceloopProgramBytes},
}

// ErrUserMemoryDefinitions: the loaded program carries syscall argument
// definitions, which would make it read user memory. Metadata mode refuses.
var ErrUserMemoryDefinitions = errors.New("syscall engine carries argument definitions")

// loadPinned reads pinned blobs into a memory OCI store and tags the index.
// The memory store verifies size and digest on push, so a changed file is
// refused before any load.
func loadPinned(ctx context.Context, dir, reference, indexDigest string, blobs []pinnedBlob) (*memory.Store, error) {
	store := memory.New()
	for _, b := range blobs {
		hexDigest := strings.TrimPrefix(b.digest, "sha256:")
		raw, err := os.ReadFile(filepath.Join(dir, "blobs", "sha256", hexDigest))
		if err != nil || int64(len(raw)) != b.size {
			return nil, fmt.Errorf("%w: pinned blob %s: %v", ErrEngineUnavailable, b.digest, err)
		}
		if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != hexDigest {
			return nil, fmt.Errorf("%w: pinned blob %s digest", ErrEngineUnavailable, b.digest)
		}
		desc := ocispec.Descriptor{MediaType: b.mediaType, Digest: digest.Digest(b.digest), Size: b.size}
		if err := store.Push(ctx, desc, bytes.NewReader(raw)); err != nil {
			return nil, fmt.Errorf("%w: pinned blob %s: %v", ErrEngineUnavailable, b.digest, err)
		}
		if b.digest == indexDigest {
			if err := store.Tag(ctx, desc, reference); err != nil {
				return nil, fmt.Errorf("%w: tag %s: %v", ErrEngineUnavailable, reference, err)
			}
		}
	}
	return store, nil
}

// podMountNamespaces returns the mount namespace IDs of the pod's processes
// on this node (each container has its own); the host's is refused.
func podMountNamespaces(proc, podUID string) (map[uint64]bool, error) {
	marks := []string{"pod" + podUID, "pod" + strings.ReplaceAll(podUID, "-", "_")}
	host, err := mountNamespace(proc, 1)
	if err != nil {
		return nil, ErrEngineUnavailable
	}
	entries, err := os.ReadDir(proc)
	if err != nil {
		return nil, ErrEngineUnavailable
	}
	out := map[uint64]bool{}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 1 {
			continue
		}
		b, err := os.ReadFile(filepath.Join(proc, e.Name(), "cgroup"))
		if err != nil {
			continue
		}
		for _, m := range marks {
			if bytes.Contains(b, []byte(m)) {
				if ns, err := mountNamespace(proc, pid); err == nil && ns != host {
					out[ns] = true
				}
				break
			}
		}
	}
	if len(out) == 0 {
		return nil, ErrTargetNotFound
	}
	return out, nil
}

// mountNamespace parses "mnt:[4026531841]".
func mountNamespace(proc string, pid int) (uint64, error) {
	link, err := os.Readlink(filepath.Join(proc, strconv.Itoa(pid), "ns", "mnt"))
	if err != nil || !strings.HasPrefix(link, "mnt:[") || !strings.HasSuffix(link, "]") {
		return 0, ErrEngineUnavailable
	}
	return strconv.ParseUint(link[5:len(link)-1], 10, 64)
}

// TraceSyscalls runs the pinned traceloop program for the pod's containers
// until ctx ends and hands deliver every raw syscall_event_t record, in
// order, from one goroutine (it must not retain the slice). numbers, when
// non-empty, restricts tracing to those syscall numbers in the kernel. The
// pod's mount namespaces are rescanned every second, so a restarted
// container keeps being traced. Lost perf samples are reported as notices.
func TraceSyscalls(ctx context.Context, podUID string, numbers []uint16, deliver func([]byte), notice func(InputNotice)) (CaptureStats, error) {
	var stats CaptureStats
	if deliver == nil || len(numbers) > 16 {
		return stats, ErrEngineUnavailable
	}
	proc := "/proc"
	if _, err := podMountNamespaces(proc, podUID); err != nil {
		return stats, err
	}
	store, err := loadPinned(ctx, TraceloopBlobs, TraceloopReference, TraceloopIndexDigest, traceloopBlobs)
	if err != nil {
		return stats, err
	}
	var (
		mu      sync.Mutex // serializes deliver/notice
		lost    uint64
		startEr error
		wg      sync.WaitGroup
	)
	run, cancel := context.WithCancel(ctx)
	defer cancel()
	trace := simple.New("asservat-syscalls",
		simple.WithPriority(10000),
		simple.OnStart(func(gadgetCtx operators.GadgetContext) error {
			outer, ok1 := gadgetCtx.GetVar(operators.MapPrefix + "map_of_perf_buffers")
			defs, ok2 := gadgetCtx.GetVar(operators.MapPrefix + "syscalls")
			perfMaps, ok3 := outer.(*ebpf.Map)
			defMap, ok4 := defs.(*ebpf.Map)
			if !ok1 || !ok2 || !ok3 || !ok4 {
				startEr = fmt.Errorf("%w: traceloop maps (perf buffers %t/%t, definitions %t/%t)", ErrEngineUnavailable, ok1, ok3, ok2, ok4)
				return startEr
			}
			// Metadata mode: no argument definitions, so no user-memory reads.
			var key uint64
			var value [48]byte
			it := defMap.Iterate()
			if it.Next(&key, &value) || it.Err() != nil {
				startEr = ErrUserMemoryDefinitions
				return startEr
			}
			if len(numbers) > 0 {
				filters, okF := gadgetCtx.GetVar(operators.MapPrefix + "syscall_filters")
				enable, okE := gadgetCtx.GetVar(operators.MapPrefix + "syscall_enable_filters")
				fm, okF2 := filters.(*ebpf.Map)
				em, okE2 := enable.(*ebpf.Map)
				if !okF || !okE || !okF2 || !okE2 {
					startEr = fmt.Errorf("%w: traceloop syscall filter maps", ErrEngineUnavailable)
					return startEr
				}
				for _, n := range numbers {
					if err := fm.Put(uint64(n), true); err != nil {
						startEr = fmt.Errorf("%w: syscall filter %d: %v", ErrEngineUnavailable, n, err)
						return startEr
					}
				}
				if err := em.Put(uint32(0), true); err != nil {
					startEr = fmt.Errorf("%w: enabling the syscall filter: %v", ErrEngineUnavailable, err)
					return startEr
				}
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				traceNamespaces(run, proc, podUID, perfMaps, func(raw []byte, lostNow uint64) {
					mu.Lock()
					defer mu.Unlock()
					if raw == nil && lostNow == 0 {
						// A late-attached namespace: its calls before the
						// attach are unknown, a gap of unknown size.
						if notice != nil {
							notice(InputNotice{})
						}
						return
					}
					if lostNow > 0 {
						lost += lostNow
						if notice != nil {
							notice(InputNotice{LostSamples: lostNow})
						}
						return
					}
					deliver(raw)
				})
			}()
			return nil
		}),
	)
	log := &lossLogger{level: logger.WarnLevel, w: os.Stderr}
	gadgetCtx := gadgetcontext.New(run, TraceloopReference,
		gadgetcontext.WithDataOperators(ocihandler.OciHandler, trace),
		gadgetcontext.WithOrasReadonlyTarget(store),
		gadgetcontext.WithLogger(logger.NewFromGenericLogger(log)),
	)
	rt := local.New()
	if err := rt.Init(nil); err != nil {
		return stats, fmt.Errorf("%w: local runtime: %v", ErrEngineUnavailable, err)
	}
	defer rt.Close()
	err = rt.RunGadget(gadgetCtx, nil, nil)
	cancel()
	wg.Wait()
	mu.Lock()
	stats.LostSamples = lost
	mu.Unlock()
	if startEr != nil {
		return stats, startEr
	}
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		return stats, fmt.Errorf("running the syscall gadget: %w", err)
	}
	return stats, nil
}

// traceNamespaces keeps one perf array per pod mount namespace in the
// program's map_of_perf_buffers and forwards their records until ctx ends.
func traceNamespaces(ctx context.Context, proc, podUID string, outer *ebpf.Map, emit func([]byte, uint64)) {
	type traced struct {
		inner  *ebpf.Map
		reader *perf.Reader
	}
	active := map[uint64]*traced{}
	failed := map[uint64]bool{} // namespaces whose failure was already logged
	scanned := false            // the first scan's namespaces are not late
	var readers sync.WaitGroup
	defer func() {
		for ns, t := range active {
			_ = outer.Delete(ns)
			_ = t.reader.Close()
			_ = t.inner.Close()
		}
		readers.Wait()
	}()
	scan := func() {
		current, err := podMountNamespaces(proc, podUID)
		if errors.Is(err, ErrTargetNotFound) {
			current = map[uint64]bool{} // every pod process is gone
		} else if err != nil {
			return // transient /proc failure: keep the existing readers
		}
		for ns, t := range active {
			if !current[ns] {
				_ = outer.Delete(ns)
				_ = t.reader.Close()
				_ = t.inner.Close()
				delete(active, ns)
			}
		}
		for ns := range current {
			if active[ns] != nil {
				continue
			}
			fail := func(step string, err error) {
				if !failed[ns] {
					failed[ns] = true
					fmt.Fprintf(os.Stderr, "syscall engine: mount namespace %d not traced: %s: %v\n", ns, step, err)
				}
			}
			inner, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.PerfEventArray, KeySize: 4, ValueSize: 4, MaxEntries: uint32(runtime.NumCPU())})
			if err != nil {
				fail("perf array", err)
				continue
			}
			reader, err := perf.NewReader(inner, 64*os.Getpagesize())
			if err != nil {
				_ = inner.Close()
				fail("perf reader", err)
				continue
			}
			if err := outer.Put(ns, uint32(inner.FD())); err != nil {
				_ = reader.Close()
				_ = inner.Close()
				fail("perf buffer map", err)
				continue
			}
			active[ns] = &traced{inner: inner, reader: reader}
			if scanned {
				// A container that started after the first scan was traced
				// up to one rescan late; report it as a gap, not quiet input.
				emit(nil, 0)
			}
			readers.Add(1)
			go func(r *perf.Reader) {
				defer readers.Done()
				for {
					rec, err := r.Read()
					if err != nil {
						return
					}
					if rec.LostSamples > 0 {
						emit(nil, rec.LostSamples)
						continue
					}
					emit(rec.RawSample, 0)
				}
			}(reader)
		}
	}
	scan()
	scanned = true
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			scan()
		}
	}
}
