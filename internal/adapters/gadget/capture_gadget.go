//go:build gadget && linux

package gadget

import (
	"bytes"
	"context"
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

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/socketenricher"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sys/unix"
	"oras.land/oras-go/v2/content/memory"
)

// pinnedBlob is one blob of the pinned gadget image.
type pinnedBlob struct {
	mediaType, digest string
	size              int64
}

var tcpdumpBlobs = []pinnedBlob{
	{ocispec.MediaTypeImageIndex, TcpdumpIndexDigest, TcpdumpIndexBytes},
	{ocispec.MediaTypeImageManifest, TcpdumpManifestDigest, TcpdumpManifestBytes},
	{"application/vnd.gadget.config.v1+yaml", TcpdumpConfigDigest, TcpdumpConfigBytes},
	{"application/vnd.gadget.ebpf.program.v1+binary", TcpdumpProgramDigest, TcpdumpProgramBytes},
}

// loadTcpdump reads the pinned blobs from the image into a memory OCI store
// and tags the index with the gadget's reference. The memory store verifies
// size and digest on push, so a changed file is refused before any load.
func loadTcpdump(ctx context.Context, dir string) (*memory.Store, error) {
	return loadPinned(ctx, dir, TcpdumpReference, TcpdumpIndexDigest, tcpdumpBlobs)
}

// podProcess finds one process of the pod on this node from the host process
// table (host PID namespace): the cgroup path of every container of a pod
// names the pod UID, with dashes (cgroupfs) or underscores (systemd driver).
// All containers of a pod share its network namespace, so any one will do;
// the lowest PID is preferred because a short-lived child (a forked request
// handler) can exit before the attach reads its namespace (collector-packet
// run 41280944426).
// ponytail: lowest PID approximates the longest-lived process; compare start
// times if PID wraparound ever matters.
func podProcess(proc, podUID string) (int, error) {
	marks := []string{"pod" + podUID, "pod" + strings.ReplaceAll(podUID, "-", "_")}
	entries, err := os.ReadDir(proc)
	if err != nil {
		return 0, ErrEngineUnavailable
	}
	found := 0
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 1 || found != 0 && pid >= found {
			continue
		}
		b, err := os.ReadFile(filepath.Join(proc, e.Name(), "cgroup"))
		if err != nil {
			continue
		}
		for _, m := range marks {
			if bytes.Contains(b, []byte(m)) {
				found = pid
				break
			}
		}
	}
	if found == 0 {
		return 0, ErrTargetNotFound
	}
	return found, nil
}

func netns(proc string, pid int) (string, error) {
	return os.Readlink(filepath.Join(proc, strconv.Itoa(pid), "ns", "net"))
}

// lossLogger forwards gadget log lines at warning level and above to w and
// counts the perf reader's lost samples, which the engine reports only as a
// log line ("reading event: lost %d samples").
type lossLogger struct {
	mu     sync.Mutex
	level  logger.Level
	lost   atomic.Uint64
	w      io.Writer
	lines  int
	notice func(InputNotice)
}

func (l *lossLogger) SetLevel(level logger.Level) { l.mu.Lock(); l.level = level; l.mu.Unlock() }
func (l *lossLogger) GetLevel() logger.Level      { l.mu.Lock(); defer l.mu.Unlock(); return l.level }
func (l *lossLogger) Log(severity logger.Level, params ...any) {
	l.Logf(severity, "%s", fmt.Sprint(params...))
}
func (l *lossLogger) Logf(severity logger.Level, format string, params ...any) {
	if format == "reading event: lost %d samples" && len(params) == 1 {
		if n, ok := params[0].(uint64); ok {
			l.lost.Add(n)
			if n > 0 && l.notice != nil {
				l.notice(InputNotice{LostSamples: n})
			}
			return
		}
	}
	// Match the pinned tracer's fixed formats, never the provider arguments.
	// Notice before formatting or the bounded diagnostic log; saturated logging
	// must not suppress a stop. The callback must not join its own engine.
	if l.notice != nil && (format == "error reading event: %v" || format == "error processing event: %v") {
		l.notice(InputNotice{})
		return
	}
	if severity > logger.WarnLevel {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	// Bound the log: a capture never writes more than 32 engine lines.
	if l.lines < 32 {
		l.lines++
		fmt.Fprintf(l.w, "packet engine: "+format+"\n", params...)
	}
}

// CapturePackets runs the pinned tcpdump gadget on the pod's network
// interfaces until ctx ends. The gadget attaches its classifier programs
// (ingress and egress) to the host side of each of the pod's veth pairs from
// the host network namespace, which it enters itself; the collector Pod keeps
// its own network namespace. deliver receives every frame the gadget emits, in
// order, from one goroutine; it must not retain Data. No filter is passed to
// the gadget: the hub-compiled program runs on each frame in user space
// (internal/adapters/packets), so the kernel never runs a second compiler's
// output (S2).
func CapturePackets(ctx context.Context, podUID string, snaplen int, deliver func(Frame)) (CaptureStats, error) {
	return CaptureObservedPackets(ctx, podUID, snaplen, deliver, nil)
}

// CaptureObservedPackets adds input-gap notifications for metered capture.
// Notifications and packet delivery are serialized. A non-nil notice callback
// additionally requires the complete requested prefix and decoded input fields;
// ordinary CapturePackets retains its existing behavior. This does not itself
// authorize collection or implement a meter.
func CaptureObservedPackets(ctx context.Context, podUID string, snaplen int, deliver func(Frame), notice func(InputNotice)) (CaptureStats, error) {
	var stats CaptureStats
	if snaplen <= 0 || snaplen > 1500 || deliver == nil {
		return stats, ErrEngineUnavailable
	}
	proc := "/proc"
	pid, err := podProcess(proc, podUID)
	if err != nil {
		return stats, err
	}
	target, err := netns(proc, pid)
	if err != nil {
		return stats, fmt.Errorf("%w: pod network namespace: %v", ErrEngineUnavailable, err)
	}
	if host, err := netns(proc, 1); err != nil || host == target {
		if err != nil {
			return stats, fmt.Errorf("%w: host network namespace: %v", ErrEngineUnavailable, err)
		}
		return stats, ErrTargetHostNetwork
	}
	store, err := loadTcpdump(ctx, TcpdumpBlobs)
	if err != nil {
		return stats, err
	}
	clock, err := newPacketClock(time.Now, readPacketMonotonic)
	if err != nil {
		return stats, fmt.Errorf("%w: packet clock", ErrEngineUnavailable)
	}
	var delivered sync.Mutex
	log := &lossLogger{level: logger.WarnLevel, w: os.Stderr}
	if notice != nil {
		log.notice = func(n InputNotice) { delivered.Lock(); defer delivered.Unlock(); notice(n) }
	}
	var attachErr error
	capture := simple.New("asservat",
		simple.WithPriority(10000),
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			ds := gadgetCtx.GetDataSources()["packets"]
			if ds == nil {
				return ErrEngineUnavailable
			}
			payload, size, raw := ds.GetField("payload"), ds.GetField("packet_size"), ds.GetField("timestamp_raw")
			direction := ds.GetField("packet_type")
			if payload == nil || size == nil || raw == nil {
				return ErrEngineUnavailable
			}
			return ds.Subscribe(func(_ datasource.DataSource, data datasource.Data) error {
				b, payloadErr := payload.Bytes(data)
				wire, wireErr := size.Uint32(data)
				ts, timeErr := raw.Uint64(data)
				delivered.Lock()
				defer delivered.Unlock()
				if notice != nil && (payloadErr != nil || wireErr != nil || timeErr != nil || !completePrefix(len(b), wire, snaplen)) {
					notice(InputNotice{})
					return nil
				}
				if payloadErr != nil {
					return nil
				}
				metadata := Frame{}
				if direction != nil {
					value, e := direction.Uint8(data)
					metadata.DirectionKnown = e == nil && value <= 1
					metadata.Ingress = value == 1
				}
				clock.deliver(b, wire, ts, notice, deliver, metadata)
				return nil
			}, 10000)
		}),
		simple.OnStart(func(gadgetCtx operators.GadgetContext) error {
			v, ok := gadgetCtx.GetVar("ebpfInstance")
			attacher, ok2 := v.(interface {
				AttachContainer(*containercollection.Container) error
			})
			if !ok || !ok2 {
				attachErr = ErrEngineUnavailable
				return attachErr
			}
			c := &containercollection.Container{}
			c.Runtime.ContainerPID = uint32(pid)
			if err := attacher.AttachContainer(c); err != nil {
				attachErr = fmt.Errorf("attaching to the pod's interfaces: %w", err)
				return attachErr
			}
			return nil
		}),
	)
	// The gadget's classifier looks packets up in Inspektor Gadget's socket
	// map, whose layout the socket enricher operator supplies (CO-RE
	// relocation target). It is Inspektor Gadget's own operator, refcounted
	// for the gadget's lifetime; its optional cwd/exepath fields are off, and
	// the PCAPNG never contains its process attribution.
	enricher := &socketenricher.SocketEnricher{}
	enricherParams := enricher.GlobalParamDescs().ToParams()
	if err := enricherParams.Set("socket-enricher-fields", ""); err != nil {
		return stats, fmt.Errorf("%w: socket enricher parameters: %v", ErrEngineUnavailable, err)
	}
	if err := enricher.Init(enricherParams); err != nil {
		return stats, fmt.Errorf("%w: socket enricher: %v", ErrEngineUnavailable, err)
	}
	defer enricher.Close()
	gadgetCtx := gadgetcontext.New(ctx, TcpdumpReference,
		gadgetcontext.WithDataOperators(ocihandler.OciHandler, enricher, capture),
		gadgetcontext.WithOrasReadonlyTarget(store),
		gadgetcontext.WithLogger(logger.NewFromGenericLogger(log)),
	)
	runtime := local.New()
	if err := runtime.Init(nil); err != nil {
		return stats, fmt.Errorf("%w: local runtime: %v", ErrEngineUnavailable, err)
	}
	defer runtime.Close()
	err = runtime.RunGadget(gadgetCtx, nil, map[string]string{"operator.oci.ebpf.snaplen": strconv.Itoa(snaplen)})
	stats.LostSamples = log.lost.Load()
	delivered.Lock()
	invalidTime := clock.invalid
	delivered.Unlock()
	if invalidTime {
		return stats, fmt.Errorf("%w: invalid packet timestamp", ErrEngineUnavailable)
	}

	if attachErr != nil {
		return stats, attachErr
	}
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		return stats, fmt.Errorf("running the packet gadget: %w", err)
	}
	return stats, nil
}

func readPacketMonotonic() (int64, error) {
	var t unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &t); err != nil {
		return 0, err
	}
	return packetMonotonicNanos(int64(t.Sec), int64(t.Nsec))
}
