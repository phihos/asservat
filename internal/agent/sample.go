package agent

import (
	"bytes"
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unique"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/google/pprof/profile"
	"github.com/ianlancetaylor/demangle"
	"go.opentelemetry.io/ebpf-profiler/interpreter/interpreterconfig"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/processmanager"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/times"
	"go.opentelemetry.io/ebpf-profiler/tracer"
	corev1 "k8s.io/api/core/v1"

	"asservat.local/asservat/internal/api"
)

// A CPU profile of a pod is sampled from the node, so the application needs
// no profile endpoint and nothing is put into it. The sampling is done by
// the OpenTelemetry eBPF profiler, used as a library: programs in the kernel
// take the stack of whatever runs on each CPU, and unwind native code as
// well as the interpreters and virtual machines of Python, Java, Node.js,
// Ruby, PHP, Perl, .NET and Erlang. It samples the whole node; the agent
// keeps the samples of the pods that are being recorded and drops the rest.

// sampleRate is the number of samples per second and CPU: 99, as perf's
// examples use it, which gives a busy thread about 3000 samples in 30
// seconds and does not run in step with timers of 100 per second.
const sampleRate = 99

// tracefs is where the kernel tells the IDs of its tracepoints, which the
// profiler attaches to.
const tracefs = "/sys/kernel/tracing"

// sampledKind is what a sampled profile counts.
type sampledKind struct {
	recording string // the kind of recording that asks for it
	file      string
	// memory tells a profile of page faults from one of CPU samples.
	memory bool
	// count and amount name the two values of every stack: how often it
	// was seen, and what that stands for, each sample standing for unit.
	count, amount profile.ValueType
	unit          int64
	// nothing is what a pod without a sample is told.
	nothing string
}

var (
	// sampledCPU counts the samples taken of what runs on the CPUs.
	sampledCPU = sampledKind{
		recording: api.KindCPU, file: "sampled-cpu.pprof",
		count: profile.ValueType{Type: "samples", Unit: "count"}, amount: profile.ValueType{Type: "cpu", Unit: "nanoseconds"},
		unit:    int64(time.Second / sampleRate),
		nothing: "the pod's processes used no CPU time while they were sampled",
	}
	// sampledMemory counts page faults. The kernel gives a process a page of
	// memory when the process first touches it, which is a page fault: the
	// stacks at the faults are the code that makes the memory in use grow.
	// Every fault counts as one page of the usual size, also where the
	// kernel hands out a huge page.
	sampledMemory = sampledKind{
		recording: api.KindMemory, file: "sampled-memory.pprof", memory: true,
		count: profile.ValueType{Type: "page_faults", Unit: "count"}, amount: profile.ValueType{Type: "memory", Unit: "bytes"},
		unit:    int64(os.Getpagesize()),
		nothing: "the pod's processes took no new memory while they were watched",
	}
)

// sampler runs the profiler while at least one recording wants samples.
type sampler struct {
	// running guards the profiler's start and stop, which take seconds and
	// during which the profiler goes on reporting.
	running sync.Mutex
	tracer  *tracer.Tracer
	cancel  func()
	// cpus tells that the CPUs are sampled, which the first profile of CPU
	// time turns on until the profiler stops.
	cpus bool
	// faults reports page faults while a profile of memory wants them.
	faults *faultProbe
	// mu guards what the profiler's reports change.
	mu       sync.Mutex
	profiles map[*sampledProfile]struct{}
	// binaries are the executables and libraries the profiler has seen
	// mapped, by the ID it gives them: where to read their symbols from.
	binaries map[libpf.FileID]mappedFile
}

// mappedFile is a mapped file: its path as the process sees it, and that process.
type mappedFile struct {
	pid  int
	path string
}

// sampledProfile collects the samples of one kind of one pod.
type sampledProfile struct {
	kind       sampledKind
	containers map[string]bool // the pod's container IDs
	pids       map[int]bool    // its processes when the sampling began
	// stacks holds every stack once, and seconds how often each was seen
	// by the second: a busy process shows the same stacks second after
	// second. A profile that is kept running for a watch drops the seconds
	// that lie further back than its window, and with them the stacks that
	// no second counts any more; window 0 keeps all.
	stacks  map[stackKey]*sampledStack
	seconds map[int64]map[stackKey]int64
	window  time.Duration
}

func newSampledProfile(kind sampledKind, window time.Duration) *sampledProfile {
	return &sampledProfile{kind: kind, window: window, containers: map[string]bool{}, pids: map[int]bool{}, stacks: map[stackKey]*sampledStack{}, seconds: map[int64]map[stackKey]int64{}}
}

// add counts a stack seen at a moment; stack makes it if the profile does
// not hold it yet. The caller holds the sampler's lock.
func (p *sampledProfile) add(key stackKey, at time.Time, stack func() *sampledStack) {
	second := at.Unix()
	counts := p.seconds[second]
	if counts == nil {
		counts = map[stackKey]int64{}
		p.seconds[second] = counts
		// A new second begins: those out of the window go.
		if p.window > 0 {
			for old, counted := range p.seconds {
				if old >= second-int64(p.window/time.Second) {
					continue
				}
				for key := range counted {
					if held := p.stacks[key]; held.seconds > 1 {
						held.seconds--
					} else {
						delete(p.stacks, key)
					}
				}
				delete(p.seconds, old)
			}
		}
	}
	if _, counted := counts[key]; !counted {
		held := p.stacks[key]
		if held == nil {
			held = stack()
			p.stacks[key] = held
		}
		held.seconds++
	}
	counts[key]++
}

// since returns the stacks seen from a moment on, each with how often. The
// caller holds the sampler's lock, or the profile is no longer sampled.
func (p *sampledProfile) since(from time.Time) map[stackKey]*sampledStack {
	all := map[stackKey]*sampledStack{}
	for second, counts := range p.seconds {
		if second < from.Unix() {
			continue
		}
		for key, count := range counts {
			sum := all[key]
			if sum == nil {
				whole := *p.stacks[key]
				sum = &whole
				all[key] = sum
			}
			sum.count += count
		}
	}
	return all
}

// cover adds the pod's containers and processes to those whose samples the
// profile takes: a restarted container is a new one.
func (a *Agent) cover(p *sampledProfile, pod *corev1.Pod, known *processes) {
	var added []string
	a.sampler.mu.Lock()
	for _, status := range slices.Concat(pod.Status.InitContainerStatuses, pod.Status.ContainerStatuses, pod.Status.EphemeralContainerStatuses) {
		if _, id, ok := strings.Cut(status.ContainerID, "://"); ok && !p.containers[id] {
			p.containers[id] = true
			added = append(added, id)
		}
	}
	a.sampler.mu.Unlock()
	// Their processes are looked for without the lock: that reads a file of
	// every process on the node, and every sample of the node waits for
	// the lock.
	var pids []int
	for _, id := range added {
		all, _, _ := known.of(a, pod, id)
		pids = append(pids, all...)
	}
	a.sampler.mu.Lock()
	defer a.sampler.mu.Unlock()
	for _, pid := range pids {
		p.pids[pid] = true
	}
}

type stackKey struct {
	trace libpf.TraceHash
	pid   int
}

// sampledStack is one stack of one process.
type sampledStack struct {
	frames libpf.Frames // the innermost first
	pid    int
	comm   string
	// count is how often it was seen in the time that was asked for; a
	// profile counts by the second instead.
	count int64
	// seconds is the number of a profile's seconds that count it.
	seconds int
}

// begin starts collecting the samples of a pod, and before that the
// profiler and what the profile's kind needs of it, unless they run.
func (s *sampler) begin(p *sampledProfile) error {
	s.running.Lock()
	defer s.running.Unlock()
	started := s.tracer == nil
	if started {
		if err := s.run(); err != nil {
			return err
		}
	}
	var err error
	switch {
	case p.kind.memory:
		// The probe is kept once it is loaded, so that a failure is tried again.
		if s.faults == nil {
			probe := &faultProbe{}
			if err = s.tracer.Enable(context.Background(), probe); err == nil {
				s.faults = probe
			}
		}
		if err == nil {
			err = s.faults.attach()
		}
	case !s.cpus:
		err = s.tracer.EnableProfiling()
		s.cpus = err == nil
	}
	if err != nil {
		if started {
			s.halt()
		}
		return fmt.Errorf("the node's kernel does not let the profiler take these samples: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.profiles == nil {
		s.profiles = map[*sampledProfile]struct{}{}
	}
	s.profiles[p] = struct{}{}
	return nil
}

// end stops collecting for a pod. Page faults are reported until the last
// profile of memory ends, and the profiler runs until its last profile
// ends. It returns where the symbols of the binaries seen can be read.
func (s *sampler) end(p *sampledProfile) map[libpf.FileID]mappedFile {
	s.running.Lock()
	defer s.running.Unlock()
	s.mu.Lock()
	delete(s.profiles, p)
	memory := false
	for other := range s.profiles {
		memory = memory || other.kind.memory
	}
	last := len(s.profiles) == 0
	binaries := make(map[libpf.FileID]mappedFile, len(s.binaries))
	for id, b := range s.binaries {
		binaries[id] = b
	}
	s.mu.Unlock()
	if !memory && s.faults != nil {
		s.faults.Unload()
	}
	if last {
		s.halt()
	}
	return binaries
}

// halt stops the profiler and gives back what it held.
func (s *sampler) halt() {
	if s.faults != nil {
		s.faults.Unload()
		s.faults.release()
	}
	s.cancel()
	s.tracer.Close()
	s.tracer, s.cancel, s.faults, s.cpus = nil, nil, nil, false
	s.mu.Lock()
	s.binaries = nil
	s.mu.Unlock()
	// The profiler's Close leaves its programs and maps in the kernel, some
	// hundred megabytes that count as the agent's memory: it is made for a
	// process that ends. They go when the garbage collector finds their
	// handles unused, which an idle agent's collector does not do for a long
	// time. So it is told to, and to return the profiler's part of the heap
	// as well. The profiler's goroutines still hold it until they notice
	// that it stopped, some at once and some at their interval of 5 seconds,
	// and no event tells when the last has: the collector runs after 1, 7
	// and 19 seconds.
	go func() {
		for _, wait := range []time.Duration{time.Second, 6 * time.Second, 12 * time.Second} {
			time.Sleep(wait)
			debug.FreeOSMemory()
		}
	}()
}

// run loads the profiler's programs into the kernel. The order of the steps
// is the profiler's own (its collector receiver); sampling the CPUs and
// reporting page faults are turned on by the profiles that want them.
func (s *sampler) run() error {
	// A container's /sys comes without the tracepoints.
	if _, err := os.Stat(tracefs + "/events"); err != nil {
		if err := syscall.Mount("tracefs", tracefs, "tracefs", 0, ""); err != nil {
			return fmt.Errorf("the kernel's tracepoints cannot be reached (mount of %s: %w)", tracefs, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	times.StartRealtimeSync(ctx, 0)
	// The intervals at which the profiler looks after its own state: its defaults.
	intervals := times.New(5*time.Second, 5*time.Second, time.Minute)
	trc, err := tracer.NewTracer(ctx, &tracer.Config{
		TraceReporter:          s,
		ExecutableReporter:     s,
		Intervals:              intervals,
		InterpretersConfig:     interpreterconfig.AllInterpreters(),
		SamplesPerSecond:       sampleRate,
		FrameCacheSize:         processmanager.DefaultFrameCacheSize,
		FilterErrorFrames:      true,
		FilterIdleFrames:       true,
		KernelVersionCheck:     true,
		ProbabilisticInterval:  time.Minute,
		ProbabilisticThreshold: tracer.ProbabilisticThresholdMax, // every sample, not a share of them
		// The agent sees the process IDs of the kernel on a node, but not
		// where the node is itself a container (kind).
		PIDNamespaceTranslationMode: tracer.PIDNamespaceTranslationModeAuto,
	})
	if err != nil {
		cancel()
		return fmt.Errorf("the node's kernel does not let the profiler load its programs: %w", err)
	}
	trc.StartPIDEventProcessor(ctx)
	traces := make(chan *libpf.EbpfTrace)
	for _, step := range []struct {
		what string
		do   func() error
	}{
		{"sample the CPUs", func() error { return trc.AttachTracer(nil) }},
		{"follow ending processes", trc.AttachSchedMonitor},
		{"hand over its samples", func() error { return trc.StartMapMonitors(ctx, traces) }},
	} {
		if err := step.do(); err != nil {
			cancel()
			trc.Close()
			return fmt.Errorf("the node's kernel does not let the profiler %s: %w", step.what, err)
		}
	}
	go func() {
		for {
			select {
			case trace := <-traces:
				if trace != nil {
					trc.HandleTrace(trace)
				}
			case <-trc.Done():
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	s.tracer, s.cancel = trc, cancel
	return nil
}

// pageFaults marks the profiler's reports of page faults.
var pageFaults = &samples.TypeMetadata{
	SampleTypes:  []samples.SampleType{{Type: "page_faults", Unit: "count"}},
	AppendValues: samples.AppendFirstContextValue,
}

// faultProbe has the profiler take a stack at every page fault on the node:
// at the kernel function that handles the fault for every architecture. It
// is the profiler's own probe for a kernel function (probes/kprobe), which
// only its collector can configure.
type faultProbe struct {
	program  *cebpf.Program
	loaded   map[string]*cebpf.Program // the program and the unwinders it calls
	attached link.Link
}

// Load registers page faults as an origin of stacks and loads the program
// that takes them.
func (f *faultProbe) Load(_ context.Context, origins tracer.ProbeRegistrar, c *tracer.ProbeContext) error {
	const program = "kprobe__generic"
	origin, err := origins.Register(&tracer.OriginEntry{Meta: pageFaults})
	if err != nil {
		return err
	}
	spec, err := c.CollectionSpecWith(nil, []string{program}, []string{"origin_id_probe"})
	if err != nil {
		return err
	}
	if err := spec.Variables["origin_id_probe"].Set(origin); err != nil {
		return err
	}
	if err := c.RewriteMaps(spec, nil); err != nil {
		return err
	}
	loaded := map[string]*cebpf.Program{}
	if err := c.LoadProbeUnwinders(spec, loaded, []tracer.ProgLoaderHelper{{Name: program, NoTailCallTarget: true, Enable: true}}, 0); err != nil {
		return err
	}
	f.program, f.loaded = loaded[program], loaded
	return nil
}

// release takes the probe's programs out of the kernel.
func (f *faultProbe) release() {
	for _, p := range f.loaded {
		p.Close()
	}
	f.program, f.loaded = nil, nil
}

func (f *faultProbe) attach() (err error) {
	if f.attached == nil {
		f.attached, err = link.Kprobe("handle_mm_fault", f.program, nil)
	}
	return err
}

// Unload ends the reports; attach brings them back.
func (f *faultProbe) Unload() error {
	if f.attached == nil {
		return nil
	}
	attached := f.attached
	f.attached = nil
	return attached.Close()
}

// ReportTraceEvent takes a sample from the profiler.
func (s *sampler) ReportTraceEvent(trace *libpf.Trace, meta *samples.TraceEventMeta) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	pid, now := int(meta.PID), time.Now()
	for p := range s.profiles {
		// The container tells whose sample it is. Only where the profiler
		// knows none does the process ID decide, which another process can
		// get once the pod's process has ended.
		if container := meta.ContainerID.String(); !p.containers[container] && (container != "" || !p.pids[pid]) {
			continue
		}
		if p.kind.memory != (meta.ProfileType == pageFaults) {
			continue
		}
		p.add(stackKey{trace.Hash(), pid}, now, func() *sampledStack {
			frames := slices.Clone(trace.Frames)
			if p.kind.memory {
				// The kernel's part is the same at every fault: the fault's handler.
				frames = slices.DeleteFunc(frames, func(f unique.Handle[libpf.Frame]) bool { return f.Value().Type == libpf.KernelFrame })
			}
			return &sampledStack{frames: frames, pid: pid, comm: meta.Comm.String()}
		})
	}
	return nil
}

// ReportExecutable notes where a mapped file is.
func (s *sampler) ReportExecutable(args *reporter.ExecutableMetadata) {
	if args.Mapping == nil || !strings.HasPrefix(args.Mapping.Path, "/") {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.binaries == nil {
		s.binaries = map[libpf.FileID]mappedFile{}
	}
	s.binaries[args.MappingFile.Value().FileID] = mappedFile{pid: int(args.Process.PID()), path: strings.Clone(args.Mapping.Path)}
}

// sample records the stacks of the pod's processes at what kind counts,
// for duration from when the profiler runs or until frame ends before, and
// uploads the profile in pprof's format.
func (a *Agent) sample(ctx, frame context.Context, kind sampledKind, duration time.Duration, pod *corev1.Pod, known *processes, up func(string, io.Reader) error) error {
	p := newSampledProfile(kind, 0)
	a.cover(p, pod, known)
	if len(p.pids) == 0 {
		return fmt.Errorf("pod %s has no running process", pod.Name)
	}
	began := time.Now()
	if err := a.sampler.begin(p); err != nil {
		return err
	}
	select {
	case <-frame.Done():
	case <-time.After(duration):
	}
	binaries := a.sampler.end(p)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return a.uploadSampled(p, p.since(time.Time{}), binaries, began, up)
}

// sampled records a sampled profile for a capture: from the profile that the
// capture's watch has kept running for the pod if there is one, and
// otherwise from now on.
func (a *Agent) sampled(ctx, frame context.Context, kind sampledKind, r api.CaptureRequest, podName string, duration time.Duration, pod *corev1.Pod, known *processes, up func(string, io.Reader) error) error {
	a.mu.Lock()
	running := a.kept[r.Watch+"/"+podName+"/"+kind.recording]
	a.mu.Unlock()
	if r.Watch == "" || running == nil {
		return a.sample(ctx, frame, kind, duration, pod, known, up)
	}
	if r.AfterCrash() {
		duration = 0
	}
	return a.sampleKept(ctx, frame, running, duration, pod, up)
}

// kept is a sampled profile that a watch keeps running for a pod, so that
// the profile of its capture reaches back before the watch's condition was
// met.
type kept struct {
	profile *sampledProfile
	before  time.Duration
}

// keep has the profiler take the pod's samples of a kind for as long as the
// watch waits (ctx), keeping the seconds that a capture of the watch will
// want: those before the condition is met and those of its time frame
// after. A pod that is kept already gets its new containers covered.
func (a *Agent) keep(ctx context.Context, w api.Watch, kind sampledKind, pod *corev1.Pod) {
	key := w.ID + "/" + pod.Name + "/" + kind.recording
	a.mu.Lock()
	running := a.kept[key]
	a.mu.Unlock()
	if running != nil {
		a.cover(running.profile, pod, nil)
		return
	}
	// A few seconds more than asked: the capture's task takes a moment to arrive.
	p := newSampledProfile(kind, w.Before()+time.Duration(w.DurationSeconds)*time.Second+10*time.Second)
	a.cover(p, pod, nil)
	if len(p.pids) == 0 {
		return // no container runs yet: the pod's next change tries again
	}
	if err := a.sampler.begin(p); err != nil {
		slog.Warn("a watch's profile is not kept running: its captures will sample from the moment they start", "watch", w.ID, "pod", pod.Name, "error", err)
		return
	}
	a.mu.Lock()
	a.kept[key] = &kept{profile: p, before: w.Before()}
	a.mu.Unlock()
	go func() {
		<-ctx.Done()
		a.mu.Lock()
		delete(a.kept, key)
		a.mu.Unlock()
		a.sampler.end(p)
	}()
}

// sampleKept uploads the profile of a watch's capture from the profile that
// was kept running: the time before the capture, and after it the time
// frame, unless the capture follows a crash, which leaves nothing to sample.
func (a *Agent) sampleKept(ctx, frame context.Context, k *kept, after time.Duration, pod *corev1.Pod, up func(string, io.Reader) error) error {
	from := time.Now().Add(-k.before)
	select {
	case <-frame.Done():
	case <-time.After(after):
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	a.cover(k.profile, pod, nil) // the processes of now lead to the binaries
	a.sampler.mu.Lock()
	stacks := k.profile.since(from)
	binaries := make(map[libpf.FileID]mappedFile, len(a.sampler.binaries))
	for id, b := range a.sampler.binaries {
		binaries[id] = b
	}
	a.sampler.mu.Unlock()
	return a.uploadSampled(k.profile, stacks, binaries, from, up)
}

// uploadSampled names the functions of the stacks and uploads them as a
// profile in pprof's format.
func (a *Agent) uploadSampled(p *sampledProfile, stacks map[stackKey]*sampledStack, binaries map[libpf.FileID]mappedFile, began time.Time, up func(string, io.Reader) error) error {
	if len(stacks) == 0 {
		return errors.New(p.kind.nothing)
	}
	// The symbols of native code are in the binaries, which the pod's own processes lead to first.
	a.sampler.mu.Lock()
	pids := make([]int, 0, len(p.pids))
	for pid := range p.pids {
		pids = append(pids, pid)
	}
	a.sampler.mu.Unlock()
	tables := map[libpf.FileID]symbolTable{}
	name := func(file libpf.FileID, address uint64) string {
		table, read := tables[file]
		if b, known := binaries[file]; !read && known {
			for _, pid := range append(pids, b.pid) {
				if table = readSymbols(filepath.Join(a.Proc, strconv.Itoa(pid), "root", b.path)); table != nil {
					break
				}
			}
			tables[file] = table
		}
		return table.name(address)
	}
	var packed bytes.Buffer
	if err := sampledAsProfile(p.kind, stacks, began, time.Since(began), name).Write(&packed); err != nil {
		return err
	}
	return up(p.kind.file, &packed)
}

// sampledAsProfile turns sampled stacks into a profile in pprof's format.
// name tells the function at an address of a binary, or "".
func sampledAsProfile(kind sampledKind, stacks map[stackKey]*sampledStack, began time.Time, lasted time.Duration, name func(file libpf.FileID, address uint64) string) *profile.Profile {
	prof := &profile.Profile{
		SampleType:    []*profile.ValueType{&kind.count, &kind.amount},
		PeriodType:    &kind.amount,
		Period:        kind.unit,
		TimeNanos:     began.UnixNano(),
		DurationNanos: lasted.Nanoseconds(),
		Comments:      []string{"Sampled from the node by Asservat with the OpenTelemetry eBPF profiler."},
	}
	functions := map[[2]string]*profile.Function{}
	function := func(name, file string) *profile.Function {
		f := functions[[2]string{name, file}]
		if f == nil {
			f = &profile.Function{ID: uint64(len(prof.Function) + 1), Name: name, SystemName: name, Filename: file}
			functions[[2]string{name, file}] = f
			prof.Function = append(prof.Function, f)
		}
		return f
	}
	mappings := map[libpf.FileID]*profile.Mapping{}
	locations := map[libpf.Frame]*profile.Location{}
	location := func(frame libpf.Frame) *profile.Location {
		if l := locations[frame]; l != nil {
			return l
		}
		l := &profile.Location{ID: uint64(len(prof.Location) + 1)}
		called, line := frame.FunctionName.String(), int64(frame.SourceLine)
		if frame.Mapping.Valid() {
			// Native code: an address in a binary.
			data := frame.Mapping.Value()
			file := data.File.Value()
			m := mappings[file.FileID]
			if m == nil {
				m = &profile.Mapping{ID: uint64(len(prof.Mapping) + 1), File: file.FileName.String(), BuildID: file.GnuBuildID, HasFunctions: true}
				mappings[file.FileID] = m
				prof.Mapping = append(prof.Mapping, m)
			}
			l.Mapping, l.Address = m, uint64(frame.AddressOrLineno)
			if called == "" {
				called = name(file.FileID, l.Address)
			}
			if called == "" {
				// A binary without symbols: the address stands for the function.
				called = fmt.Sprintf("%s+0x%x", m.File, l.Address)
			}
		}
		if called == "" {
			called = "[" + frame.Type.String() + "]"
		}
		l.Line = []profile.Line{{Function: function(called, frame.SourceFile.String()), Line: line}}
		locations[frame] = l
		prof.Location = append(prof.Location, l)
		return l
	}
	// In a fixed order, so that the same samples give the same file.
	ordered := make([]*sampledStack, 0, len(stacks))
	for _, stack := range stacks {
		ordered = append(ordered, stack)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].count != ordered[j].count {
			return ordered[i].count > ordered[j].count
		}
		return ordered[i].pid < ordered[j].pid
	})
	for _, stack := range ordered {
		sample := &profile.Sample{
			Value:    []int64{stack.count, stack.count * kind.unit},
			Label:    map[string][]string{"process": {stack.comm}},
			NumLabel: map[string][]int64{"pid": {int64(stack.pid)}},
		}
		for _, frame := range stack.frames {
			sample.Location = append(sample.Location, location(frame.Value()))
		}
		prof.Sample = append(prof.Sample, sample)
	}
	return prof
}

// symbolTable holds the functions of a binary, sorted by address.
type symbolTable []elf.Symbol

// readSymbols reads the functions that a binary names: those of its symbol
// table, which a stripped binary lacks, and those it exports.
func readSymbols(path string) symbolTable {
	file, err := elf.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()
	var table symbolTable
	static, _ := file.Symbols()
	dynamic, _ := file.DynamicSymbols()
	for _, s := range append(static, dynamic...) {
		if elf.ST_TYPE(s.Info) == elf.STT_FUNC && s.Value != 0 {
			table = append(table, s)
		}
	}
	sort.Slice(table, func(i, j int) bool { return table[i].Value < table[j].Value })
	return table
}

// name returns the function that holds an address, with the names of C++
// and Rust in their readable form, or "".
func (t symbolTable) name(address uint64) string {
	i := sort.Search(len(t), func(i int) bool { return t[i].Value > address }) - 1
	if i < 0 || (t[i].Size != 0 && address >= t[i].Value+t[i].Size) {
		return ""
	}
	return demangle.Filter(t[i].Name)
}
