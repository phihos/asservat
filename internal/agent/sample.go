package agent

import (
	"bytes"
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

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

// sampler runs the profiler while at least one recording wants samples.
type sampler struct {
	mu       sync.Mutex
	stop     func()
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

// sampledProfile collects the samples of one pod.
type sampledProfile struct {
	containers map[string]bool // the pod's container IDs
	pids       map[int]bool    // its processes when the sampling began
	stacks     map[stackKey]*sampledStack
}

type stackKey struct {
	trace libpf.TraceHash
	pid   int
}

// sampledStack is one stack of one process and how often it was seen.
type sampledStack struct {
	frames libpf.Frames // the innermost first
	pid    int
	comm   string
	count  int64
}

// begin starts collecting the samples of a pod, and the profiler if it does
// not run yet.
func (s *sampler) begin(p *sampledProfile) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stop == nil {
		stop, err := s.run()
		if err != nil {
			return err
		}
		s.stop = stop
	}
	if s.profiles == nil {
		s.profiles = map[*sampledProfile]struct{}{}
	}
	s.profiles[p] = struct{}{}
	return nil
}

// end stops collecting for a pod, and the profiler with its last pod. It
// returns where the symbols of the binaries seen can be read.
func (s *sampler) end(p *sampledProfile) map[libpf.FileID]mappedFile {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.profiles, p)
	binaries := s.binaries
	if len(s.profiles) == 0 && s.stop != nil {
		s.stop()
		s.stop, s.binaries = nil, nil
	} else {
		binaries = make(map[libpf.FileID]mappedFile, len(s.binaries))
		for id, b := range s.binaries {
			binaries[id] = b
		}
	}
	return binaries
}

// run loads the profiler's programs into the kernel and starts sampling.
// The order of the steps is the profiler's own (its collector receiver).
func (s *sampler) run() (stop func(), err error) {
	// A container's /sys comes without the tracepoints.
	if _, err := os.Stat(tracefs + "/events"); err != nil {
		if err := syscall.Mount("tracefs", tracefs, "tracefs", 0, ""); err != nil {
			return nil, fmt.Errorf("the kernel's tracepoints cannot be reached (mount of %s: %w)", tracefs, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	fail := func(what string, err error) (func(), error) {
		cancel()
		return nil, fmt.Errorf("the node's kernel does not let the profiler %s: %w", what, err)
	}
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
	})
	if err != nil {
		return fail("load its programs (it needs Linux 5.10 or later)", err)
	}
	stop = func() { cancel(); trc.Close() }
	trc.StartPIDEventProcessor(ctx)
	if err := trc.AttachTracer(nil); err != nil {
		stop()
		return fail("sample the CPUs", err)
	}
	if err := trc.EnableProfiling(); err != nil {
		stop()
		return fail("sample the CPUs", err)
	}
	if err := trc.AttachSchedMonitor(); err != nil {
		stop()
		return fail("follow ending processes", err)
	}
	traces := make(chan *libpf.EbpfTrace)
	if err := trc.StartMapMonitors(ctx, traces); err != nil {
		stop()
		return fail("hand over its samples", err)
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
	return stop, nil
}

// ReportTraceEvent takes a sample from the profiler.
func (s *sampler) ReportTraceEvent(trace *libpf.Trace, meta *samples.TraceEventMeta) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	pid := int(meta.PID)
	for p := range s.profiles {
		if !p.containers[meta.ContainerID.String()] && !p.pids[pid] {
			continue
		}
		key := stackKey{trace.Hash(), pid}
		stack := p.stacks[key]
		if stack == nil {
			stack = &sampledStack{frames: slices.Clone(trace.Frames), pid: pid, comm: meta.Comm.String()}
			p.stacks[key] = stack
		}
		stack.count++
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

// sample records where the pod's processes spend CPU time, for duration
// from when the profiler runs or until frame ends before, and uploads the
// profile in pprof's format.
func (a *Agent) sample(ctx, frame context.Context, duration time.Duration, pod *corev1.Pod, up func(string, io.Reader) error) error {
	p := &sampledProfile{containers: map[string]bool{}, pids: map[int]bool{}, stacks: map[stackKey]*sampledStack{}}
	for _, status := range slices.Concat(pod.Status.InitContainerStatuses, pod.Status.ContainerStatuses, pod.Status.EphemeralContainerStatuses) {
		if _, id, ok := strings.Cut(status.ContainerID, "://"); ok {
			p.containers[id] = true
			all, _, _ := containerPIDs(a.Proc, id)
			for _, pid := range all {
				p.pids[pid] = true
			}
		}
	}
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
	if len(p.stacks) == 0 {
		return errors.New("the pod's processes used no CPU time while they were sampled")
	}
	// The symbols of native code are in the binaries, which the pod's own processes lead to first.
	pids := make([]int, 0, len(p.pids))
	for pid := range p.pids {
		pids = append(pids, pid)
	}
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
	if err := sampledAsProfile(p.stacks, began, time.Since(began), name).Write(&packed); err != nil {
		return err
	}
	return up("sampled-cpu.pprof", &packed)
}

// sampledAsProfile turns sampled stacks into a profile in pprof's format.
// name tells the function at an address of a binary, or "".
func sampledAsProfile(stacks map[stackKey]*sampledStack, began time.Time, lasted time.Duration, name func(file libpf.FileID, address uint64) string) *profile.Profile {
	period := int64(time.Second / sampleRate)
	prof := &profile.Profile{
		SampleType:    []*profile.ValueType{{Type: "samples", Unit: "count"}, {Type: "cpu", Unit: "nanoseconds"}},
		PeriodType:    &profile.ValueType{Type: "cpu", Unit: "nanoseconds"},
		Period:        period,
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
			Value:    []int64{stack.count, stack.count * period},
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
