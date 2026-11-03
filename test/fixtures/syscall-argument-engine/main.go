//go:build ignore

// Disposable-only ADR-281 engine qualification. This is not a product loader.
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"asservat.local/asservat/internal/adapters/syscalls"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

const objectSHA = "4c548b54bf9cc0850352d8a4e4cc23cc5ddc7d50cfbc4bfb96913f319ec1784d"

type budget struct {
	Events, Bytes, Stopped, DeadlineBootNS, MaxProbeBytes uint64
	RateNextNS, RateIntervalNS, RateBurstNS               uint64
}

type counts struct {
	Entries, Exits, Continuations, FailedReads, Lost uint64
}

func (c *counts) add(raw []byte) error {
	// Exact upstream syscall_event_t / syscall_event_cont_t layout, x86-64.
	// perf.Record.RawSample documents 0..7 trailing garbage bytes from kernel
	// ring alignment. Native run41596591270 delivered164 for the160-byte ABI.
	// Only the ABI prefix is interpreted; padding never contributes counters.
	if len(raw) < 160 || len(raw) > 167 {
		return fmt.Errorf("unexpected traceloop record size %d", len(raw))
	}
	switch binary.LittleEndian.Uint32(raw[:4]) {
	case 0:
		c.Entries++
	case 1:
		c.Exits++
	case 2:
		c.Continuations++
		if raw[153] != 0 {
			c.FailedReads++
		}
	default:
		return errors.New("unknown traceloop record type")
	}
	return nil
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func require(ok bool, message string) {
	if !ok {
		panic(message)
	}
}

func bootNS() uint64 {
	var now unix.Timespec
	must(unix.ClockGettime(unix.CLOCK_BOOTTIME, &now))
	return uint64(now.Nano())
}

// These definitions are synthetic test inputs only: pwrite64 reads a fixed
// 128-byte buffer at entry; pread64 reads it at exit. Neither is a product ABI
// allowlist, and no argument content is retained in the report.
func definitions(atExit bool) (uint64, [6]uint64) {
	var d [6]uint64
	d[1] = 128
	nr := uint64(unix.SYS_PWRITE64)
	if atExit {
		nr = unix.SYS_PREAD64
		d[1] |= 0xf000000000000000
	}
	return nr, d
}

func pinnedSpec(object, output string) *ebpf.CollectionSpec {
	raw, err := os.ReadFile(object)
	must(err)
	require(fmt.Sprintf("%x", sha256.Sum256(raw)) == objectSHA, "compiled object digest mismatch")
	spec, err := ebpf.LoadCollectionSpec(object)
	must(err)
	require(len(spec.Programs) == 2, "unexpected program inventory")
	var listing strings.Builder
	for _, name := range []string{"ig_traceloop_e", "ig_traceloop_x"} {
		p := spec.Programs[name]
		require(p != nil && p.Type == ebpf.RawTracepoint, "unexpected program type")
		fmt.Fprintf(&listing, "%s\n%s\n", name, p.Instructions)
	}
	must(os.WriteFile(output, []byte(listing.String()), 0644))
	inventory := map[string]any{}
	for name, m := range spec.Maps {
		inventory[name] = map[string]any{"keyBytes": m.KeySize, "valueBytes": m.ValueSize, "maxEntries": m.MaxEntries, "type": m.Type.String()}
	}
	encoded, e := json.MarshalIndent(inventory, "", "  ")
	must(e)
	must(os.WriteFile(output+".maps.json", append(encoded, '\n'), 0644))
	return spec
}

type child struct {
	cmd *exec.Cmd
	in  io.WriteCloser
	out *bufio.Reader
	ns  uint64
}

func startChild(ctx context.Context) *child {
	self, err := os.Executable()
	must(err)
	cmd := exec.CommandContext(ctx, self, "workload")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS, Pdeathsig: unix.SIGKILL}
	in, err := cmd.StdinPipe()
	must(err)
	out, err := cmd.StdoutPipe()
	must(err)
	cmd.Stderr = os.Stderr
	must(cmd.Start())
	c := &child{cmd: cmd, in: in, out: bufio.NewReader(out)}
	line, err := c.out.ReadString('\n')
	must(err)
	require(line == "ready\n", "workload failed to become ready")
	ns, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/mnt", cmd.Process.Pid))
	must(err)
	c.ns, err = strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(ns, "mnt:["), "]"), 10, 64)
	must(err)
	return c
}

func (c *child) close() {
	_ = c.in.Close()
	_ = c.cmd.Process.Kill()
	_ = c.cmd.Wait()
}

type workloadRequest struct {
	Threads, Calls            int
	Exit, Fault               bool
	ReadBytes                 int
	Zero, BadFD, ReturnLength bool
}

func (c *child) run(request workloadRequest) error {
	if err := json.NewEncoder(c.in).Encode(request); err != nil {
		return err
	}
	line, err := c.out.ReadString('\n')
	if err != nil {
		return err
	}
	if line != "done\n" {
		return errors.New("synthetic workload failed: " + line)
	}
	return nil
}

func workload() {
	writeFD, err := unix.Open("/dev/null", unix.O_WRONLY, 0)
	must(err)
	defer unix.Close(writeFD)
	readFD, err := unix.Open("/dev/zero", unix.O_RDONLY, 0)
	must(err)
	defer unix.Close(readFD)
	fmt.Println("ready")
	input := json.NewDecoder(os.Stdin)
	for {
		var request workloadRequest
		if err := input.Decode(&request); err == io.EOF {
			return
		} else {
			must(err)
		}
		require(request.Threads >= 1 && request.Threads <= 16 && request.Calls >= 1 && request.Calls <= 1000, "unbounded workload")
		var wg sync.WaitGroup
		start := make(chan struct{})
		errs := make(chan error, request.Threads)
		for range request.Threads {
			wg.Add(1)
			go func() {
				defer wg.Done()
				runtime.LockOSThread()
				defer runtime.UnlockOSThread()
				var data [128]byte
				copy(data[:], "synthetic argument budget fixture")
				ptr := uintptr(unsafe.Pointer(&data[0]))
				length := 128
				if request.ReadBytes > 0 {
					length = request.ReadBytes
				}
				if request.Zero {
					length = 0
				}
				require(length >= 0 && length <= 128, "unbounded native length")
				if request.Fault {
					ptr = 1
				}
				nr, fd := uintptr(unix.SYS_PWRITE64), writeFD
				if request.Exit {
					nr, fd = unix.SYS_PREAD64, readFD
				}
				if request.BadFD {
					fd = -1
				}
				<-start
				for range request.Calls {
					n, _, errno := unix.RawSyscall6(nr, uintptr(fd), ptr, uintptr(length), 0, 0, 0)
					// /dev/null may accept a bad pointer without inspecting it;
					// the BPF continuation still records the attempted read fault.
					if (!request.Fault && !request.BadFD && (errno != 0 || n != uintptr(length))) || (request.BadFD && errno != unix.EBADF) || (request.Fault && errno != 0 && errno != unix.EFAULT) {
						errs <- fmt.Errorf("synthetic syscall: n=%d errno=%v", n, errno)
						return
					}
				}
				runtime.KeepAlive(&data)
			}()
		}
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			must(err)
		}
		fmt.Println("done")
	}
}

type scenario struct {
	Name       string
	Initial    budget
	Request    workloadRequest
	Namespaces int
	Expired    bool
}

type result struct {
	Name                                          string
	Initial, Final                                budget
	Counts                                        counts
	Milliseconds                                  int64
	DetachStoppedDebits                           bool
	DecodedProbes, DecoderGaps, ContinuationBytes uint64
	Threads                                       int
}

func runScenario(parent context.Context, original *ebpf.CollectionSpec, s scenario, dir string) (out result) {
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	started := time.Now()
	out.Name = s.Name
	spec := original.Copy()
	cpus, err := ebpf.PossibleCPU()
	must(err)
	spec.Maps["map_of_perf_buffers"].InnerMap.MaxEntries = uint32(cpus)
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelStats}})
	if err != nil {
		must(os.WriteFile(filepath.Join(dir, s.Name+"-verifier-error.txt"), []byte(fmt.Sprintf("%+v", err)), 0644))
		panic(err)
	}
	defer collection.Close()
	for name, program := range collection.Programs {
		must(os.WriteFile(filepath.Join(dir, s.Name+"-"+name+"-verifier.txt"), []byte(program.VerifierLog), 0644))
	}
	b := s.Initial
	if s.Name != "zero" {
		b.DeadlineBootNS = bootNS() + uint64(10*time.Second)
		if s.Name == "deadline-between-batches" {
			b.DeadlineBootNS = bootNS() + uint64(2*time.Second)
		}
		if s.Expired {
			b.DeadlineBootNS = bootNS() - 1
		}
		b.MaxProbeBytes = 1792
		b.RateIntervalNS = 10000
		b.RateBurstNS = 999990000
		if s.Name == "rate-exhaustion" {
			b.RateIntervalNS = 333333334
			b.RateBurstNS = 666666668
		}
	}
	out.Initial = b
	zero := uint32(0)
	budgetMap := collection.Maps["asservat_budget"]
	if s.Name != "zero" {
		must(budgetMap.Put(zero, b))
	}
	nr, definition := definitions(s.Request.Exit)
	if s.Request.ReturnLength {
		definition[1] = syscalls.ArgumentExitMask | syscalls.ArgumentReturnLength
	}
	defs := collection.Maps["syscalls"]
	must(defs.Put(nr, definition))
	must(collection.Maps["syscall_filters"].Put(nr, uint8(1)))
	must(collection.Maps["syscall_enable_filters"].Put(zero, uint8(1)))
	must(budgetMap.Freeze())
	must(defs.Freeze())
	require(errors.Is(budgetMap.Put(zero, b), unix.EPERM), "frozen budget accepted userspace refill")
	require(errors.Is(defs.Put(nr, definition), unix.EPERM), "frozen definitions accepted replacement")
	// No namespace is exposed and no tracepoint attached until initialization
	// and freeze are complete. Fresh maps here are independent synthetic cases,
	// not authorization to restart or refill a production session.
	var children []*child
	var readers []*perf.Reader
	var readersWG sync.WaitGroup
	var mu sync.Mutex
	var readErr error
	defer func() {
		for _, c := range children {
			c.close()
		}
		for _, r := range readers {
			_ = r.Close()
		}
		readersWG.Wait()
	}()
	handle, _, handleErr := unix.NameToHandleAt(unix.AT_FDCWD, "/sys/fs/cgroup", 0)
	must(handleErr)
	require(handle.Size() == 8, "unsupported cgroup handle")
	cgroupID := binary.LittleEndian.Uint64(handle.Bytes())
	if s.Name != "wrong-cgroup" {
		must(collection.Maps["asservat_cgroups"].Put(cgroupID, uint8(1)))
	}
	decoder, e := syscalls.NewArgumentDecoder([]string{"pread64", "pwrite64"}, true, 256, 4096)
	must(e)
	threadStarts := map[uint32]uint64{}
	flushed := make(chan struct{}, s.Namespaces)
	for range s.Namespaces {
		c := startChild(ctx)
		children = append(children, c)
		for _, previous := range children[:len(children)-1] {
			require(previous.ns != c.ns, "workloads did not get independent namespaces")
		}
		inner, err := ebpf.NewMap(spec.Maps["map_of_perf_buffers"].InnerMap)
		must(err)
		defer inner.Close()
		r, err := perf.NewReader(inner, 64*os.Getpagesize())
		must(err)
		readers = append(readers, r)
		must(collection.Maps["map_of_perf_buffers"].Put(c.ns, uint32(inner.FD())))
		readersWG.Add(1)
		go func() {
			defer readersWG.Done()
			for {
				record, err := r.Read()
				if errors.Is(err, perf.ErrFlushed) {
					flushed <- struct{}{}
					continue
				}
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				mu.Lock()
				if err != nil {
					readErr = err
				} else if record.LostSamples != 0 {
					out.Counts.Lost += record.LostSamples
				} else if err := out.Counts.add(record.RawSample); err != nil {
					readErr = err
				} else {
					probe, e := decoder.Add(record.RawSample)
					if e != nil {
						readErr = e
					}
					if probe != nil {
						out.DecodedProbes++
						if old := threadStarts[probe.Event.TID]; old != 0 && old != probe.Event.TaskStart {
							readErr = errors.New("thread incarnation changed within synthetic child")
						}
						threadStarts[probe.Event.TID] = probe.Event.TaskStart
						if probe.Memory != nil {
							out.ContinuationBytes += uint64(len(probe.Memory.Data))
						}
					}
				}
				mu.Unlock()
				if err != nil {
					return
				}
			}
		}()
	}
	var links []link.Link
	defer func() {
		for _, l := range links {
			_ = l.Close()
		}
	}()
	for _, pair := range [][2]string{{"sys_enter", "ig_traceloop_e"}, {"sys_exit", "ig_traceloop_x"}} {
		l, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: pair[0], Program: collection.Programs[pair[1]]})
		must(err)
		links = append(links, l)
	}
	var runs sync.WaitGroup
	errs := make(chan error, len(children))
	for _, c := range children {
		runs.Add(1)
		go func() { defer runs.Done(); errs <- c.run(s.Request) }()
	}
	runs.Wait()
	close(errs)
	for err := range errs {
		must(err)
	}
	if s.Name == "deadline-between-batches" {
		var before budget
		must(budgetMap.Lookup(zero, &before))
		require(before.Events == b.Events-64 && before.Bytes == b.Bytes-32*768 && before.Stopped == 0, "first batch did not finish inside original deadline")
		remaining := int64(b.DeadlineBootNS) - int64(bootNS())
		require(remaining > 0, "original deadline already elapsed before observation")
		timer := time.NewTimer(time.Duration(remaining) + time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			panic("expiry observation exceeded fixture deadline")
		}
		must(children[0].run(s.Request))
	}
	must(budgetMap.Lookup(zero, &out.Final))
	for _, l := range links {
		must(l.Close())
	}
	links = nil
	// A second synthetic syscall batch after detach must consume nothing.
	for _, c := range children {
		must(c.run(workloadRequest{Threads: 1, Calls: 2, Exit: s.Request.Exit}))
	}
	var after budget
	must(budgetMap.Lookup(zero, &after))
	require(after == out.Final, "detached program still debited budget")
	out.DetachStoppedDebits = true
	for _, r := range readers {
		must(r.Flush())
	}
	for range readers {
		select {
		case <-flushed:
		case <-ctx.Done():
			panic("perf drain did not join")
		}
	}
	mu.Lock()
	must(readErr)
	out.DecoderGaps = decoder.Flush()
	out.Threads = len(threadStarts)
	if s.Name == "interleaved-threads" {
		require(out.Threads >= 2 && out.DecoderGaps == 0, "interleaved thread identity/correlation failed")
	}
	if s.Request.ReturnLength {
		want := uint64(s.Request.Calls * s.Request.Threads * s.Request.ReadBytes)
		require(out.ContinuationBytes == want && out.Counts.FailedReads == 0 && out.DecoderGaps == 0, "short/zero/negative result read mismatch")
	}
	validate(s, out)
	mu.Unlock()
	out.Milliseconds = time.Since(started).Milliseconds()
	return out
}

func validate(s scenario, r result) {
	require(r.Final.Events <= r.Initial.Events && r.Final.Bytes <= r.Initial.Bytes, "budget underflow/refill")
	used := r.Initial.Events - r.Final.Events
	charged := r.Initial.Bytes - r.Final.Bytes
	require(r.Counts.Entries+r.Counts.Exits <= used, "emitted probes exceed event debits")
	require(charged >= 256*(r.Counts.Entries+r.Counts.Exits)+256*r.Counts.Continuations, "emitted records exceed conservative debit")
	if s.Name == "concurrent-two-namespaces" {
		require(used > 0 && r.Final.Stopped == 1, "concurrent workload did not reach budget/early stop")
		return // Loss and premature stop are measured, never inferred as zero.
	}
	require(r.Counts.Lost == 0, "serial fixture lost events; cannot assert exact accounting")
	switch s.Name {
	case "wrong-cgroup":
		require(r.Counts == (counts{}) && used == 0 && charged == 0, "foreign cgroup inspected/debited")
	case "zero", "expired", "insufficient-first-read":
		require(r.Counts == (counts{}) && r.Final.Stopped == 1, "denied probe emitted records")
		if s.Name == "insufficient-first-read" {
			require(used == 1 && charged == 0, "failed byte reservation refunded its event")
		} else {
			require(used == 0 && charged == 0, "expired/zero allowance was debited")
		}
	case "rate-exhaustion":
		require(used == 3 && charged == 1280 && r.Final.Stopped == 1 && r.Counts.Entries == 2 && r.Counts.Exits == 1 && r.Counts.Continuations == 2, "shared observed-probe rate mismatch")
	case "event-exhaustion":
		require(used == 7 && charged == 2816 && r.Final.Stopped == 1 && r.Counts.Entries == 4 && r.Counts.Exits == 3 && r.Counts.Continuations == 4, "entry/exit event exhaustion mismatch")
	case "byte-exhaustion":
		require(used == 3 && charged == 768 && r.Final.Stopped == 1 && r.Counts.Entries == 1 && r.Counts.Exits == 1 && r.Counts.Continuations == 1, "byte exhaustion mismatch")
	default:
		calls := uint64(s.Request.Calls * max(s.Request.Threads, 1))
		stopped := uint64(0)
		if s.Name == "deadline-between-batches" {
			stopped = 1
		}
		require(used == 2*calls && charged == 768*calls && r.Final.Stopped == stopped, "serial pre-read charge mismatch")
		require(r.Counts.Entries == calls && r.Counts.Exits == calls && r.Counts.Continuations == calls, "entry/exit/continuation records mismatch")
		if s.Request.Fault && !s.Request.ReturnLength {
			require(r.Counts.FailedReads == calls, "faulting reads were not reported/charged")
		} else {
			require(r.Counts.FailedReads == 0, "synthetic valid buffer faulted")
		}
	}
}

func main() {
	if len(os.Args) == 4 && os.Args[1] == "inspect" {
		pinnedSpec(os.Args[2], os.Args[3])
		return // Compile-only inspection: no guard, kernel load or namespace work.
	}
	_, err := os.Stat("/etc/asservat-disposable-host")
	must(err)
	require(runtime.GOOS == "linux" && runtime.GOARCH == "amd64", "unqualified architecture")
	if len(os.Args) == 2 && os.Args[1] == "workload" {
		workload()
		return
	}
	require(len(os.Args) == 3, "usage: engine OBJECT OUTPUT_DIRECTORY")
	dir := os.Args[2]
	report := map[string]any{"objectSHA256": objectSHA, "scope": "engine only; no product authority/publication; emitted counts do not independently observe every user-memory helper call", "results": []result{}}
	defer func() {
		if problem := recover(); problem != nil {
			report["error"] = fmt.Sprint(problem)
		}
		raw, err := json.MarshalIndent(report, "", "  ")
		must(err)
		must(os.WriteFile(filepath.Join(dir, "native-results.json"), append(raw, '\n'), 0644))
		if report["error"] != nil {
			fmt.Fprintln(os.Stderr, report["error"])
			os.Exit(1)
		}
	}()
	must(rlimit.RemoveMemlock())
	cpus, err := ebpf.PossibleCPU()
	must(err)
	report["possibleCPUs"] = cpus
	report["perfBufferBytesCeiling"] = 2 * 64 * os.Getpagesize() * cpus
	spec := pinnedSpec(os.Args[1], filepath.Join(dir, "instructions.txt"))
	serial := workloadRequest{Threads: 1, Calls: 32}
	fault := serial
	fault.Fault = true
	exit := serial
	exit.Exit = true
	exitFault := exit
	exitFault.Fault = true
	scenarios := []scenario{
		{Name: "zero", Request: serial, Namespaces: 1},
		{Name: "wrong-cgroup", Initial: budget{Events: 100, Bytes: 100000}, Request: serial, Namespaces: 1},
		{Name: "short-read", Initial: budget{Events: 100, Bytes: 100000}, Request: workloadRequest{Threads: 1, Calls: 32, Exit: true, ReturnLength: true, ReadBytes: 4}, Namespaces: 1},
		{Name: "zero-read", Initial: budget{Events: 100, Bytes: 100000}, Request: workloadRequest{Threads: 1, Calls: 32, Exit: true, ReturnLength: true, Zero: true, Fault: true}, Namespaces: 1},
		{Name: "negative-read", Initial: budget{Events: 100, Bytes: 100000}, Request: workloadRequest{Threads: 1, Calls: 32, Exit: true, ReturnLength: true, BadFD: true}, Namespaces: 1},
		{Name: "interleaved-threads", Initial: budget{Events: 1000, Bytes: 1000000}, Request: workloadRequest{Threads: 4, Calls: 8}, Namespaces: 1},
		{Name: "expired", Initial: budget{Events: 100, Bytes: 100000}, Request: serial, Namespaces: 1, Expired: true},
		{Name: "insufficient-first-read", Initial: budget{Events: 100, Bytes: 511}, Request: serial, Namespaces: 1},
		{Name: "entry", Initial: budget{Events: 100, Bytes: 100000}, Request: serial, Namespaces: 1},
		{Name: "fault-entry", Initial: budget{Events: 100, Bytes: 100000}, Request: fault, Namespaces: 1},
		{Name: "exit", Initial: budget{Events: 100, Bytes: 100000}, Request: exit, Namespaces: 1},
		{Name: "fault-exit", Initial: budget{Events: 100, Bytes: 100000}, Request: exitFault, Namespaces: 1},
		{Name: "deadline-between-batches", Initial: budget{Events: 100, Bytes: 100000}, Request: serial, Namespaces: 1},
		{Name: "rate-exhaustion", Initial: budget{Events: 100, Bytes: 100000}, Request: serial, Namespaces: 1},
		{Name: "event-exhaustion", Initial: budget{Events: 7, Bytes: 100000}, Request: serial, Namespaces: 1},
		{Name: "byte-exhaustion", Initial: budget{Events: 100, Bytes: 1024}, Request: serial, Namespaces: 1},
		{Name: "concurrent-two-namespaces", Initial: budget{Events: 10000, Bytes: 2000000}, Request: workloadRequest{Threads: 16, Calls: 1000}, Namespaces: 2},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for _, s := range scenarios {
		report["activeScenario"] = s.Name
		r := runScenario(ctx, spec, s, dir)
		report["results"] = append(report["results"].([]result), r)
	}
	delete(report, "activeScenario")
	report["localHandlesClosed"] = true
}
