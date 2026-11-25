package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"asservat.local/asservat/internal/api"
	"asservat.local/asservat/internal/coredesc"
)

// capture makes the request's recordings of one pod, all at once, and
// uploads their files. It fails if no recording succeeded; otherwise it
// names those that failed. The recordings that run over time end with
// frame, which is the task's context until the user stops the capture, and
// keep what they recorded until then.
func (a *Agent) capture(ctx, frame context.Context, id string, t api.TaskAssignment, report *progress) (failures string, err error) {
	r := t.Request
	pod, err := a.Kube.CoreV1().Pods(r.Namespace).Get(ctx, t.Pod, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	if pod.Spec.NodeName != a.Node {
		return "", fmt.Errorf("pod %s runs on node %s", t.Pod, pod.Spec.NodeName)
	}
	// A core dump and a trace both attach to the process, which only one
	// can do at a time: the trace starts when the dump is written. After a
	// crash the core is the kernel's and nothing attaches for it.
	dumped := make(chan struct{})
	if r.Recording(api.KindCoredump) == nil || r.AfterCrash() {
		close(dumped)
	}
	errs := make([]error, len(r.Recordings))
	known := &processes{}
	var wg sync.WaitGroup
	for i, rec := range r.Recordings {
		wg.Go(func() {
			if rec.Kind == api.KindStrace {
				select {
				case <-dumped:
				case <-frame.Done():
					errs[i] = errors.New("stopped before it began")
					report.set(rec.Kind, api.StateFailed, errs[i].Error())
					return
				}
			}
			report.set(rec.Kind, api.StateRunning, "")
			errs[i] = a.recording(ctx, frame, id, t, pod, rec, known)
			if rec.Kind == api.KindCoredump && !r.AfterCrash() {
				close(dumped)
			}
			switch {
			case errs[i] != nil:
				report.set(rec.Kind, api.StateFailed, errs[i].Error())
			case frame.Err() != nil && rec.Timed(r.DurationSeconds > 0):
				report.set(rec.Kind, api.StateCompleted, "stopped early")
			default:
				report.set(rec.Kind, api.StateCompleted, "")
			}
		})
	}
	wg.Wait()
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	var failed []string
	delivered := false
	for i, err := range errs {
		delivered = delivered || err == nil || errors.As(err, &partialError{})
		if err != nil && len(errs) > 1 {
			failed = append(failed, r.Recordings[i].Kind+": "+err.Error())
		} else if err != nil {
			failed = append(failed, err.Error())
		}
	}
	if !delivered {
		return "", errors.New(strings.Join(failed, "; "))
	}
	return strings.Join(failed, "; "), nil
}

// straceArgs are the arguments of strace for a recording of the processes:
// children are followed, calls are timed, and the contents of buffers are
// left out unless strings was requested (and approved).
func straceArgs(rec api.Recording, pids []int) []string {
	size := "0"
	if rec.Params["strings"] == "true" {
		size = "256"
	}
	args := []string{"-f", "-tt", "-T", "-s", size, "-o", "/dev/stdout"}
	for _, pid := range pids {
		args = append(args, "-p", strconv.Itoa(pid))
	}
	return args
}

// partialError is the failure of a recording that still delivered files.
type partialError struct{ error }

// recording makes one recording of a pod.
func (a *Agent) recording(ctx, frame context.Context, id string, t api.TaskAssignment, pod *corev1.Pod, rec api.Recording, known *processes) error {
	r := t.Request
	duration := time.Duration(r.DurationSeconds) * time.Second
	up := func(name string, body io.Reader) error { return a.upload(ctx, id, t.Pod, name, body) }
	switch rec.Kind {
	case api.KindPodState:
		events, err := a.Kube.CoreV1().Events(r.Namespace).List(ctx, metav1.ListOptions{FieldSelector: "involvedObject.name=" + t.Pod})
		if err != nil {
			return err
		}
		pod.ManagedFields = nil
		for name, v := range map[string]any{"pod.json": pod, "events.json": events.Items} {
			b, _ := json.MarshalIndent(v, "", "  ")
			if err := up(name, bytes.NewReader(b)); err != nil {
				return err
			}
		}
		return nil
	case api.KindLogs:
		return a.logs(ctx, frame, pod, rec, r.AfterCrash(), duration, up)
	case api.KindPcap:
		if r.Watch != "" && rec.Buffers() {
			// After a crash: the packets before it, set aside when it was
			// reported. Otherwise the pod goes on: the packets from before
			// the capture and those of its time frame, in one file.
			a.mu.Lock()
			packets := a.snapshots[r.Trigger]
			delete(a.snapshots, r.Trigger)
			ring := a.rings[r.Watch+"/"+t.Pod]
			a.mu.Unlock()
			if packets == nil && ring != nil {
				from := time.Now().Add(-ring.before)
				if !r.AfterCrash() {
					select {
					case <-frame.Done():
					case <-time.After(duration):
					}
				}
				packets = ring.snapshot(from)
			}
			if packets == nil {
				return errors.New("the node agent holds no packets of this pod from before the watch's condition was met")
			}
			return up("capture.pcap", bytes.NewReader(packets))
		}
		pid, err := a.podPID(pod, known)
		if err != nil {
			return err
		}
		// Headers only unless payload was requested (and approved).
		payload := rec.Params["payload"] == "true"
		if !payload {
			packets := up
			up = func(name string, body io.Reader) error { return packets(name, headersOnly(body)) }
		}
		return a.record(ctx, frame, duration, "capture.pcap", up, "nsenter", tcpdumpArgs(pid, rec.Params["filter"], payload, false)...)
	case api.KindStrace:
		// The system calls that the capture's watch kept tracing: those from
		// before the capture and, unless a crash ended the process, those
		// of its time frame.
		a.mu.Lock()
		traced, calls := a.traces[r.Watch+"/"+t.Pod], a.calls[r.Trigger]
		delete(a.calls, r.Trigger)
		a.mu.Unlock()
		if r.Watch != "" && (traced != nil || calls.name != "") {
			if calls.name == "" { // nothing was set aside: the process goes on
				from := time.Now().Add(-traced.before)
				if !r.AfterCrash() {
					select {
					case <-frame.Done():
					case <-time.After(duration):
					}
				}
				calls = setAside{name: traced.name, content: traced.since(from)}
			}
			if len(calls.content) == 0 {
				return errors.New("the node agent holds no system calls of this pod from before the watch's condition was met")
			}
			return up(calls.name, bytes.NewReader(calls.content))
		}
		pids, container, err := a.targets(pod, rec.Params["container"], rec.Params["process"], known)
		if err != nil {
			return err
		}
		// The trace is taken aside first and sent when it is complete:
		// it is sent only if the processes are still those that were
		// found. strace is set on them by number, so between this look
		// and its hold another process can come by a number: that one is
		// then traced, and what was traced of it is deleted here, unsent.
		theSame := func() error {
			for _, pid := range pids {
				if !known.same(a.Proc, pid) {
					return replaced(pid)
				}
			}
			return nil
		}
		if err := theSame(); err != nil {
			return err
		}
		return a.record(ctx, frame, duration, container+".strace", a.aside(sentIf(theSame, up)), "strace", straceArgs(rec, pids)...)
	case api.KindCPU:
		return a.sampled(ctx, frame, sampledCPU, r, t.Pod, duration, pod, known, up)
	case api.KindMemory:
		return a.sampled(ctx, frame, sampledMemory, r, t.Pod, duration, pod, known, up)
	case api.KindPprof:
		targets, err := rec.ProfileTargets()
		if err != nil {
			return err
		}
		// The pod's network namespace, for the endpoints that are served
		// over HTTP.
		pid := 0
		if slices.ContainsFunc(targets, func(t api.ProfileTarget) bool { return !t.Attach }) {
			if pid, err = a.podPID(pod, known); err != nil {
				return err
			}
		}
		// The endpoints are fetched at once, so that their profiles cover
		// the same time.
		errs := make([]error, len(targets))
		var wg sync.WaitGroup
		for i, target := range targets {
			wg.Go(func() {
				if target.Attach {
					if errs[i] = a.askJVM(ctx, frame, pod, target, r.DurationSeconds, known, up); errs[i] != nil {
						errs[i] = fmt.Errorf("%s of container %s: %w", target.ID, target.Container, errs[i])
					}
					return
				}
				// A profile over time cannot be cut short: stopping the
				// capture abandons it.
				ctx := ctx
				if target.Timed {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(frame, duration+30*time.Second)
					defer cancel()
				}
				errs[i] = a.record(ctx, ctx, 0, target.File, up, "nsenter", profileRequest(pid, target, r.DurationSeconds)...)
				if errs[i] != nil && target.Timed && frame.Err() != nil {
					errs[i] = errors.New("stopped before it was complete")
				}
				if errs[i] != nil {
					errs[i] = fmt.Errorf("%s on port %d: %w", target.Name, target.Port, errs[i])
				}
			})
		}
		wg.Wait()
		if err := errors.Join(errs...); err != nil && slices.Contains(errs, nil) {
			return partialError{err} // the other endpoints delivered
		} else {
			return err
		}
	case api.KindCoredump:
		if r.AfterCrash() {
			// The core of the crashed process, not one of its successor.
			return a.crashCores(ctx, pod, r.Trigger, known, up)
		}
		pids, container, err := a.targets(pod, rec.Params["container"], rec.Params["process"], known)
		if err != nil {
			return err
		}
		for _, pid := range pids {
			name := "core." + container
			if rec.Params["process"] != "" {
				name += "." + strconv.Itoa(pid)
			}
			if err := a.gcore(ctx, id+"-"+t.Pod, pid, name, func() bool { return known.same(a.Proc, pid) }, up); err != nil {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("unknown kind %q", rec.Kind)
}

// profileRequest returns the arguments of nsenter for an HTTP GET of a
// profile endpoint. The request runs inside the pod's network namespace, so
// endpoints bound to localhost work and no NetworkPolicy applies.
func profileRequest(pid int, target api.ProfileTarget, seconds int) []string {
	args := []string{"-t", strconv.Itoa(pid), "-n", "curl", "-sS", "--fail"}
	if target.Accept != "" {
		args = append(args, "-H", "Accept: "+target.Accept)
	}
	path := strings.ReplaceAll(target.Path, "{seconds}", strconv.Itoa(seconds))
	return append(args, "http://127.0.0.1:"+strconv.Itoa(target.Port)+path)
}

// aside makes an upload take its content to the scratch directory first and
// send it when it is complete. A tool that holds a process, as strace does
// at every system call, then waits for the node's disk only and not for
// the way to the hub.
func (a *Agent) aside(up func(string, io.Reader) error) func(string, io.Reader) error {
	return func(name string, src io.Reader) error {
		f, err := os.CreateTemp(a.Scratch, "aside-*")
		if err != nil {
			return err
		}
		defer os.Remove(f.Name())
		defer f.Close()
		if _, err := io.Copy(f, src); err != nil {
			return err
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return err
		}
		return up(name, f)
	}
}

// gcore dumps a running process. gcore cannot write to a pipe: the core
// rests in the scratch directory until it is uploaded.
func (a *Agent) gcore(ctx context.Context, scratch string, pid int, name string, same func() bool, up func(string, io.Reader) error) error {
	prefix := filepath.Join(a.Scratch, scratch)
	file := prefix + "." + strconv.Itoa(pid)
	defer os.Remove(file)
	// Whether the process is still the one that was found is asked before
	// it is dumped and again before the core is sent (see same): a core of
	// another process that came by the number is deleted here, unsent.
	if !same() {
		return replaced(pid)
	}
	// What the gcore script of gdb does, with gdb told to run no scripts
	// of the program's (coredesc.NoScripts), which the script cannot be told.
	dump := append(slices.Clone(coredesc.NoScripts), "--nx", "--batch", "--readnever", "-iex", "set debuginfod enabled off",
		"-ex", "set pagination off", "-ex", "set height 0", "-ex", "set width 0",
		"-ex", "attach "+strconv.Itoa(pid), "-ex", "gcore "+file, "-ex", "detach", "-ex", "quit")
	cmd := exec.CommandContext(ctx, "gdb", dump...)
	cmd.Stdin = nil
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("gcore: %w: %s", err, tail(out))
	} else if _, missing := os.Stat(file); missing != nil {
		// gdb ends well also when it could not attach or write.
		return fmt.Errorf("gcore: %s", tail(out))
	}
	if !same() {
		return replaced(pid)
	}
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := up(name, f); err != nil {
		return err
	}
	a.describe(ctx, file, "/proc/"+strconv.Itoa(pid)+"/root", name, pid, up)
	return nil
}

// logs uploads the containers' logs. After a crash they are those of both
// instances of each container.
func (a *Agent) logs(ctx, frame context.Context, pod *corev1.Pod, rec api.Recording, crashed bool, duration time.Duration, up func(string, io.Reader) error) error {
	opts := corev1.PodLogOptions{Previous: rec.Params["previous"] == "true", Follow: duration > 0, Timestamps: true}
	if v := rec.Params["tailLines"]; v != "" {
		n, _ := strconv.ParseInt(v, 10, 64)
		opts.TailLines = &n
	}
	if duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(frame, duration)
		defer cancel()
	}
	type instance struct {
		previous bool
		suffix   string
	}
	instances := []instance{{opts.Previous, ".log"}}
	if crashed {
		// The crashed instance is the current one until the kubelet restarts
		// the container and the previous one from then on. Reading the
		// current one first cannot miss it.
		instances = []instance{{false, ".log"}, {true, ".previous.log"}}
	}
	uploaded := 0
	for _, c := range pod.Spec.Containers {
		if want := rec.Params["container"]; want != "" && want != c.Name {
			continue
		}
		for _, i := range instances {
			o := opts
			o.Container, o.Previous = c.Name, i.previous
			stream, err := a.Kube.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &o).Stream(ctx)
			if err != nil {
				if i.previous || crashed {
					continue // this container has no such instance
				}
				return err
			}
			// A followed stream ends with the duration; what arrived until
			// then is the result.
			err = up(c.Name+i.suffix, untilDeadline{stream, ctx})
			stream.Close()
			if err != nil {
				return err
			}
			uploaded++
		}
	}
	if uploaded == 0 {
		return errors.New("no container has such logs")
	}
	return nil
}

// untilDeadline turns the end of a bounded recording into a clean end of the
// stream.
type untilDeadline struct {
	r   io.Reader
	ctx context.Context
}

func (u untilDeadline) Read(p []byte) (int, error) {
	n, err := u.r.Read(p)
	if err != nil && u.ctx.Err() != nil { // the time frame ended, or the user stopped it
		err = io.EOF
	}
	return n, err
}

// record runs a tool and uploads its standard output while it runs. With a
// duration, the tool is interrupted after it, or when frame ends before,
// and its output up to then is the result.
func (a *Agent) record(ctx, frame context.Context, duration time.Duration, name string, up func(string, io.Reader) error, tool string, args ...string) error {
	run := ctx
	if duration > 0 {
		var cancel context.CancelFunc
		run, cancel = context.WithTimeout(frame, duration)
		defer cancel()
	}
	cmd := exec.CommandContext(run, tool, args...)
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGINT) } // lets the tool flush
	cmd.WaitDelay = 10 * time.Second
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	uploadErr := up(name, out)
	io.Copy(io.Discard, out)
	err = cmd.Wait()
	switch {
	case ctx.Err() != nil:
		return ctx.Err()
	case uploadErr != nil:
		return uploadErr
	case err != nil && run.Err() == nil:
		return fmt.Errorf("%s: %w: %s", tool, err, tail(stderr.Bytes()))
	}
	return nil
}

// describe uploads the description of a core that was uploaded as name,
// and the program's files that the core maps, found under root. The core
// is the evidence; a description that fails is only logged.
// pid is the process on the node that the agent took the core of, or 0 for
// a core that the kernel wrote.
func (a *Agent) describe(ctx context.Context, core, root, name string, pid int, up func(string, io.Reader) error) {
	describer := coredesc.Describer{Scratch: a.Scratch, DebuginfodURLs: a.DebuginfodURLs}
	if pid != 0 {
		describer.ThreadIDs = coredesc.NamespaceThreadIDs(a.Proc, pid)
	}
	report, err := describer.Describe(ctx, core, root)
	if err == nil {
		err = up(name+coredesc.Suffix, bytes.NewReader(report))
	}
	if err != nil {
		slog.Warn("core not described", "core", name, "error", err)
		// The program's files are kept all the same: with them the hub
		// can describe the core when it is opened.
		report = coredesc.Mapped(core)
	}
	if files := coredesc.Files(report, root); root != "" && len(files) > 0 {
		archive, w := io.Pipe()
		go func() { w.CloseWithError(coredesc.WriteFiles(w, root, files)) }()
		err := up(name+coredesc.FilesSuffix, archive)
		archive.Close()
		if err != nil {
			slog.Warn("program files not kept", "core", name, "error", err)
		}
	}
	// Delve reads the tables of the whole program to describe a Go core,
	// hundreds of megabytes for a large one. The agent describes cores
	// rarely: what that took goes back to the node now, not when the
	// runtime gets round to it.
	debug.FreeOSMemory()
}

func tail(b []byte) string {
	b = bytes.TrimSpace(b)
	if len(b) > 400 {
		b = b[len(b)-400:]
	}
	return string(b)
}

// podPID returns the node PID of a process in the pod's network namespace:
// the main process of its first running container. known is what a capture
// has found of the pod's processes, or nil.
func (a *Agent) podPID(pod *corev1.Pod, known *processes) (int, error) {
	err := fmt.Errorf("pod %s has no running container", pod.Name)
	for _, c := range pod.Spec.Containers {
		var pid int
		if pid, _, err = a.containerPID(pod, c.Name, known); err == nil {
			return pid, nil
		}
	}
	return 0, err
}

// containerPID returns the node PID of a container's main process. An empty
// name selects the pod's first container.
func (a *Agent) containerPID(pod *corev1.Pod, name string, known *processes) (int, string, error) {
	id, name, err := runningID(pod, name)
	if err != nil {
		return 0, name, err
	}
	_, pid, err := known.of(a, pod, id)
	return pid, name, err
}

// processes remembers the processes of a pod's containers for one capture.
// The capture's recordings run at once and each ask for them, and finding
// them reads a file of every process on the node: that is done once per
// container. A nil one remembers nothing.
type processes struct {
	mu    sync.Mutex
	found map[string]func() containerProcesses // by container ID
}

type containerProcesses struct {
	all  []int
	main int
	err  error
	// started is when each process started, by which it is told from
	// another that has its number later.
	started map[int]uint64
}

// of returns the processes of a container of the pod, and its main process.
func (p *processes) of(a *Agent, pod *corev1.Pod, containerID string) ([]int, int, error) {
	if p == nil {
		return containerPIDs(a.Proc, containerID, a.own(pod))
	}
	p.mu.Lock()
	find := p.found[containerID]
	if find == nil {
		// Who asks meanwhile waits for the one search.
		find = sync.OnceValue(func() (c containerProcesses) {
			c.all, c.main, c.started, c.err = containerProcessesOf(a.Proc, containerID, a.own(pod))
			return c
		})
		if p.found == nil {
			p.found = map[string]func() containerProcesses{}
		}
		p.found[containerID] = find
	}
	p.mu.Unlock()
	c := find()
	return c.all, c.main, c.err
}

// replaced is said of a process that was found and is no longer the one
// with its number.
func replaced(pid int) error {
	return fmt.Errorf("process %d of the container ended and its number went to another process: nothing of that one is kept", pid)
}

// sentIf sends what was recorded only if the check still holds when it is
// complete.
func sentIf(holds func() error, up func(string, io.Reader) error) func(string, io.Reader) error {
	return func(name string, body io.Reader) error {
		if err := holds(); err != nil {
			return err
		}
		return up(name, body)
	}
}

// startOf returns when a process started, in the kernel's ticks since the
// node's start, or 0 for one that is gone.
func startOf(proc string, pid int) uint64 {
	stat, err := os.ReadFile(filepath.Join(proc, strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0
	}
	// After the name, which may hold spaces and parentheses, the 20th field.
	fields := strings.Fields(string(stat[bytes.LastIndexByte(stat, ')')+1:]))
	if len(fields) < 20 {
		return 0
	}
	started, _ := strconv.ParseUint(fields[19], 10, 64)
	return started
}

// same tells whether a process is still the one that was found. The
// processes are looked for once per capture, and a recording may come to
// one of them minutes later, after a large core was written: by then the
// process can have ended and its number been given to another one, of the
// node or of someone else's pod, which a workload can bring about by
// starting processes until the numbers come round. A process with the same
// number and the same start is the same. Asked before a tool is set on a
// process and again before what it recorded is sent, this keeps what is
// uploaded to the container's own. A nil receiver looked just now and
// remembers nothing.
func (p *processes) same(proc string, pid int) bool {
	if p == nil {
		return true
	}
	p.mu.Lock()
	finds := make([]func() containerProcesses, 0, len(p.found))
	for _, find := range p.found {
		finds = append(finds, find)
	}
	p.mu.Unlock()
	for _, find := range finds {
		if started, known := find().started[pid]; known {
			return started != 0 && started == startOf(proc, pid)
		}
	}
	return false
}

// runningID returns the ID of a container of the pod that runs. An empty
// name selects the pod's first container.
func runningID(pod *corev1.Pod, name string) (string, string, error) {
	if name == "" {
		name = pod.Spec.Containers[0].Name
	}
	for _, s := range pod.Status.ContainerStatuses {
		if s.Name != name {
			continue
		}
		_, id, ok := strings.Cut(s.ContainerID, "://")
		if !ok || s.State.Running == nil {
			return "", name, fmt.Errorf("container %s is not running", name)
		}
		return id, name, nil
	}
	return "", name, fmt.Errorf("pod %s has no container %s", pod.Name, name)
}

// mainPIDs remembers the main processes of a pod's containers for something
// that asks again and again. Finding one reads a file of every process on
// the node, and it stays the same for as long as the container's ID does.
type mainPIDs map[string]foundPID // by container name

type foundPID struct {
	id  string // of the container
	pid int
}

// of returns the node PID of the named container's main process. What it
// remembers costs one read to confirm: that the process is still in the
// container, since the ID of a process that ended is given to another.
func (m mainPIDs) of(a *Agent, pod *corev1.Pod, name string) (int, error) {
	id, name, err := runningID(pod, name)
	if err != nil {
		delete(m, name)
		return 0, err
	}
	own := a.own(pod)
	if found := m[name]; found.id == id && inContainer(a.Proc, found.pid, id, ownCgroup(a.Proc, own)) {
		return found.pid, nil
	}
	delete(m, name)
	pid, err := mainPID(a.Proc, id, own)
	if err == nil {
		m[name] = foundPID{id, pid}
	}
	return pid, err
}

// mainPID finds a container's main process in the node's /proc.
func mainPID(proc, containerID string, own bool) (int, error) {
	_, main, err := containerPIDs(proc, containerID, own)
	return main, err
}

// own tells whether a pod is the agent's own.
func (a *Agent) own(pod *corev1.Pod) bool { return a.Pod != "" && pod.Name == a.Pod }

// containerPIDs finds the processes of a container in the node's /proc and
// its main process: the oldest one in the container's cgroup whose parent is
// outside of it (an exec session also has such a parent, but started later).
//
// A cgroup is told by the container's ID in its path. Of its own container
// (own) the agent sees no such path: the kernel shows a process its own
// cgroup as the root of its cgroup namespace. There the processes are those
// whose cgroup reads like the agent's own.
func containerPIDs(proc, containerID string, own bool) (all []int, main int, err error) {
	all, main, _, err = containerProcessesOf(proc, containerID, own)
	return all, main, err
}

// containerProcessesOf is containerPIDs with the time each process
// started, from the same reading that showed it to be the container's: a
// number that went to another process a moment later is then not taken
// for the one that was found.
func containerProcessesOf(proc, containerID string, own bool) (all []int, main int, begun map[int]uint64, err error) {
	begun = map[int]uint64{}
	mine := ownCgroup(proc, own)
	inside := func(pid int) bool { return inContainer(proc, pid, containerID, mine) }
	entries, err := os.ReadDir(proc)
	if err != nil {
		return nil, 0, nil, err
	}
	oldest := uint64(0)
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || !inside(pid) {
			continue
		}
		stat, err := os.ReadFile(filepath.Join(proc, e.Name(), "stat"))
		if err != nil {
			continue
		}
		all = append(all, pid)
		// "pid (comm) state ppid ... starttime ..."; comm may contain spaces
		// and parentheses. After it, ppid is field 2 and starttime field 20.
		fields := strings.Fields(string(stat[bytes.LastIndexByte(stat, ')')+1:]))
		if len(fields) < 20 {
			continue
		}
		ppid, err1 := strconv.Atoi(fields[1])
		started, err2 := strconv.ParseUint(fields[19], 10, 64)
		if err2 == nil {
			begun[pid] = started
		}
		if err1 == nil && err2 == nil && !inside(ppid) && (main == 0 || started < oldest) {
			main, oldest = pid, started
		}
	}
	if main == 0 {
		return nil, 0, nil, fmt.Errorf("no process of the container (%.12s) is visible on this node", containerID)
	}
	return all, main, begun, nil
}

// ownCgroup returns how the agent's own cgroup reads, for a container that
// is the agent's own, and nothing for any other.
func ownCgroup(proc string, own bool) []byte {
	if !own {
		return nil
	}
	mine, _ := os.ReadFile(filepath.Join(proc, "self", "cgroup"))
	return mine
}

// inContainer tells whether a process is in a container's cgroup: one with
// the container's ID in its path, or one that reads like mine.
func inContainer(proc string, pid int, containerID string, mine []byte) bool {
	b, err := os.ReadFile(filepath.Join(proc, strconv.Itoa(pid), "cgroup"))
	return err == nil && (bytes.Contains(b, []byte(containerID)) || len(mine) > 0 && bytes.Equal(b, mine))
}

// executable returns the path of a process's program, as the process sees it.
func executable(proc string, pid int) string {
	path, _ := os.Readlink(filepath.Join(proc, strconv.Itoa(pid), "exe"))
	return strings.TrimSuffix(path, " (deleted)")
}

// targets returns the node PIDs to dump or trace in a container: its main
// process, or with an executable every process that runs that program.
func (a *Agent) targets(pod *corev1.Pod, container, program string, known *processes) ([]int, string, error) {
	main, container, err := a.containerPID(pod, container, known)
	if err != nil || program == "" {
		return []int{main}, container, err
	}
	var pids []int
	for _, s := range pod.Status.ContainerStatuses {
		if _, id, ok := strings.Cut(s.ContainerID, "://"); ok && s.Name == container {
			all, _, _ := known.of(a, pod, id)
			for _, pid := range all {
				if executable(a.Proc, pid) == program {
					pids = append(pids, pid)
				}
			}
		}
	}
	if len(pids) == 0 {
		return nil, container, fmt.Errorf("no process in container %s of pod %s runs %s", container, pod.Name, program)
	}
	return pids, container, nil
}
