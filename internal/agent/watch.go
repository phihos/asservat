package agent

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"

	"asservat.local/asservat/internal/api"
)

// setWatches makes the agent observe exactly the given watches.
func (a *Agent) setWatches(ctx context.Context, list []api.Watch) {
	a.mu.Lock()
	defer a.mu.Unlock()
	wanted := map[string]bool{}
	for _, w := range list {
		wanted[w.ID] = true
		if _, ok := a.watching[w.ID]; !ok {
			watching, cancel := context.WithCancel(ctx)
			// A watch ends with the report of its last time, before the
			// capture that this report starts has arrived and used what the
			// watch kept running. So an ended watch is observed a while
			// longer: for the capture's time frame and the half minute in
			// which its task arrives. Its reports meanwhile find no watch.
			linger := time.Duration(w.DurationSeconds)*time.Second + 30*time.Second
			a.watching[w.ID] = func() { time.AfterFunc(linger, cancel) }
			go a.observe(ctx, watching, w)
		}
	}
	for id, cancel := range a.watching {
		if !wanted[id] {
			cancel()
			delete(a.watching, id)
		}
	}
}

// podWatch returns the Kubernetes watch of this node's pods, which all the
// agent's watches share: the API server serves one watch per node, however
// many watches wait. It starts with the first of them, and release stops
// it after the last.
func (a *Agent) podWatch(ctx context.Context) (informer cache.SharedInformer, release func()) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pods.users == 0 {
		options := func(o metav1.ListOptions) metav1.ListOptions {
			o.FieldSelector = "spec.nodeName=" + a.Node
			return o
		}
		pods := a.Kube.CoreV1().Pods(metav1.NamespaceAll)
		// The wrapper tells the informer whether the client can stream the
		// initial list.
		source := cache.ToListWatcherWithWatchListSemantics(&cache.ListWatch{
			ListWithContextFunc: func(ctx context.Context, o metav1.ListOptions) (runtime.Object, error) {
				return pods.List(ctx, options(o))
			},
			WatchFuncWithContext: func(ctx context.Context, o metav1.ListOptions) (watch.Interface, error) {
				return pods.Watch(ctx, options(o))
			},
		}, a.Kube)
		running, stop := context.WithCancel(ctx)
		a.pods.informer, a.pods.stop = cache.NewSharedInformer(source, &corev1.Pod{}, 0), stop
		go a.pods.informer.RunWithContext(running)
	}
	a.pods.users++
	return a.pods.informer, func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.pods.users--; a.pods.users == 0 {
			a.pods.stop()
		}
	}
}

// observe follows the watched workload's pods on this node, as the
// Kubernetes watch of the node's pods tells of them, until ctx ends. It
// reports a pod that meets the watch's condition to the hub and, for a
// packet watch, keeps a buffer of each pod's packets. A report continues
// under the agent's context: the hub ends the watch while it answers the
// last report it waited for.
func (a *Agent) observe(agent, ctx context.Context, w api.Watch) {
	selector, err := labels.Parse(podOptions(w.Workload, w.Selector).LabelSelector)
	if err != nil {
		slog.Error("watch", "watch", w.ID, "error", err) // the hub read it from the workload
		return
	}
	// of returns the pod that a change is about if it is one of the watch's
	// workload on this node, and nil otherwise.
	of := func(obj any) *corev1.Pod {
		pod, ok := obj.(*corev1.Pod) // or a tombstone of a pod whose deletion was missed
		if !ok || pod.Spec.NodeName != a.Node || pod.Namespace != w.Namespace || !selector.Matches(labels.Set(pod.Labels)) {
			return nil
		}
		if kind, name, _ := strings.Cut(w.Workload, "/"); kind == "Pod" && name != pod.Name {
			return nil
		}
		return pod
	}
	// The handlers run one at a time. A pod's first sighting only records
	// the state it is in: what happened before is not reported.
	seen := map[string]string{}
	marked := map[string]bool{} // pod UIDs whose cores the node's handler keeps
	// The pods that a watch for a log line or for what a container uses
	// keeps reading: how to stop that, and the pod as last seen.
	type tended struct {
		stop context.CancelFunc
		pod  *atomic.Pointer[corev1.Pod]
	}
	tending := map[string]tended{}
	defer func() {
		for uid := range marked {
			a.Cores.unmark(uid, w.ID)
		}
	}()
	changed := func(pod *corev1.Pod, known bool) {
		if packets := w.Recording(api.KindPcap); packets != nil && packets.Buffers() {
			a.buffer(ctx, w, *packets, pod)
		}
		if trace := w.Recording(api.KindStrace); trace != nil && trace.Buffers() {
			a.trace(ctx, w, *trace, pod)
		}
		// The sampled profiles that the watch keeps running reach back as well.
		for _, kind := range []sampledKind{sampledCPU, sampledMemory} {
			if rec := w.Recording(kind.recording); rec != nil && rec.Buffers() {
				a.keep(ctx, w, kind, pod)
			}
		}
		if w.Recording(api.KindCoredump) != nil && w.When.Crash() && a.Cores != "" && !marked[string(pod.UID)] {
			// From now on the node's core handler keeps this pod's cores.
			if err := os.WriteFile(a.Cores.marker(string(pod.UID), w.ID), nil, 0o600); err != nil {
				slog.Error("core handler marker", "pod", pod.Name, "error", err)
			}
			marked[string(pod.UID)] = true
		}
		if w.When.Kind == api.OnLog || w.When.Kind == api.OnEvent || w.When.Usage() {
			// The pod is read from once a container of it runs; Kubernetes
			// warns most about a pod before that.
			if t, reads := tending[pod.Name]; reads {
				t.pod.Store(pod)
			} else if (pod.Status.Phase == corev1.PodRunning || w.When.Kind == api.OnEvent) && pod.DeletionTimestamp == nil {
				reading, stop := context.WithCancel(ctx)
				t := tended{stop: stop, pod: &atomic.Pointer[corev1.Pod]{}}
				t.pod.Store(pod)
				tending[pod.Name] = t
				if w.When.Usage() {
					go a.measure(agent, reading, w, t.pod)
				} else if w.When.Kind == api.OnEvent {
					go a.warned(agent, reading, w, pod.DeepCopy())
				} else {
					go a.follow(agent, reading, w, pod.DeepCopy())
				}
			}
			return
		}
		if message := met(w.When, pod, seen); message != "" && known {
			go a.trigger(agent, w, pod, message)
		}
	}
	gone := func(pod *corev1.Pod) {
		for key := range seen {
			if strings.HasPrefix(key, pod.Name+"/") {
				delete(seen, key)
			}
		}
		if marked[string(pod.UID)] {
			a.Cores.unmark(string(pod.UID), w.ID)
			delete(marked, string(pod.UID))
		}
		if t, reads := tending[pod.Name]; reads {
			t.stop()
			delete(tending, pod.Name)
		}
		a.mu.Lock()
		// A new pod of the same name gets its own buffer at once.
		if r := a.rings[w.ID+"/"+pod.Name]; r != nil {
			r.stop()
			delete(a.rings, w.ID+"/"+pod.Name)
		}
		a.mu.Unlock()
	}
	pods, release := a.podWatch(agent)
	defer release()
	// A watch that comes later is told of the pods that are already known
	// as added, like the first one.
	told, err := pods.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			if pod := of(obj); pod != nil {
				changed(pod, false)
			}
		},
		// A pod can come to the workload's selector and leave it.
		UpdateFunc: func(old, obj any) {
			if was, pod := of(old), of(obj); pod != nil {
				changed(pod, was != nil)
			} else if was != nil {
				gone(was)
			}
		},
		DeleteFunc: func(obj any) {
			if pod := of(obj); pod != nil {
				gone(pod)
			}
		},
	})
	if err != nil {
		slog.Error("watch", "watch", w.ID, "error", err)
		return
	}
	<-ctx.Done()
	// Waits for the handler that runs, before what the watch held is given up.
	cache.ShutDownEventHandler(pods, told)
}

// met describes how the pod has come to meet a condition since the last
// call, or returns "". seen remembers what was reported and the state the
// pod was in.
func met(when api.Condition, pod *corev1.Pod, seen map[string]string) string {
	switch when.Kind {
	case api.OnRestart:
		return restarts(pod, seen)
	case api.OnNotReady:
		return unready(pod, seen)
	case api.OnCrash, "":
		return crashes(pod, seen)
	default: // told by something else than the agent, such as an alert
		return ""
	}
}

// restarts describes the containers of the pod that were started again
// since the last call, whatever ended them: a failure, a clean exit or a
// failed liveness probe. A restart is reported once the new instance runs,
// so that the capture finds its process.
func restarts(pod *corev1.Pod, seen map[string]string) string {
	var out []string
	for _, s := range append(append([]corev1.ContainerStatus{}, pod.Status.InitContainerStatuses...), pod.Status.ContainerStatuses...) {
		key, count := pod.Name+"/"+s.Name+"/restarts", strconv.Itoa(int(s.RestartCount))
		before, known := seen[key]
		if !known || before == count || pod.DeletionTimestamp != nil {
			seen[key] = count
			continue
		}
		// Counted, but the new instance does not run yet: the report waits
		// for the change that shows it running. A container that fails so
		// fast that it is never seen running is reported at its next restart.
		if waiting := key + "/waiting"; s.State.Running == nil && seen[waiting] != count {
			if seen[waiting] == "" {
				seen[waiting] = count
				continue
			}
		} else if s.State.Running == nil {
			continue
		}
		delete(seen, key+"/waiting")
		seen[key] = count
		ended := "it ended"
		if t := s.LastTerminationState.Terminated; t != nil {
			ended = fmt.Sprintf("it ended with exit code %d, %s", t.ExitCode, t.Reason)
		}
		out = append(out, fmt.Sprintf("container %s was restarted: %s", s.Name, ended))
	}
	return strings.Join(out, "; ")
}

// unready reports a pod that was ready and no longer is, with the reason
// that Kubernetes gives. A pod that is being deleted, and one that has not
// been ready yet, do not count.
func unready(pod *corev1.Pod, seen map[string]string) string {
	key, ready, why := pod.Name+"//ready", "", ""
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodReady {
			ready, why = string(c.Status), c.Message
		}
	}
	before := seen[key]
	seen[key] = ready
	if before != string(corev1.ConditionTrue) || ready == before || ready == "" || pod.DeletionTimestamp != nil {
		return ""
	}
	if why == "" {
		why = "its readiness probe fails"
	}
	return "pod is not ready any more: " + why
}

// crashes describes the containers of the pod that failed since the last
// call: terminated with an exit code other than zero, which includes being
// killed for exceeding the memory limit. seen remembers the reported
// terminations. A pod that is being deleted has no crashes: its containers
// are stopped on purpose.
func crashes(pod *corev1.Pod, seen map[string]string) string {
	if pod.DeletionTimestamp != nil {
		return ""
	}
	var out []string
	for _, s := range append(append([]corev1.ContainerStatus{}, pod.Status.InitContainerStatuses...), pod.Status.ContainerStatuses...) {
		t := s.State.Terminated
		if t == nil {
			t = s.LastTerminationState.Terminated
		}
		if t == nil || t.ExitCode == 0 {
			continue
		}
		// The same termination shows first as the container's state and,
		// after its restart, as its last state.
		key, instance := pod.Name+"/"+s.Name, t.ContainerID
		if instance == "" {
			instance = t.FinishedAt.String()
		}
		if seen[key] == instance {
			continue
		}
		seen[key] = instance
		out = append(out, fmt.Sprintf("container %s crashed: exit code %d, %s", s.Name, t.ExitCode, t.Reason))
	}
	return strings.Join(out, "; ")
}

// trigger reports to the hub that a pod met the watch's condition; the hub
// answers with a capture task for the pod. The packets from before and, after
// a crash, the cores of the crashed processes are set aside for that task.
func (a *Agent) trigger(ctx context.Context, w api.Watch, crashed *corev1.Pod, message string) {
	id, pod := uuid.NewString(), crashed.Name
	if w.Recording(api.KindCoredump) != nil && w.When.Crash() && a.Cores != "" {
		a.Cores.take(string(crashed.UID), id)
	}
	// After a crash the packets up to it are set aside. A pod that goes on
	// is recorded on by its buffer, which the capture reads when it is done.
	a.mu.Lock()
	if r := a.rings[w.ID+"/"+pod]; r != nil && w.When.Crash() {
		a.snapshots[id] = r.snapshot(time.Now().Add(-r.before))
	}
	// Likewise the system calls up to the crash: the trace starts anew with
	// the restarted process.
	if l := a.traces[w.ID+"/"+pod]; l != nil && w.When.Crash() {
		a.calls[id] = setAside{name: l.name, content: l.since(time.Now().Add(-l.before))}
	}
	a.mu.Unlock()
	slog.Info("watch met", "watch", w.ID, "pod", pod, "message", message)
	if err := a.post(ctx, "/agent/watches/"+w.ID+"/trigger", api.Trigger{ID: id, Pod: pod, Node: a.Node, Message: message}); err != nil {
		// Also when the watch ended with another pod's report.
		slog.Info("watch not recorded", "watch", w.ID, "pod", pod, "error", err)
		a.mu.Lock()
		delete(a.snapshots, id)
		delete(a.calls, id)
		a.mu.Unlock()
		if a.Cores != "" {
			os.RemoveAll(a.Cores.taken(id))
		}
	}
}

// buffer keeps the packet headers of the watch's last seconds in memory,
// from tcpdump in the pod's network namespace, unless it already does. If no
// container of the pod runs yet, or after tcpdump ended, the pod's next
// change tries again.
func (a *Agent) buffer(ctx context.Context, w api.Watch, packets api.Recording, pod *corev1.Pod) {
	key := w.ID + "/" + pod.Name
	a.mu.Lock()
	_, buffering := a.rings[key]
	a.mu.Unlock()
	if buffering {
		return
	}
	pid, err := a.podPID(pod)
	if err != nil {
		return
	}
	ctx, stop := context.WithCancel(ctx)
	// Payload is kept only for a watch that asked for it and was approved.
	payload := packets.Params["payload"] == "true"
	cmd := exec.CommandContext(ctx, "nsenter", tcpdumpArgs(pid, packets.Params["filter"], payload)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err == nil {
		err = cmd.Start()
	}
	if err != nil {
		slog.Error("packet buffer", "pod", pod.Name, "error", err)
		stop()
		return
	}
	// The buffer holds what a capture wants: the seconds before it, its
	// time frame after it, and some more for the task to arrive.
	r := &ring{before: w.Before(), window: w.Before() + time.Duration(w.DurationSeconds)*time.Second + 10*time.Second, limit: ringBytes, payload: payload, stop: stop}
	a.mu.Lock()
	a.rings[key] = r
	a.mu.Unlock()
	go func() {
		err := r.fill(out)
		cmd.Wait()
		if ctx.Err() == nil {
			slog.Warn("packet buffer ended", "pod", pod.Name, "error", err, "tcpdump", tail(stderr.Bytes()))
		}
		stop()
		a.mu.Lock()
		if a.rings[key] == r {
			delete(a.rings, key)
		}
		a.mu.Unlock()
	}()
}

// ringBytes bounds the packet buffer of one pod: it lives in the agent's
// memory. Headers take about 100 bytes per packet, so this holds roughly
// 150,000 packets, or fewer with payload; older ones are dropped first.
const ringBytes = 16 << 20

// ring holds the most recent packets of a pcap stream, cut after their
// transport headers unless payload is set.
type ring struct {
	payload bool
	before  time.Duration      // how far before a capture its packets reach
	window  time.Duration      // how far back the packets are held
	limit   int                // bytes
	stop    context.CancelFunc // ends the tool that fills the ring

	mu      sync.Mutex
	header  []byte   // the pcap file header
	packets [][]byte // record header and bytes of each packet, oldest first
	seconds []uint32 // each packet's timestamp
	size    int
}

// fill reads a pcap stream into the ring until the stream ends.
func (r *ring) fill(src io.Reader) error {
	packets, err := newPacketReader(src)
	if err != nil || packets == nil {
		return err
	}
	packets.payload = r.payload
	r.mu.Lock()
	r.header = packets.header
	r.mu.Unlock()
	for {
		record, packet, err := packets.next()
		if err != nil || record == nil {
			return err
		}
		second := packets.order.Uint32(record)
		r.mu.Lock()
		r.packets = append(r.packets, append(append(make([]byte, 0, len(record)+len(packet)), record...), packet...))
		r.seconds = append(r.seconds, second)
		r.size += len(record) + len(packet)
		drop := 0
		for drop < len(r.packets)-1 && (r.size > r.limit || int64(second)-int64(r.seconds[drop]) > int64(r.window/time.Second)) {
			r.size -= len(r.packets[drop])
			drop++
		}
		// Cleared, or the dropped packets stay in memory until the list is
		// next copied to grow.
		clear(r.packets[:drop])
		r.packets, r.seconds = r.packets[drop:], r.seconds[drop:]
		r.mu.Unlock()
	}
}

// snapshot returns the buffered packets from a moment on as a pcap file, or
// nil before the stream began.
func (r *ring) snapshot(from time.Time) []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.header == nil {
		return nil
	}
	first := 0
	for first < len(r.packets) && int64(r.seconds[first]) < from.Unix() {
		first++
	}
	return bytes.Join(append([][]byte{r.header}, r.packets[first:]...), nil)
}

// setAside is a file's content that the agent kept at a crash, for the
// capture of that crash.
type setAside struct {
	name    string
	content []byte
}

// lines holds the most recent lines of a tool's output, each with the
// moment it was read.
type lines struct {
	name   string             // the file that a capture stores them as
	ended  atomic.Bool        // the tool has ended, with its process
	before time.Duration      // how far before a capture its lines reach
	window time.Duration      // how far back the lines are held
	limit  int                // bytes
	stop   context.CancelFunc // ends the tool that writes them

	mu   sync.Mutex
	at   []time.Time
	text [][]byte // with their line ends, oldest first
	size int
}

// fill reads lines into the buffer until the stream ends, dropping those
// out of the window and the oldest over the limit.
func (l *lines) fill(src io.Reader) {
	stream := bufio.NewReaderSize(src, 64<<10)
	for {
		line, err := stream.ReadBytes('\n')
		if len(line) > 0 {
			now := time.Now()
			l.mu.Lock()
			l.at, l.text, l.size = append(l.at, now), append(l.text, line), l.size+len(line)
			drop := 0
			for drop < len(l.text)-1 && (l.size > l.limit || now.Sub(l.at[drop]) > l.window) {
				l.size -= len(l.text[drop])
				drop++
			}
			clear(l.text[:drop]) // as for packets: or they stay in memory
			l.at, l.text = l.at[drop:], l.text[drop:]
			l.mu.Unlock()
		}
		if err != nil {
			return
		}
	}
}

// since returns the lines read from a moment on.
func (l *lines) since(from time.Time) []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	first := 0
	for first < len(l.text) && l.at[first].Before(from) {
		first++
	}
	return bytes.Join(l.text[first:], nil)
}

// trace keeps tracing the system calls of the pod's process for a watch,
// unless it already does, and holds the last of them in memory: as many
// bytes as of packets. The tracing ends with its process; the pod's next
// change then starts it for the restarted one.
func (a *Agent) trace(ctx context.Context, w api.Watch, rec api.Recording, pod *corev1.Pod) {
	key := w.ID + "/" + pod.Name
	a.mu.Lock()
	running := a.traces[key]
	a.mu.Unlock()
	if running != nil && !running.ended.Load() {
		return
	}
	pids, container, err := a.targets(pod, rec.Params["container"], rec.Params["process"])
	if err != nil {
		return // no such process yet
	}
	ctx, stop := context.WithCancel(ctx)
	cmd := exec.CommandContext(ctx, "strace", straceArgs(rec, pids)...)
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGINT) } // lets it detach
	cmd.WaitDelay = 10 * time.Second
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err == nil {
		err = cmd.Start()
	}
	if err != nil {
		slog.Error("system call buffer", "pod", pod.Name, "error", err)
		stop()
		return
	}
	l := &lines{name: container + ".strace", before: w.Before(), window: w.Before() + time.Duration(w.DurationSeconds)*time.Second + 10*time.Second, limit: ringBytes, stop: stop}
	a.mu.Lock()
	a.traces[key] = l
	a.mu.Unlock()
	if running != nil {
		running.stop() // the buffer of the process that ended makes room
	}
	go func() {
		l.fill(out)
		cmd.Wait()
		if ctx.Err() == nil {
			slog.Info("system call buffer ended with its process", "pod", pod.Name, "strace", tail(stderr.Bytes()))
		}
		// A capture may still want the calls up to the process's end: the
		// buffer stays until tracing starts anew or the watch ends.
		l.ended.Store(true)
		<-ctx.Done()
		a.mu.Lock()
		if a.traces[key] == l {
			delete(a.traces, key)
		}
		a.mu.Unlock()
	}()
}

// follow reads what the pod's containers write from now on and reports to
// the hub when a line matches the watch's pattern. It reads the log files
// on the node, which costs nobody else anything, and where it cannot, the
// Kubernetes log stream. It ends with ctx, which the pod's deletion or the
// watch's end cancels.
func (a *Agent) follow(agent, ctx context.Context, w api.Watch, pod *corev1.Pod) {
	pattern, err := regexp.Compile(w.When.Params["pattern"])
	if err != nil {
		slog.Error("log watch", "watch", w.ID, "error", err) // the hub validated it
		return
	}
	// After a report the pod's lines are passed over for the watch's time
	// frame, or the default time frame where it has none: they belong to
	// the incident whose capture is being made.
	quiet := time.Duration(w.DurationSeconds) * time.Second
	if quiet == 0 {
		quiet = 30 * time.Second
	}
	var mu sync.Mutex
	var reported time.Time
	matched := func(container, line string) {
		mu.Lock()
		again := time.Since(reported) < quiet
		if !again {
			reported = time.Now()
		}
		mu.Unlock()
		if !again {
			a.trigger(agent, w, pod, fmt.Sprintf("a log line of container %s matches %q: %s", container, pattern, clip(line)))
		}
	}
	var wg sync.WaitGroup
	for _, c := range pod.Spec.Containers {
		if want := w.When.Params["container"]; want != "" && want != c.Name {
			continue
		}
		wg.Go(func() {
			files, err := openPodLog(a.podLogDir(pod.Namespace, pod.Name, string(pod.UID), c.Name))
			if err == nil {
				err = files.follow(ctx, func(line []byte) {
					if pattern.Match(line) {
						matched(c.Name, string(line))
					}
				})
			}
			if err == nil {
				return
			}
			// As where the runtime keeps the files elsewhere, or for a pod
			// that the kubelet runs from a file, whose directory is named
			// otherwise.
			slog.Info("log watch reads through the API server", "watch", w.ID, "pod", pod.Name, "container", c.Name, "reason", err)
			since := metav1.Now()
			// A stream ends when its container ends, and also when the
			// kubelet or the API server closes it. Nothing tells when it
			// can be read again, so it is opened again after a pause that
			// grows up to a minute while the stream keeps failing.
			for pause := time.Second; ctx.Err() == nil; pause = min(2*pause, time.Minute) {
				opened := time.Now()
				stream, err := a.Kube.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &corev1.PodLogOptions{Container: c.Name, Follow: true, SinceTime: &since}).Stream(ctx)
				if err == nil {
					matchLines(stream, pattern, func(line string) { matched(c.Name, line) })
					stream.Close()
					since = metav1.Now()
				}
				if time.Since(opened) > 10*time.Second {
					pause = time.Second // it worked for a while
				}
				select {
				case <-ctx.Done():
				case <-time.After(pause):
				}
			}
		})
	}
	wg.Wait()
}

// matchLines calls found for every line of the stream that the pattern
// matches. A line longer than the reader's buffer is matched in pieces.
func matchLines(stream io.Reader, pattern *regexp.Regexp, found func(line string)) {
	lines := bufio.NewReaderSize(stream, 64<<10)
	for {
		line, _, err := lines.ReadLine()
		if len(line) > 0 && pattern.Match(line) {
			found(string(line))
		}
		if err != nil {
			return
		}
	}
}

// warned reports the warnings that Kubernetes gives about a pod with
// events while a watch waits for them: those of the watch's reason, or all.
// The API server sends them as they come; those from before are passed
// over, and so are those of the time frame after a report, which belong to
// the incident whose capture is being made.
func (a *Agent) warned(agent, ctx context.Context, w api.Watch, pod *corev1.Pod) {
	options := func(o metav1.ListOptions) metav1.ListOptions {
		o.FieldSelector = "involvedObject.kind=Pod,involvedObject.name=" + pod.Name + ",involvedObject.uid=" + string(pod.UID) + ",type=" + corev1.EventTypeWarning
		if reason := w.When.Params["reason"]; reason != "" {
			o.FieldSelector += ",reason=" + reason
		}
		return o
	}
	events := a.Kube.CoreV1().Events(pod.Namespace)
	source := cache.ToListWatcherWithWatchListSemantics(&cache.ListWatch{
		ListWithContextFunc: func(ctx context.Context, o metav1.ListOptions) (runtime.Object, error) {
			return events.List(ctx, options(o))
		},
		WatchFuncWithContext: func(ctx context.Context, o metav1.ListOptions) (watch.Interface, error) {
			return events.Watch(ctx, options(o))
		},
	}, a.Kube)
	quiet := time.Duration(w.DurationSeconds) * time.Second
	if quiet == 0 {
		quiet = 30 * time.Second
	}
	var reported time.Time // the handlers run one at a time
	told := func(e *corev1.Event) {
		if message := warning(w.When, pod, e); message != "" && time.Since(reported) >= quiet {
			reported = time.Now()
			go a.trigger(agent, w, pod, message)
		}
	}
	_, informer := cache.NewInformerWithOptions(cache.InformerOptions{ListerWatcher: source, ObjectType: &corev1.Event{}, Handler: cache.ResourceEventHandlerDetailedFuncs{
		AddFunc: func(obj any, before bool) {
			if !before {
				told(obj.(*corev1.Event))
			}
		},
		// Kubernetes counts a warning that repeats in its one event.
		UpdateFunc: func(old, obj any) {
			if was, e := old.(*corev1.Event), obj.(*corev1.Event); occurrences(e) > occurrences(was) {
				told(e)
			}
		},
	}})
	informer.RunWithContext(ctx)
}

// warning describes an event that a watch for events waits for: a warning
// about the pod, of the watch's reason if it names one.
func warning(when api.Condition, pod *corev1.Pod, e *corev1.Event) string {
	if e.Type != corev1.EventTypeWarning || e.InvolvedObject.Kind != "Pod" || e.InvolvedObject.Name != pod.Name {
		return ""
	}
	if reason := when.Params["reason"]; reason != "" && reason != e.Reason {
		return ""
	}
	return "Kubernetes warns: " + e.Reason + ": " + clip(e.Message)
}

// occurrences tells how often the warning of an event has come.
func occurrences(e *corev1.Event) int32 {
	if e.Series != nil {
		return e.Series.Count
	}
	return e.Count
}

// clip shortens a log line for a capture's reason, which a person reads in a list.
func clip(line string) string {
	const most = 200
	if len(line) <= most {
		return line
	}
	return strings.ToValidUTF8(line[:most], "") + "…"
}
