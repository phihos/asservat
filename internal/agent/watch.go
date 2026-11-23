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
	"time"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
			a.watching[w.ID] = cancel
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

// observe follows the watched workload's pods on this node through a
// Kubernetes watch until ctx ends. It reports a pod that meets the watch's
// condition to the hub and, for a packet watch, keeps a buffer of each
// pod's packets. A report continues under the agent's context: the hub ends
// the watch while it answers the last report it waited for.
func (a *Agent) observe(agent, ctx context.Context, w api.Watch) {
	options := func(o metav1.ListOptions) metav1.ListOptions {
		selected := podOptions(w.Workload, w.Selector)
		o.LabelSelector = selected.LabelSelector
		o.FieldSelector = strings.TrimPrefix(selected.FieldSelector+",spec.nodeName="+a.Node, ",")
		return o
	}
	pods := a.Kube.CoreV1().Pods(w.Namespace)
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
	changed := func(obj any, known bool) {
		pod := obj.(*corev1.Pod)
		if pod.Spec.NodeName != a.Node {
			return
		}
		if packets := w.Recording(api.KindPcap); packets != nil && packets.Buffers() {
			a.buffer(ctx, w, *packets, pod)
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
		if w.When.Kind == api.OnLog || w.When.Usage() {
			// The pod is read from once a container of it runs.
			if t, reads := tending[pod.Name]; reads {
				t.pod.Store(pod)
			} else if pod.Status.Phase == corev1.PodRunning && pod.DeletionTimestamp == nil {
				reading, stop := context.WithCancel(ctx)
				t := tended{stop: stop, pod: &atomic.Pointer[corev1.Pod]{}}
				t.pod.Store(pod)
				tending[pod.Name] = t
				if w.When.Usage() {
					go a.measure(agent, reading, w, t.pod)
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
	_, informer := cache.NewInformerWithOptions(cache.InformerOptions{ListerWatcher: source, ObjectType: &corev1.Pod{}, Handler: cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { changed(obj, false) },
		UpdateFunc: func(_, obj any) { changed(obj, true) },
		DeleteFunc: func(obj any) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				return // a tombstone of a pod whose deletion was missed
			}
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
		},
	}})
	informer.RunWithContext(ctx)
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
	a.mu.Lock()
	if r := a.rings[w.ID+"/"+pod]; r != nil {
		a.snapshots[id] = r.snapshot()
	}
	a.mu.Unlock()
	slog.Info("watch met", "watch", w.ID, "pod", pod, "message", message)
	if err := a.post(ctx, "/agent/watches/"+w.ID+"/trigger", api.Trigger{ID: id, Pod: pod, Node: a.Node, Message: message}); err != nil {
		// Also when the watch ended with another pod's report.
		slog.Info("watch not recorded", "watch", w.ID, "pod", pod, "error", err)
		a.mu.Lock()
		delete(a.snapshots, id)
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
	args := []string{"-t", strconv.Itoa(pid), "-n", "tcpdump", "-Z", "root", "-i", "any", "-U", "-w", "-", withoutOwnTraffic(packets.Params["filter"])}
	cmd := exec.CommandContext(ctx, "nsenter", args...)
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
	// Payload is kept only for a watch that asked for it and was approved.
	r := &ring{window: w.Before(), limit: ringBytes, payload: packets.Params["payload"] == "true", stop: stop}
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
	window  time.Duration      // how far back the packets reach
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
		r.packets = append(r.packets, append(bytes.Clone(record), packet...))
		r.seconds = append(r.seconds, second)
		r.size += len(record) + len(packet)
		drop := 0
		for drop < len(r.packets)-1 && (r.size > r.limit || int64(second)-int64(r.seconds[drop]) > int64(r.window/time.Second)) {
			r.size -= len(r.packets[drop])
			drop++
		}
		r.packets, r.seconds = r.packets[drop:], r.seconds[drop:]
		r.mu.Unlock()
	}
}

// snapshot returns the buffered packets as a pcap file, or nil before the
// stream began.
func (r *ring) snapshot() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.header == nil {
		return nil
	}
	return bytes.Join(append([][]byte{r.header}, r.packets...), nil)
}

// follow reads what the pod's containers write from now on, through the
// Kubernetes log stream, and reports to the hub when a line matches the
// watch's pattern. It ends with ctx, which the pod's deletion or the
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

// clip shortens a log line for a capture's reason, which a person reads in a list.
func clip(line string) string {
	const most = 200
	if len(line) <= most {
		return line
	}
	return strings.ToValidUTF8(line[:most], "") + "…"
}
