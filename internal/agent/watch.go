package agent

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
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
		if packets := w.Recording(api.KindPcap); packets != nil {
			a.buffer(ctx, w, *packets, pod)
		}
		if w.Recording(api.KindCoredump) != nil && w.When.Crash() && a.Cores != "" && !marked[string(pod.UID)] {
			// From now on the node's core handler keeps this pod's cores.
			if err := os.WriteFile(a.Cores.marker(string(pod.UID), w.ID), nil, 0o600); err != nil {
				slog.Error("core handler marker", "pod", pod.Name, "error", err)
			}
			marked[string(pod.UID)] = true
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
	default:
		return crashes(pod, seen)
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
		if known && before != count && s.State.Running == nil {
			continue // counted, but not running yet: the next change tells
		}
		seen[key] = count
		if !known || before == count || pod.DeletionTimestamp != nil {
			continue
		}
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
	r := &ring{window: time.Duration(w.DurationSeconds) * time.Second, limit: ringBytes, payload: packets.Params["payload"] == "true", stop: stop}
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
