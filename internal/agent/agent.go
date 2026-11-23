// Package agent is the node agent. One runs on every node of a workload
// cluster, connects out to the hub and records evidence from the pods of its
// node. Any agent also answers the hub's questions about its cluster.
package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"k8s.io/client-go/kubernetes"

	"asservat.local/asservat/internal/api"
)

type Agent struct {
	HubURL string
	Token  string
	Node   string
	Kube   kubernetes.Interface
	HTTP   *http.Client
	// Scratch holds a core file until it is uploaded, and the symbols that
	// gdb fetched from debuginfod servers.
	Scratch string
	// DebuginfodURLs are the debuginfod servers, separated by spaces, that
	// gdb asks for the symbols of stripped programs; empty for none.
	DebuginfodURLs string
	// Proc is the node's /proc.
	Proc string
	// Pod is the name of the agent's own pod, whose processes it finds
	// differently than those of other pods; empty if unknown.
	Pod string
	// Cores is the spool of the node's core handler; empty without it.
	Cores CoreSpool

	mu       sync.Mutex
	running  map[string]task               // capture ID + pod -> the running task
	watching map[string]context.CancelFunc // watch ID -> cancel
	// Packet buffers of watched pods by watch ID + pod, and the packets set
	// aside at a crash, by trigger ID, until the hub's task for it arrives.
	rings     map[string]*ring
	snapshots map[string][]byte
	// sampler takes the CPU profiles of pods.
	sampler sampler
	// kept holds the profiles that watches keep running, by watch ID, pod
	// and kind of recording.
	kept map[string]*kept
	// traces holds the system calls that watches keep tracing, by watch ID
	// and pod.
	traces map[string]*lines
	// calls holds the system calls set aside at a crash, by trigger ID,
	// until the hub's task for it arrives.
	calls map[string]setAside
}

// Run keeps the stream to the hub open until ctx ends, reconnecting with a
// growing delay after a failure.
func (a *Agent) Run(ctx context.Context) {
	a.running, a.watching = map[string]task{}, map[string]context.CancelFunc{}
	a.rings, a.snapshots, a.kept, a.traces = map[string]*ring{}, map[string][]byte{}, map[string]*kept{}, map[string]*lines{}
	a.calls = map[string]setAside{}
	delay := time.Second
	for ctx.Err() == nil {
		started := time.Now()
		err := a.stream(ctx)
		if ctx.Err() != nil {
			return
		}
		if time.Since(started) > time.Minute {
			delay = time.Second
		}
		slog.Warn("hub stream ended; reconnecting", "error", err, "in", delay)
		select {
		case <-ctx.Done():
		case <-time.After(delay):
		}
		delay = min(2*delay, 30*time.Second)
	}
}

func (a *Agent) request(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, a.HubURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+a.Token)
	res, err := a.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(res.Body, 1<<10))
		res.Body.Close()
		return nil, fmt.Errorf("%s %s: %s %s", method, path, res.Status, bytes.TrimSpace(msg))
	}
	return res, nil
}

func (a *Agent) post(ctx context.Context, path string, v any) error {
	b, _ := json.Marshal(v)
	res, err := a.request(ctx, http.MethodPost, path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	return res.Body.Close()
}

func (a *Agent) stream(ctx context.Context) error {
	res, err := a.request(ctx, http.MethodGet, "/agent/stream?node="+url.QueryEscape(a.Node), nil)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	slog.Info("connected to the hub", "node", a.Node)
	lines := bufio.NewReader(res.Body)
	for {
		line, err := lines.ReadBytes('\n')
		if err != nil {
			return err
		}
		var c api.Command
		if err := json.Unmarshal(line, &c); err != nil {
			return err
		}
		a.handle(ctx, c)
	}
}

// handle acts on one command of the hub.
func (a *Agent) handle(ctx context.Context, c api.Command) {
	switch c.Type {
	case "sync":
		// Stop what is no longer open (cancelled or deleted while the
		// stream was down), then start what was missed.
		open := map[string]bool{}
		for _, t := range c.Tasks {
			open[t.ID+"/"+t.Task.Pod] = true
		}
		a.mu.Lock()
		for key, t := range a.running {
			if !open[key] {
				t.cancel()
			}
		}
		a.mu.Unlock()
		for _, t := range c.Tasks {
			a.start(ctx, t.ID, *t.Task)
		}
		a.setWatches(ctx, c.Watches)
	case "watches":
		a.setWatches(ctx, c.Watches)
	case "query":
		go func() {
			r := a.answer(ctx, *c.Query)
			if err := a.post(ctx, "/agent/replies/"+c.ID, r); err != nil {
				slog.Error("reply", "error", err)
			}
		}()
	case "task":
		a.start(ctx, c.ID, *c.Task)
	case "stop", "cancel":
		a.mu.Lock()
		for key, t := range a.running {
			if !strings.HasPrefix(key, c.ID+"/") {
				continue
			}
			if c.Type == "stop" {
				t.stop()
			} else {
				t.cancel()
			}
		}
		a.mu.Unlock()
	}
}

// task is a capture of one pod while it runs. cancel abandons it; stop ends
// its time frame, so that what runs over time finishes with what it has.
type task struct{ cancel, stop context.CancelFunc }

// progress is the state of a task's recordings. Each change wakes the
// task's reporter, which sends the whole state to the hub.
type progress struct {
	mu      sync.Mutex
	states  []api.RecordingStatus
	changed chan struct{}
}

func newProgress(r api.CaptureRequest) *progress {
	p := &progress{changed: make(chan struct{}, 1)}
	for _, rec := range r.Recordings {
		p.states = append(p.states, api.RecordingStatus{Kind: rec.Kind, State: api.StateWaiting})
	}
	return p
}

func (p *progress) set(kind, state, message string) {
	p.mu.Lock()
	for i := range p.states {
		if p.states[i].Kind == kind {
			p.states[i].State, p.states[i].Message = state, message
		}
	}
	p.mu.Unlock()
	select {
	case p.changed <- struct{}{}:
	default: // a report is already due and will carry this change
	}
}

func (p *progress) snapshot() []api.RecordingStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.states)
}

// start runs one task in the background. The hub sends a node's open tasks
// again after a reconnect: one that is running here is not started twice,
// and one that had started before this agent did is reported as lost.
func (a *Agent) start(ctx context.Context, id string, t api.TaskAssignment) {
	key := id + "/" + t.Pod
	a.mu.Lock()
	if _, ok := a.running[key]; ok {
		a.mu.Unlock()
		return
	}
	if t.Started {
		a.mu.Unlock()
		lost := api.TaskStatus{Pod: t.Pod, State: api.StateFailed, Message: "the node agent restarted during the capture, or its result did not reach the hub"}
		go func() {
			if err := a.post(ctx, "/agent/captures/"+id+"/status", lost); err != nil {
				slog.Warn("task status", "capture", id, "pod", t.Pod, "error", err)
			}
		}()
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	frame, stop := context.WithCancel(ctx)
	if t.Stopped {
		stop() // stopped while this agent was away: nothing runs over time
	}
	a.running[key] = task{cancel, stop}
	a.mu.Unlock()
	go func() {
		defer func() {
			cancel()
			a.mu.Lock()
			delete(a.running, key)
			a.mu.Unlock()
		}()
		report := newProgress(t.Request)
		status := api.TaskStatus{Pod: t.Pod, State: api.StateRunning, Recordings: report.snapshot()}
		err := a.post(ctx, "/agent/captures/"+id+"/status", status)
		if err != nil {
			slog.Error("task not started", "capture", id, "pod", t.Pod, "error", err)
			return
		}
		// The reporter tells the hub how the recordings get on, one report
		// at a time, until the capture ends.
		captured, reported := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(reported)
			for {
				select {
				case <-captured:
					return
				case <-report.changed:
					running := api.TaskStatus{Pod: t.Pod, State: api.StateRunning, Recordings: report.snapshot()}
					if err := a.post(ctx, "/agent/captures/"+id+"/status", running); err != nil && ctx.Err() == nil {
						slog.Warn("task progress", "capture", id, "pod", t.Pod, "error", err)
					}
				}
			}
		}()
		// A task with a recording that failed still completes, and says so.
		status.State = api.StateCompleted
		status.Message, err = a.capture(ctx, frame, id, t, report)
		close(captured)
		<-reported
		if status.Recordings = report.snapshot(); err != nil {
			status.State, status.Message = api.StateFailed, err.Error()
		}
		// A cancelled task still reports; the hub ignores it if the capture ended.
		if err := a.post(context.WithoutCancel(ctx), "/agent/captures/"+id+"/status", status); err != nil {
			slog.Warn("task status", "capture", id, "pod", t.Pod, "error", err)
		}
	}()
}

// upload streams one file of a capture to the hub.
func (a *Agent) upload(ctx context.Context, id, pod, name string, r io.Reader) error {
	res, err := a.request(ctx, http.MethodPut, "/agent/captures/"+id+"/artifacts/"+url.PathEscape(pod)+"/"+url.PathEscape(name), &full{r: r})
	if err != nil {
		return err
	}
	return res.Body.Close()
}

// full reads from r until the caller's buffer is full or r ends. A tool
// writes its output in small pieces, a line or a packet at a time, and the
// HTTP client sends each piece it reads as a chunk with a write to the
// network of its own: tens of thousands per second for a busy trace. The
// hub has no use for a piece before the file is complete, so the pieces
// are gathered.
type full struct {
	r   io.Reader
	err error
}

func (f *full) Read(p []byte) (int, error) {
	if f.err != nil {
		return 0, f.err
	}
	n, err := io.ReadFull(f.r, p)
	if err == io.ErrUnexpectedEOF {
		err = io.EOF
	}
	// What was read before the end or a failure is handed on first.
	if n > 0 && err != nil {
		f.err, err = err, nil
	}
	return n, err
}
