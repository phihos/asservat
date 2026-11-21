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
	// Scratch holds a core file until it is uploaded.
	Scratch string
	// Proc is the node's /proc.
	Proc string

	mu       sync.Mutex
	running  map[string]context.CancelFunc // capture ID + pod -> cancel
	watching map[string]context.CancelFunc // watch ID -> cancel
	// Packet buffers of watched pods by watch ID + pod, and the packets set
	// aside at a crash, by trigger ID, until the hub's task for it arrives.
	rings     map[string]*ring
	snapshots map[string][]byte
}

// Run keeps the stream to the hub open until ctx ends, reconnecting with a
// growing delay after a failure.
func (a *Agent) Run(ctx context.Context) {
	a.running, a.watching = map[string]context.CancelFunc{}, map[string]context.CancelFunc{}
	a.rings, a.snapshots = map[string]*ring{}, map[string][]byte{}
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
		for key, cancel := range a.running {
			if !open[key] {
				cancel()
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
	case "cancel":
		a.mu.Lock()
		for key, cancel := range a.running {
			if strings.HasPrefix(key, c.ID+"/") {
				cancel()
			}
		}
		a.mu.Unlock()
	}
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
	a.running[key] = cancel
	a.mu.Unlock()
	go func() {
		defer func() {
			cancel()
			a.mu.Lock()
			delete(a.running, key)
			a.mu.Unlock()
		}()
		status := api.TaskStatus{Pod: t.Pod, State: api.StateRunning}
		if err := a.post(ctx, "/agent/captures/"+id+"/status", status); err != nil {
			slog.Error("task not started", "capture", id, "pod", t.Pod, "error", err)
			return
		}
		status.State = api.StateCompleted
		if err := a.capture(ctx, id, t); err != nil {
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
	res, err := a.request(ctx, http.MethodPut, "/agent/captures/"+id+"/artifacts/"+url.PathEscape(pod)+"/"+url.PathEscape(name), r)
	if err != nil {
		return err
	}
	return res.Body.Close()
}
