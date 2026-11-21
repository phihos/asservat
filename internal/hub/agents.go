package hub

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/google/uuid"

	"asservat.local/asservat/internal/api"
)

var errNoAgent = errors.New("no agent of this cluster is connected")

// agents tracks the connected node agents. Each holds one outbound stream on
// which the hub pushes commands.
type agents struct {
	mu      sync.Mutex
	streams map[string]map[string]chan api.Command // cluster -> node -> stream
	replies map[string]chan api.Reply              // cluster + query ID -> waiting caller
}

func newAgents() *agents {
	return &agents{streams: map[string]map[string]chan api.Command{}, replies: map[string]chan api.Reply{}}
}

func (a *agents) connect(cluster, node string) chan api.Command {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.streams[cluster] == nil {
		a.streams[cluster] = map[string]chan api.Command{}
	}
	if old := a.streams[cluster][node]; old != nil {
		close(old) // a reconnect replaces the node's previous stream
	}
	ch := make(chan api.Command, 64)
	a.streams[cluster][node] = ch
	return ch
}

func (a *agents) disconnect(cluster, node string, ch chan api.Command) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.streams[cluster][node] == ch {
		delete(a.streams[cluster], node)
	}
}

// drop closes every stream of a removed cluster.
func (a *agents) drop(cluster string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, ch := range a.streams[cluster] {
		close(ch)
	}
	delete(a.streams, cluster)
}

func (a *agents) nodes(cluster string) []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := []string{}
	for n := range a.streams[cluster] {
		out = append(out, n)
	}
	slices.Sort(out)
	return out
}

// send pushes a command to one node's agent and reports whether it is
// connected. A stream that does not drain is closed: its agent reconnects
// and learns the node's open tasks from the sync.
func (a *agents) send(cluster, node string, c api.Command) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	ch := a.streams[cluster][node]
	if ch == nil {
		return false
	}
	select {
	case ch <- c:
		return true
	default:
		close(ch)
		delete(a.streams[cluster], node)
		return false
	}
}

// query asks any connected agent of the cluster and waits for its reply or
// the end of ctx.
func (a *agents) query(ctx context.Context, cluster string, q api.Query) (api.Reply, error) {
	id := uuid.NewString()
	wait := make(chan api.Reply, 1)
	a.mu.Lock()
	a.replies[cluster+"/"+id] = wait
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		delete(a.replies, cluster+"/"+id)
		a.mu.Unlock()
	}()
	sent := false
	for _, node := range a.nodes(cluster) {
		if sent = a.send(cluster, node, api.Command{Type: "query", ID: id, Query: &q}); sent {
			break
		}
	}
	if !sent {
		return api.Reply{}, errNoAgent
	}
	select {
	case r := <-wait:
		if r.Error != "" {
			return r, errStatus{http.StatusBadGateway, r.Error}
		}
		return r, nil
	case <-ctx.Done():
		return api.Reply{}, errStatus{http.StatusGatewayTimeout, "the cluster's agent did not answer"}
	}
}

// answer delivers a reply from an agent of the cluster that was asked.
func (a *agents) answer(cluster, id string, r api.Reply) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if ch := a.replies[cluster+"/"+id]; ch != nil {
		select {
		case ch <- r:
		default:
		}
	}
}

// agentStream is a node agent's long-lived connection: the hub writes one
// JSON command per line. The first is a sync with the node's open tasks
// (those approved while the agent was away and those it had started) and
// the cluster's watches.
func (h *Hub) agentStream(w http.ResponseWriter, r *http.Request, cluster string) error {
	node := r.URL.Query().Get("node")
	if node == "" {
		return errStatus{http.StatusBadRequest, "node is required"}
	}
	// Register first, so that a task dispatched from now on is not missed;
	// one that is also in the sync is started once by the agent.
	ch := h.agents.connect(cluster, node)
	defer h.agents.disconnect(cluster, node, ch)
	open, err := h.Store.OpenTasks(r.Context(), cluster, node)
	if err != nil {
		return err
	}
	watches, err := h.Store.ActiveWatches(r.Context(), cluster)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	rc := http.NewResponseController(w)
	enc := json.NewEncoder(w)
	if enc.Encode(api.Command{Type: "sync", Tasks: open, Watches: watches}) != nil {
		return nil
	}
	rc.Flush()
	for {
		select {
		case <-r.Context().Done():
			return nil
		case c, ok := <-ch:
			if !ok || enc.Encode(c) != nil {
				return nil
			}
			rc.Flush()
		}
	}
}

func (h *Hub) agentReply(w http.ResponseWriter, r *http.Request, cluster string) error {
	var in api.Reply
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		return errStatus{http.StatusBadRequest, "invalid JSON"}
	}
	h.agents.answer(cluster, r.PathValue("id"), in)
	return nil
}

// agentCapture returns the capture if it belongs to the agent's cluster.
func (h *Hub) agentCapture(ctx context.Context, cluster, id string) (api.Capture, error) {
	if uuid.Validate(id) != nil {
		return api.Capture{}, ErrNotFound
	}
	c, err := h.Store.Capture(ctx, id)
	if err == nil && c.Cluster != cluster {
		err = ErrNotFound
	}
	return c, err
}

func (h *Hub) agentStatus(w http.ResponseWriter, r *http.Request, cluster string) error {
	var in api.TaskStatus
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || !slices.Contains([]string{api.StateRunning, api.StateCompleted, api.StateFailed}, in.State) {
		return errStatus{http.StatusBadRequest, "invalid status"}
	}
	c, err := h.agentCapture(r.Context(), cluster, r.PathValue("id"))
	if err != nil {
		return err
	}
	if err := h.Store.SetTask(r.Context(), c.ID, in); err != nil {
		return err
	}
	h.notify(c.ID)
	return nil
}

// agentUpload stores one file of a running capture. The body is encrypted
// while it streams to the blob store.
func (h *Hub) agentUpload(w http.ResponseWriter, r *http.Request, cluster string) error {
	c, err := h.agentCapture(r.Context(), cluster, r.PathValue("id"))
	if err != nil {
		return err
	}
	if c.State != api.StateQueued && c.State != api.StateRunning {
		return errStatus{http.StatusConflict, "the capture has ended"}
	}
	// A file is "<pod>/<file>" of one of the capture's pods.
	pod, file, _ := strings.Cut(r.PathValue("name"), "/")
	if file == "" || strings.Contains(file, "/") || !slices.ContainsFunc(c.Tasks, func(t api.Task) bool { return t.Pod == pod }) {
		return errStatus{http.StatusBadRequest, "the file name must be <pod>/<file> of a pod of the capture"}
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	wrapped, err := wrapKey(h.MasterKey, key)
	if err != nil {
		return err
	}
	blob := uuid.NewString()
	sum := sha256.New()
	pr, pw := io.Pipe()
	body := &countingReader{r: io.TeeReader(r.Body, sum)}
	done := make(chan struct{})
	go func() {
		defer close(done)
		pw.CloseWithError(encrypt(pw, body, key))
	}()
	err = h.Blobs.Put(r.Context(), blob, pr)
	pr.CloseWithError(err)
	<-done
	if err != nil {
		h.Blobs.Delete(context.WithoutCancel(r.Context()), blob)
		return fmt.Errorf("store artifact: %w", err)
	}
	a := storedArtifact{Artifact: api.Artifact{Name: r.PathValue("name"), Size: body.n, SHA256: hex.EncodeToString(sum.Sum(nil))}, Blob: blob, Key: wrapped}
	added, err := h.Store.AddArtifact(r.Context(), c.ID, a)
	if err != nil || !added {
		// The capture ended or was deleted while the file streamed.
		h.Blobs.Delete(context.WithoutCancel(r.Context()), blob)
		if err == nil {
			err = errStatus{http.StatusConflict, "the capture has ended"}
		}
		return err
	}
	h.notify(c.ID)
	return nil
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}
