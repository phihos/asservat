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
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"asservat.local/asservat/internal/api"
	"asservat.local/asservat/internal/coredesc"
	"asservat.local/asservat/internal/holes"
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

// query asks the agent of a node, or with an empty node any connected agent
// of the cluster, and waits for its reply or the end of ctx.
func (a *agents) query(ctx context.Context, cluster, node string, q api.Query) (api.Reply, error) {
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
	nodes := []string{node}
	if node == "" {
		nodes = a.nodes(cluster)
	}
	sent := false
	for _, n := range nodes {
		if sent = a.send(cluster, n, api.Command{Type: "query", ID: id, Query: &q}); sent {
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
	// Like an event stream, the commands' stream writes a line at every
	// beat while it has nothing to say: a command that asks for nothing.
	beat := time.NewTicker(h.StreamBeat)
	defer beat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return nil
		case c, ok := <-ch:
			if !ok || enc.Encode(c) != nil {
				return nil
			}
		case <-beat.C:
			if enc.Encode(api.Command{Type: "beat"}) != nil {
				return nil
			}
		}
		rc.Flush()
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
// agentCapture returns the capture that an agent of the cluster reports on
// for a pod, with its request and its state alone, and whether the pod is
// one of its tasks (see Store.TaskOf).
func (h *Hub) agentCapture(ctx context.Context, cluster, id, pod string) (api.Capture, bool, error) {
	if uuid.Validate(id) != nil {
		return api.Capture{}, false, ErrNotFound
	}
	c, task, err := h.Store.TaskOf(ctx, id, pod)
	if err == nil && c.Cluster != cluster {
		err = ErrNotFound
	}
	return c, task, err
}

func (h *Hub) agentStatus(w http.ResponseWriter, r *http.Request, cluster string) error {
	var in api.TaskStatus
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || !slices.Contains([]string{api.StateRunning, api.StateCompleted, api.StateFailed}, in.State) {
		return errStatus{http.StatusBadRequest, "invalid status"}
	}
	c, _, err := h.agentCapture(r.Context(), cluster, r.PathValue("id"), in.Pod)
	if err != nil {
		return err
	}
	// A recording's kind and state are shown as they are: they are of the
	// capture and of the states there are, whoever holds the join token.
	for _, rec := range in.Recordings {
		if c.Recording(rec.Kind) == nil || !slices.Contains([]string{api.StateWaiting, api.StateRunning, api.StateCompleted, api.StateFailed}, rec.State) {
			return errStatus{http.StatusBadRequest, "invalid status of a recording"}
		}
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
	// A file is "<pod>/<file>" of one of the capture's pods.
	pod, file, _ := strings.Cut(r.PathValue("name"), "/")
	c, task, err := h.agentCapture(r.Context(), cluster, r.PathValue("id"), pod)
	if err != nil {
		return err
	}
	if c.State != api.StateQueued && c.State != api.StateRunning {
		return errStatus{http.StatusConflict, "the capture has ended"}
	}
	if file == "" || strings.Contains(file, "/") || !task {
		return errStatus{http.StatusBadRequest, "the file name must be <pod>/<file> of a pod of the capture"}
	}
	// A core that is mostly holes comes packed, and is kept so.
	packed := r.Header.Get("Asservat-Holes") != ""
	if packed && (api.ViewerOf(file) != "core" || strings.HasSuffix(file, coredesc.Suffix)) {
		return errStatus{http.StatusBadRequest, "only a core dump is sent without its holes"}
	}
	a, err := h.kept(r.Context(), r.PathValue("name"), r.Body, packed)
	if err != nil {
		return err
	}
	added, err := h.Store.AddArtifact(r.Context(), c.ID, a)
	if err != nil || !added {
		// The capture ended or was deleted while the file streamed.
		h.Blobs.Delete(context.WithoutCancel(r.Context()), a.Blob)
		if err == nil {
			err = errStatus{http.StatusConflict, "the capture has ended"}
		}
		return err
	}
	h.notify(c.ID)
	// The program's files come last of a core: with them here, the hub adds
	// what the agent left of the description to it.
	if core, is := strings.CutSuffix(a.Name, coredesc.FilesSuffix); is {
		go h.complete(context.WithoutCancel(r.Context()), c.ID, core)
	}
	return nil
}

// complete adds to a core's description what its agent left to the hub.
// The cores that agents send are completed one after the other: each is
// decrypted into the work directory, which a capture of many pods would
// otherwise fill with all of its cores at once.
func (h *Hub) complete(ctx context.Context, capture, core string) {
	h.completing.Lock()
	defer h.completing.Unlock()
	if result := <-h.renew(ctx, User{}, capture, core); result.err != nil {
		slog.Error("core's description not completed", "capture", capture, "name", core, "error", result.err)
	}
}

// keep stores a file's content encrypted with a key of its own and returns
// what to record of it.
func (h *Hub) keep(ctx context.Context, name string, content io.Reader) (storedArtifact, error) {
	return h.kept(ctx, name, content, false)
}

// kept is keep for content that may be packed (see the package holes).
// Packed content is stored as it comes; its size and checksum are those
// of the file it unpacks to, which the hub reads off it as it passes,
// and content that does not unpack is not kept.
func (h *Hub) kept(ctx context.Context, name string, content io.Reader, packed bool) (storedArtifact, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return storedArtifact{}, err
	}
	wrapped, err := wrapKey(h.MasterKey, key)
	if err != nil {
		return storedArtifact{}, err
	}
	blob := uuid.NewString()
	sum := sha256.New()
	pr, pw := io.Pipe()
	body := &countingReader{r: io.TeeReader(content, sum)}
	// What is stored of packed content is the content; what is counted
	// and summed is the file, unpacked beside it as it passes.
	var unpacked chan error
	size := int64(0)
	if packed {
		beside, passing := io.Pipe()
		body.r = io.TeeReader(content, passing)
		unpacked = make(chan error, 1)
		go func() {
			n, err := holes.Unpack(sum, beside)
			size = n
			beside.CloseWithError(err) // content that does not unpack ends the storing
			unpacked <- err
		}()
		defer passing.Close()
		body.r = &ending{r: body.r, end: passing}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		pw.CloseWithError(encrypt(pw, body, key))
	}()
	err = h.Blobs.Put(ctx, blob, pr)
	pr.CloseWithError(err)
	<-done
	if packed {
		if e := <-unpacked; e != nil {
			h.Blobs.Delete(context.WithoutCancel(ctx), blob)
			return storedArtifact{}, errStatus{http.StatusBadRequest, e.Error()}
		}
	} else {
		size = body.n
	}
	if err != nil {
		h.Blobs.Delete(context.WithoutCancel(ctx), blob)
		return storedArtifact{}, fmt.Errorf("store artifact: %w", err)
	}
	kept := storedArtifact{Artifact: api.Artifact{Name: name, Size: size, SHA256: hex.EncodeToString(sum.Sum(nil))}, Blob: blob, Key: wrapped, Packed: packed}
	if packed {
		kept.Stored = body.n
	}
	return kept, nil
}

// ending closes a pipe when its reader has ended, so that who reads the
// pipe's other end learns of the end too.
type ending struct {
	r   io.Reader
	end *io.PipeWriter
}

func (e *ending) Read(p []byte) (int, error) {
	n, err := e.r.Read(p)
	if err != nil {
		e.end.CloseWithError(err)
	}
	return n, err
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
