// Package hub is the central service: it authenticates users, records
// capture requests and approvals, pushes work to the node agents of every
// cluster over their outbound streams and stores the evidence they upload.
package hub

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"asservat.local/asservat/internal/api"
)

//go:embed web/index.html
var web embed.FS

// User is an authenticated caller. Name and Groups are the identity that the
// clusters' Kubernetes RBAC is asked about.
type User struct {
	Name   string   `json:"name"`
	Groups []string `json:"groups"`
	Admin  bool     `json:"admin"`
}

// StaticUser is a user with a fixed bearer token from the hub's configuration.
type StaticUser struct {
	Name   string   `json:"name"`
	Token  string   `json:"token"`
	Groups []string `json:"groups"`
}

type Config struct {
	Store     *Store
	Blobs     Blobs
	MasterKey []byte // 32 bytes; wraps the per-artifact keys
	Users     []StaticUser
	// Verify authenticates a bearer token that is no static token, for
	// example an OIDC token. Nil accepts static tokens only.
	Verify func(ctx context.Context, token string) (User, error)
	// AdminGroups names the groups whose members approve sensitive captures
	// and manage clusters.
	AdminGroups []string
	// Retention is how long evidence is kept after the request.
	Retention time.Duration
	// AllowSelfApproval lets an administrator approve their own request, for
	// installations with a single administrator.
	AllowSelfApproval bool
}

type Hub struct {
	Config
	agents *agents
	// changed wakes the retention timer when a capture is created.
	changed chan struct{}

	mu       sync.Mutex
	watchers map[chan string]struct{}
}

func New(c Config) (*Hub, error) {
	if len(c.MasterKey) != 32 {
		return nil, errors.New("the master key must be 32 bytes")
	}
	if c.Retention <= 0 {
		return nil, errors.New("retention must be positive")
	}
	return &Hub{Config: c, agents: newAgents(), changed: make(chan struct{}, 1), watchers: map[chan string]struct{}{}}, nil
}

func (h *Hub) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFileFS(w, r, web, "web/index.html")
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {})
	user := func(pattern string, f func(http.ResponseWriter, *http.Request, User) error) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			u, err := h.authenticate(r)
			if err != nil {
				fail(w, errStatus{http.StatusUnauthorized, "sign in with a bearer token"})
				return
			}
			if err := f(w, r, u); err != nil {
				fail(w, err)
			}
		})
	}
	admin := func(pattern string, f func(http.ResponseWriter, *http.Request, User) error) {
		user(pattern, func(w http.ResponseWriter, r *http.Request, u User) error {
			if !u.Admin {
				return errStatus{http.StatusForbidden, "administrators only"}
			}
			return f(w, r, u)
		})
	}
	user("GET /api/me", func(w http.ResponseWriter, r *http.Request, u User) error { return reply(w, u) })
	user("GET /api/clusters", h.listClusters)
	admin("POST /api/clusters", h.addCluster)
	admin("DELETE /api/clusters/{cluster}", h.deleteCluster)
	user("GET /api/clusters/{cluster}/namespaces/{namespace}/workloads", h.listWorkloads)
	user("POST /api/captures", h.createCapture)
	user("GET /api/captures", h.listCaptures)
	user("GET /api/captures/{id}", h.getCapture)
	user("DELETE /api/captures/{id}", h.deleteCapture)
	admin("POST /api/captures/{id}/approve", h.decide(api.StateQueued))
	admin("POST /api/captures/{id}/deny", h.decide(api.StateDenied))
	user("POST /api/captures/{id}/cancel", h.cancelCapture)
	user("GET /api/captures/{id}/artifacts/{name...}", h.download)
	user("POST /api/watches", h.createWatch)
	user("GET /api/watches", h.listWatches)
	user("DELETE /api/watches/{id}", h.deleteWatch)
	user("GET /api/events", h.events)
	admin("GET /api/audit", h.auditLog)
	user("POST /mcp", h.mcp)

	agent := func(pattern string, f func(http.ResponseWriter, *http.Request, string) error) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			sum := sha256.Sum256([]byte(bearer(r)))
			cluster, err := h.Store.ClusterByToken(r.Context(), sum[:])
			if err != nil {
				fail(w, errStatus{http.StatusUnauthorized, "unknown cluster token"})
				return
			}
			if err := f(w, r, cluster); err != nil {
				fail(w, err)
			}
		})
	}
	agent("GET /agent/stream", h.agentStream)
	agent("POST /agent/replies/{id}", h.agentReply)
	agent("POST /agent/captures/{id}/status", h.agentStatus)
	agent("PUT /agent/captures/{id}/artifacts/{name...}", h.agentUpload)
	agent("POST /agent/watches/{id}/trigger", h.agentTrigger)
	return mux
}

type errStatus struct {
	code int
	msg  string
}

func (e errStatus) Error() string { return e.msg }

func fail(w http.ResponseWriter, err error) {
	var s errStatus
	switch {
	case errors.As(err, &s):
	case errors.Is(err, ErrNotFound):
		s = errStatus{http.StatusNotFound, "not found"}
	case errors.Is(err, errNoAgent):
		s = errStatus{http.StatusServiceUnavailable, err.Error()}
	default:
		slog.Error("request failed", "error", err)
		s = errStatus{http.StatusInternalServerError, "internal error"}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(s.code)
	json.NewEncoder(w).Encode(map[string]string{"error": s.msg})
}

func reply(w http.ResponseWriter, v any) error {
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(v)
}

func bearer(r *http.Request) string {
	if t, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
		return t
	}
	// Browser downloads and EventSource cannot set headers.
	if c, err := r.Cookie("asservat_token"); err == nil {
		return c.Value
	}
	return ""
}

func (h *Hub) authenticate(r *http.Request) (User, error) {
	token := bearer(r)
	if token == "" {
		return User{}, errors.New("no token")
	}
	var u User
	found := false
	for _, s := range h.Users {
		if s.Token != "" && subtle.ConstantTimeCompare([]byte(s.Token), []byte(token)) == 1 {
			u, found = User{Name: s.Name, Groups: s.Groups}, true
		}
	}
	if !found {
		if h.Verify == nil {
			return User{}, errors.New("unknown token")
		}
		var err error
		if u, err = h.Verify(r.Context(), token); err != nil {
			return User{}, err
		}
	}
	return h.withAdmin(u), nil
}

// withAdmin marks the user as administrator if a group of theirs is one of
// the administrator groups.
func (h *Hub) withAdmin(u User) User {
	u.Admin = slices.ContainsFunc(u.Groups, func(g string) bool { return slices.Contains(h.AdminGroups, g) })
	return u
}

// allowed reports whether the user may capture workloads of the namespace:
// administrators always, everyone else if the cluster's RBAC lets them exec
// into the namespace's pods.
func (h *Hub) allowed(ctx context.Context, u User, cluster, namespace string) error {
	if u.Admin {
		return nil
	}
	r, err := h.agents.query(ctx, cluster, api.Query{Op: "review", Namespace: namespace, User: u.Name, Groups: u.Groups})
	if err != nil {
		return err
	}
	if !r.Allowed {
		return errStatus{http.StatusForbidden, "you need the right to exec into pods of this namespace (pods/exec)"}
	}
	return nil
}

func (h *Hub) listClusters(w http.ResponseWriter, r *http.Request, _ User) error {
	names, err := h.Store.Clusters(r.Context())
	if err != nil {
		return err
	}
	type cluster struct {
		Name  string   `json:"name"`
		Nodes []string `json:"nodes"` // nodes whose agent is connected
	}
	out := []cluster{}
	for _, n := range names {
		out = append(out, cluster{n, h.agents.nodes(n)})
	}
	return reply(w, out)
}

func (h *Hub) addCluster(w http.ResponseWriter, r *http.Request, u User) error {
	var in struct {
		Name string `json:"name"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil || !api.ValidName(in.Name) {
		return errStatus{http.StatusBadRequest, "name must be lowercase letters, digits, dashes or dots"}
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	token := hex.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	if err := h.Store.AddCluster(r.Context(), in.Name, sum[:]); err != nil {
		return err
	}
	if err := h.Store.Audit(r.Context(), u.Name, "cluster.add", "", in); err != nil {
		return err
	}
	// The token is shown once; adding the cluster again replaces it.
	return reply(w, map[string]string{"name": in.Name, "token": token})
}

func (h *Hub) deleteCluster(w http.ResponseWriter, r *http.Request, u User) error {
	name := r.PathValue("cluster")
	if err := h.Store.DeleteCluster(r.Context(), name); err != nil {
		return err
	}
	h.agents.drop(name)
	return h.Store.Audit(r.Context(), u.Name, "cluster.delete", "", map[string]string{"name": name})
}

func (h *Hub) listWorkloads(w http.ResponseWriter, r *http.Request, u User) error {
	cluster, namespace := r.PathValue("cluster"), r.PathValue("namespace")
	if err := h.allowed(r.Context(), u, cluster, namespace); err != nil {
		return err
	}
	res, err := h.agents.query(r.Context(), cluster, api.Query{Op: "workloads", Namespace: namespace})
	if err != nil {
		return err
	}
	return reply(w, res.Workloads)
}

func (h *Hub) createCapture(w http.ResponseWriter, r *http.Request, u User) error {
	var in api.CaptureRequest
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		return errStatus{http.StatusBadRequest, "invalid JSON"}
	}
	c, err := h.Request(r.Context(), u, in)
	if err != nil {
		return err
	}
	w.WriteHeader(http.StatusCreated)
	return reply(w, c)
}

// Request validates and records a capture. A sensitive capture waits for an
// administrator; any other starts at once.
func (h *Hub) Request(ctx context.Context, u User, in api.CaptureRequest) (api.Capture, error) {
	in.Watch = ""
	if err := in.Validate(); err != nil {
		return api.Capture{}, errStatus{http.StatusBadRequest, err.Error()}
	}
	if err := h.allowed(ctx, u, in.Cluster, in.Namespace); err != nil {
		return api.Capture{}, err
	}
	res, err := h.agents.query(ctx, in.Cluster, api.Query{Op: "resolve", Namespace: in.Namespace, Workload: in.Workload})
	if err != nil {
		return api.Capture{}, err
	}
	pods := slices.DeleteFunc(res.Pods, func(p api.Pod) bool { return len(in.Pods) > 0 && !slices.Contains(in.Pods, p.Name) })
	if len(pods) == 0 {
		return api.Capture{}, errStatus{http.StatusUnprocessableEntity, "the workload has no matching running pods"}
	}
	return h.record(ctx, u, in, pods, "capture.request")
}

// record stores a checked capture for the pods, under the audit action, and
// starts it unless it needs approval.
func (h *Hub) record(ctx context.Context, u User, in api.CaptureRequest, pods []api.Pod, action string) (api.Capture, error) {
	c := api.Capture{ID: uuid.NewString(), CaptureRequest: in, Requester: u.Name, Sensitive: in.Sensitive(), State: api.StateQueued, ExpiresAt: time.Now().Add(h.Retention)}
	if c.Sensitive {
		c.State = api.StatePendingApproval
	}
	for _, p := range pods {
		c.Tasks = append(c.Tasks, api.Task{Pod: p.Name, Node: p.Node, State: api.StateQueued})
	}
	if err := h.Store.CreateCapture(ctx, c); err != nil {
		return api.Capture{}, err
	}
	if err := h.Store.Audit(ctx, u.Name, action, c.ID, in); err != nil {
		return api.Capture{}, err
	}
	if c.State == api.StateQueued {
		h.dispatch(c)
	}
	h.notify(c.ID)
	h.Wake()
	return h.Store.Capture(ctx, c.ID)
}

// Wake makes the retention loop look for the next expiry again.
func (h *Hub) Wake() {
	select {
	case h.changed <- struct{}{}:
	default:
	}
}

// dispatch pushes the capture's tasks to the agents that are connected. An
// agent that is not receives its queued tasks when it connects.
func (h *Hub) dispatch(c api.Capture) {
	for _, t := range c.Tasks {
		h.agents.send(c.Cluster, t.Node, api.Command{Type: "task", ID: c.ID, Task: &api.TaskAssignment{Pod: t.Pod, Request: c.CaptureRequest}})
	}
}

// visible returns the capture if the user may see it: their own, or any for
// an administrator.
func (h *Hub) visible(ctx context.Context, u User, id string) (api.Capture, error) {
	if uuid.Validate(id) != nil {
		return api.Capture{}, ErrNotFound
	}
	c, err := h.Store.Capture(ctx, id)
	if err != nil {
		return c, err
	}
	if !u.Admin && c.Requester != u.Name {
		return c, ErrNotFound
	}
	return c, nil
}

// defaultPage is the length of a list page unless the caller sets limit.
const defaultPage = 50

// page reads the before and limit query parameters of a list request.
func page(r *http.Request) (time.Time, int, error) {
	before, limit := time.Now().Add(time.Hour), defaultPage
	if v := r.URL.Query().Get("before"); v != "" {
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			return before, 0, errStatus{http.StatusBadRequest, "before must be an RFC 3339 time"}
		}
		before = t
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return before, 0, errStatus{http.StatusBadRequest, "limit must be a positive number"}
		}
		limit = n
	}
	return before, limit, nil
}

func (h *Hub) listCaptures(w http.ResponseWriter, r *http.Request, u User) error {
	before, limit, err := page(r)
	if err != nil {
		return err
	}
	list, err := h.captures(r.Context(), u, before, limit)
	if err != nil {
		return err
	}
	return reply(w, list)
}

// captures lists the user's captures, or everyone's for an administrator.
func (h *Hub) captures(ctx context.Context, u User, before time.Time, limit int) ([]api.Capture, error) {
	requester := u.Name
	if u.Admin {
		requester = ""
	}
	list, err := h.Store.Captures(ctx, requester, before, limit)
	if list == nil {
		list = []api.Capture{}
	}
	return list, err
}

func (h *Hub) getCapture(w http.ResponseWriter, r *http.Request, u User) error {
	c, err := h.visible(r.Context(), u, r.PathValue("id"))
	if err != nil {
		return err
	}
	return reply(w, c)
}

func (h *Hub) decide(state string) func(http.ResponseWriter, *http.Request, User) error {
	return func(w http.ResponseWriter, r *http.Request, u User) error {
		c, err := h.Decide(r.Context(), u, r.PathValue("id"), state)
		if err != nil {
			return err
		}
		return reply(w, c)
	}
}

// Decide approves (Queued) or denies a capture that awaits approval.
func (h *Hub) Decide(ctx context.Context, u User, id, state string) (api.Capture, error) {
	c, err := h.visible(ctx, u, id)
	if err != nil {
		return c, err
	}
	if !u.Admin {
		return c, errStatus{http.StatusForbidden, "administrators only"}
	}
	if c.Requester == u.Name && state == api.StateQueued && !h.AllowSelfApproval {
		return c, errStatus{http.StatusForbidden, "another administrator must approve your request"}
	}
	ok, err := h.Store.Decide(ctx, id, u.Name, state)
	if err != nil {
		return c, err
	}
	if !ok {
		return c, errStatus{http.StatusConflict, "the capture is not awaiting approval"}
	}
	action := "capture.approve"
	if state == api.StateDenied {
		action = "capture.deny"
	}
	if err := h.Store.Audit(ctx, u.Name, action, id, nil); err != nil {
		return c, err
	}
	if state == api.StateQueued {
		h.dispatch(c)
	}
	h.notify(id)
	return h.Store.Capture(ctx, id)
}

func (h *Hub) cancelCapture(w http.ResponseWriter, r *http.Request, u User) error {
	c, err := h.visible(r.Context(), u, r.PathValue("id"))
	if err != nil {
		return err
	}
	ok, err := h.Store.Cancel(r.Context(), c.ID)
	if err != nil {
		return err
	}
	if !ok {
		return errStatus{http.StatusConflict, "the capture has already finished"}
	}
	for _, t := range c.Tasks {
		h.agents.send(c.Cluster, t.Node, api.Command{Type: "cancel", ID: c.ID})
	}
	h.notify(c.ID)
	return h.Store.Audit(r.Context(), u.Name, "capture.cancel", c.ID, nil)
}

func (h *Hub) deleteCapture(w http.ResponseWriter, r *http.Request, u User) error {
	c, err := h.visible(r.Context(), u, r.PathValue("id"))
	if err != nil {
		return err
	}
	for _, t := range c.Tasks {
		h.agents.send(c.Cluster, t.Node, api.Command{Type: "cancel", ID: c.ID})
	}
	if err := h.remove(r.Context(), c.ID); err != nil {
		return err
	}
	return h.Store.Audit(r.Context(), u.Name, "capture.delete", c.ID, nil)
}

// remove deletes a capture's rows and then its blobs.
func (h *Hub) remove(ctx context.Context, id string) error {
	blobs, err := h.Store.DeleteCapture(ctx, id)
	if err != nil {
		return err
	}
	for _, b := range blobs {
		if err := h.Blobs.Delete(ctx, b); err != nil {
			slog.Error("blob not deleted", "blob", b, "error", err)
		}
	}
	h.notify(id)
	return nil
}

func (h *Hub) download(w http.ResponseWriter, r *http.Request, u User) error {
	c, err := h.visible(r.Context(), u, r.PathValue("id"))
	if err != nil {
		return err
	}
	a, err := h.Store.Artifact(r.Context(), c.ID, r.PathValue("name"))
	if err != nil {
		return err
	}
	key, err := unwrapKey(h.MasterKey, a.Key)
	if err != nil {
		return err
	}
	blob, err := h.Blobs.Get(r.Context(), a.Blob)
	if err != nil {
		return err
	}
	defer blob.Close()
	if err := h.Store.Audit(r.Context(), u.Name, "artifact.download", c.ID, map[string]string{"name": a.Name}); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(a.Size, 10))
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", path.Base(a.Name)))
	w.Header().Set("X-Checksum-Sha256", a.SHA256)
	if err := decrypt(w, blob, key); err != nil {
		// The headers are sent; aborting the response tells the client.
		panic(http.ErrAbortHandler)
	}
	return nil
}

func (h *Hub) auditLog(w http.ResponseWriter, r *http.Request, _ User) error {
	before, limit, err := page(r)
	if err != nil {
		return err
	}
	list, err := h.Store.AuditLog(r.Context(), before, limit)
	if err != nil {
		return err
	}
	if list == nil {
		list = []AuditEntry{}
	}
	return reply(w, list)
}

// notify tells the event streams that a capture or the watches changed.
func (h *Hub) notify(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.watchers {
		select {
		case ch <- id:
		default: // a slow reader misses the hint and reloads on its next event
		}
	}
}

// events streams the IDs of changed captures (Server-Sent Events). A client
// reloads the capture or its list; the hint itself carries no data.
func (h *Hub) events(w http.ResponseWriter, r *http.Request, _ User) error {
	ch := make(chan string, 64)
	h.mu.Lock()
	h.watchers[ch] = struct{}{}
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.watchers, ch)
		h.mu.Unlock()
	}()
	w.Header().Set("Content-Type", "text/event-stream")
	rc := http.NewResponseController(w)
	fmt.Fprint(w, ": connected\n\n")
	rc.Flush()
	for {
		select {
		case <-r.Context().Done():
			return nil
		case id := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", id)
			rc.Flush()
		}
	}
}

// RunRetention deletes captures when their retention ends. It sleeps until
// the next expiry and wakes early when a capture is created.
func (h *Hub) RunRetention(ctx context.Context) {
	for {
		ids, next, err := h.Store.Expired(ctx)
		for _, id := range ids {
			if e := h.remove(ctx, id); e != nil {
				err = e
				continue
			}
			h.Store.Audit(ctx, "retention", "capture.expire", id, nil)
		}
		var timer <-chan time.Time
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			slog.Error("retention", "error", err)
			timer = time.After(time.Minute) // retry after a failure
		case next != nil:
			timer = time.After(time.Until(*next))
		}
		select {
		case <-ctx.Done():
			return
		case <-h.changed:
		case <-timer:
		}
	}
}
