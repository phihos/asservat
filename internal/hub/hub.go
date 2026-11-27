// Package hub is the central service: it authenticates users, records
// capture requests and approvals, pushes work to the node agents of every
// cluster over their outbound streams and stores the evidence they upload.
package hub

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"asservat.local/asservat/internal/api"
)

//go:embed web
var web embed.FS

// User is an authenticated caller. Name and Groups are the identity that the
// clusters' Kubernetes RBAC is asked about.
type User struct {
	Name   string   `json:"name"`
	Groups []string `json:"groups"`
	Admin  bool     `json:"admin"`
}

// Cluster is a cluster of the installation: its name, and the token with
// which its node agents join. Clusters are part of the hub's configuration.
type Cluster struct {
	Name  string `json:"name"`
	Token string `json:"token"`
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
	Clusters  []Cluster
	// Verify authenticates a bearer token that is no static token, for
	// example an OIDC token. Nil accepts static tokens only.
	Verify func(ctx context.Context, token string) (User, error)
	// OAuth lets browsers sign in at the OIDC provider whose tokens Verify
	// accepts. Nil offers no such sign-in.
	OAuth *oauth2.Config
	// AdminGroups names the groups whose members approve sensitive captures
	// and manage clusters.
	AdminGroups []string
	// Retention is how long evidence is kept after the request.
	Retention time.Duration
	// AllowSelfApproval lets an administrator approve their own request, for
	// installations with a single administrator.
	AllowSelfApproval bool
	// DebuginfodURLs are the debuginfod servers, separated by spaces, that
	// gdb asks for debug information when the hub describes a core again.
	DebuginfodURLs string
	// WorkDir holds the files that viewers have open, decrypted, while they
	// are open. Empty means the system's directory for temporary files.
	WorkDir string
	// AlertToken is the secret that Alertmanager presents with its
	// notifications; empty accepts none.
	AlertToken string
	// StreamBeat is how often the hub writes a line into an event stream
	// that has nothing to say, so that proxies on the way do not take the
	// connection for dead; 20 seconds if zero.
	StreamBeat time.Duration
	// ScheduleRetry is how long the hub waits before it tries again to
	// record a watch's time that it could not record. One minute if unset.
	ScheduleRetry time.Duration
	// Sharkd is the path of Wireshark's sharkd, which reads packet captures
	// for their viewer.
	Sharkd string
	// GoTrace is the path of Go's trace tool (cmd/trace), which shows
	// execution traces for their viewer.
	GoTrace string
}

type Hub struct {
	Config
	agents *agents
	// changed wakes the retention timer when a capture is created.
	changed chan struct{}
	// scheduled wakes the schedule of watches for a time when watches change.
	scheduled chan struct{}

	mu sync.Mutex
	// describing holds the cores that are being described again, each with
	// a channel that closes when it is done.
	describing map[string]chan struct{}
	// undescribed holds the cores that could not be described again.
	undescribed map[string]bool
	// awaited holds the cores whose runtime's tool failed, with the time
	// of that try (describeAgainAfter).
	awaited map[string]time.Time
	// completing is held while the hub completes a description that an
	// agent sent (agents.go).
	completing sync.Mutex
	// pystack is the Python that has pystack, for tests; coredesc's if empty.
	pystack  string
	watchers map[chan string]struct{}
	views    views
}

func New(c Config) (*Hub, error) {
	if len(c.MasterKey) != 32 {
		return nil, errors.New("the master key must be 32 bytes")
	}
	if c.Retention <= 0 {
		return nil, errors.New("retention must be positive")
	}
	if c.ScheduleRetry <= 0 {
		c.ScheduleRetry = time.Minute
	}
	if c.StreamBeat <= 0 {
		// Well below the time after which common proxies end a silent
		// connection: HAProxy 50 seconds, nginx and cloud load balancers 60.
		c.StreamBeat = 20 * time.Second
	}
	for i, cluster := range c.Clusters {
		// A join token is a secret that agents present from other networks.
		if !api.ValidName(cluster.Name) || len(cluster.Token) < 32 {
			return nil, fmt.Errorf("cluster %q needs a name of lowercase letters, digits, dashes or dots and a join token of at least 32 characters", cluster.Name)
		}
		for _, other := range c.Clusters[:i] {
			if other.Name == cluster.Name || other.Token == cluster.Token {
				return nil, fmt.Errorf("cluster %q repeats the name or the join token of another cluster", cluster.Name)
			}
		}
	}
	// A hub that was killed, as when its node ran out of memory, left what
	// it had decrypted for a viewer or to describe a core in its work
	// directory, which outlives the container. No view is open at the
	// start: it goes. What was downloaded of debug information stays.
	if c.WorkDir != "" {
		for _, pattern := range []string{"describe-*", "view-*", "dotnet-*", "python-stacks-*", "analysis-*"} {
			left, _ := filepath.Glob(filepath.Join(c.WorkDir, pattern))
			for _, path := range left {
				if err := os.RemoveAll(path); err != nil {
					return nil, fmt.Errorf("what an earlier hub left decrypted in its work directory: %w", err)
				}
			}
		}
	}
	return &Hub{Config: c, agents: newAgents(), changed: make(chan struct{}, 1), scheduled: make(chan struct{}, 1), undescribed: map[string]bool{}, awaited: map[string]time.Time{}, watchers: map[chan string]struct{}{}, views: views{open: map[string]*view{}}}, nil
}

// pagePolicy is what the console's pages tell the browser to hold them to
// (a content security policy). The pages show what workloads and agents
// hand the hub; every value is written as text, and should one ever reach
// a page as markup all the same, the browser runs no script of it: scripts
// come from the hub's own files only, never from the markup. Styles may be
// in the markup, where the viewers set sizes and positions; a tool's own
// pages, pprof's and the trace tool's, are framed from the hub.
const pagePolicy = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'self'"

func (h *Hub) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", pagePolicy)
		http.ServeFileFS(w, r, web, "web/index.html")
	})
	mux.HandleFunc("GET /console.js", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFileFS(w, r, web, "web/console.js")
	})
	// The viewer page and, under /view/, the script and style of each viewer.
	mux.HandleFunc("GET /view", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", pagePolicy)
		http.ServeFileFS(w, r, web, "web/view.html")
	})
	// The look: style, mark and fonts. They change only with the hub.
	mux.HandleFunc("GET /assets/{file}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=86400")
		http.ServeFileFS(w, r, web, "web/assets/"+r.PathValue("file"))
	})
	mux.HandleFunc("GET /view/{file}", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFileFS(w, r, web, "web/view/"+r.PathValue("file"))
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("GET /api/login", h.loginInfo)
	if h.OAuth != nil {
		mux.HandleFunc("GET /auth/login", h.login)
		mux.HandleFunc("GET /auth/callback", h.loginCallback)
		mux.HandleFunc("POST /auth/logout", h.logout)
	}
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
	user("GET /api/me", func(w http.ResponseWriter, r *http.Request, u User) error {
		// SelfApproval tells the console that this user's sensitive requests start at once.
		return reply(w, struct {
			User
			SelfApproval bool `json:"selfApproval"`
		}{u, h.approvesOwn(u)})
	})
	user("GET /api/clusters", h.listClusters)
	user("GET /api/clusters/{cluster}/namespaces", h.listNamespaces)
	user("GET /api/clusters/{cluster}/namespaces/{namespace}/workloads", h.listWorkloads)
	user("GET /api/clusters/{cluster}/namespaces/{namespace}/containers", h.listContainers)
	user("GET /api/clusters/{cluster}/namespaces/{namespace}/processes", h.listProcesses)
	user("POST /api/clusters/{cluster}/namespaces/{namespace}/traffic", h.sampleTraffic)
	user("POST /api/clusters/{cluster}/namespaces/{namespace}/profiles", h.findProfiles)
	user("POST /api/captures", h.createCapture)
	user("GET /api/captures", h.listCaptures)
	user("GET /api/captures/{id}", h.getCapture)
	user("DELETE /api/captures/{id}", h.deleteCapture)
	admin("POST /api/captures/{id}/approve", h.decide(api.StateQueued))
	admin("POST /api/captures/{id}/deny", h.decide(api.StateDenied))
	user("POST /api/captures/{id}/stop", h.stopCapture)
	user("POST /api/captures/{id}/cancel", h.cancelCapture)
	user("POST /api/captures/{id}/share", h.shareCapture)
	user("GET /api/captures/{id}/artifacts/{name...}", h.download)
	user("GET /api/captures/{id}/summaries/{name...}", h.summary)
	user("POST /api/captures/{id}/describe", h.describe)
	user("GET /api/captures/{id}/views/{name...}", h.openView)
	user("POST /api/views/{view}/{method}", h.askView)
	user("GET /api/views/{view}/pages/{page...}", h.viewPage)
	user("POST /api/watches", h.createWatch)
	user("GET /api/watches", h.listWatches)
	user("DELETE /api/watches/{id}", h.deleteWatch)
	admin("POST /api/watches/{id}/approve", h.approveWatch)
	user("POST /api/watches/{id}/record", h.recordNow)
	user("GET /api/events", h.events)
	admin("GET /api/audit", h.auditLog)
	user("POST /mcp", h.mcp)
	// Alertmanager presents the hub's alert token, not a user's.
	mux.HandleFunc("POST /api/alerts", h.alerts)

	agent := func(pattern string, f func(http.ResponseWriter, *http.Request, string) error) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			cluster, known := h.clusterOf(bearer(r))
			if !known {
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
	// What the hub serves is of the type it names and of no other: a
	// browser that guesses types could take a recorded file for a page
	// (X-Content-Type-Options, as OWASP's secure headers list it).
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		mux.ServeHTTP(w, r)
	})
}

type errStatus struct {
	code int
	msg  string
}

func (e errStatus) Error() string { return e.msg }

func fail(w http.ResponseWriter, err error) {
	s := told(err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(s.code)
	json.NewEncoder(w).Encode(map[string]string{"error": s.msg})
}

// told is what a caller is told of an error: what the hub says itself, as
// it says it, and of everything else (the database, the store, a path of
// the hub's) only that it failed, with the error in the hub's log.
func told(err error) errStatus {
	var s errStatus
	var syntax *json.SyntaxError
	var mistyped *json.UnmarshalTypeError
	switch {
	case errors.As(err, &s):
	case errors.Is(err, ErrNotFound):
		s = errStatus{http.StatusNotFound, "not found"}
	case errors.Is(err, errNoAgent):
		s = errStatus{http.StatusServiceUnavailable, err.Error()}
	case errors.As(err, &syntax), errors.As(err, &mistyped):
		s = errStatus{http.StatusBadRequest, "invalid arguments: " + err.Error()}
	default:
		slog.Error("request failed", "error", err)
		s = errStatus{http.StatusInternalServerError, "internal error"}
	}
	return s
}

func reply(w http.ResponseWriter, v any) error {
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(v)
}

func bearer(r *http.Request) string {
	if t, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok && t != "" {
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
		// A browser that signed in at the OIDC provider.
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			return User{}, errors.New("no token")
		}
		u, err := h.openSession(c.Value, time.Now())
		return h.withAdmin(u), err
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
	r, err := h.agents.query(ctx, cluster, "", api.Query{Op: "review", Namespace: namespace, User: u.Name, Groups: u.Groups})
	if err != nil {
		return err
	}
	if !r.Allowed {
		return errStatus{http.StatusForbidden, "you need the right to exec into pods of this namespace (pods/exec)"}
	}
	return nil
}

// clusterOf returns the cluster whose agents join with the token.
func (h *Hub) clusterOf(token string) (string, bool) {
	name, known := "", false
	for _, c := range h.Clusters {
		if subtle.ConstantTimeCompare([]byte(c.Token), []byte(token)) == 1 {
			name, known = c.Name, true
		}
	}
	return name, known
}

// clusterNames lists the configured clusters by name.
func (h *Hub) clusterNames() []string {
	names := []string{}
	for _, c := range h.Clusters {
		names = append(names, c.Name)
	}
	slices.Sort(names)
	return names
}

func (h *Hub) listClusters(w http.ResponseWriter, r *http.Request, _ User) error {
	names := h.clusterNames()
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

func (h *Hub) listNamespaces(w http.ResponseWriter, r *http.Request, u User) error {
	list, err := h.namespaces(r.Context(), u, r.PathValue("cluster"))
	if err != nil {
		return err
	}
	return reply(w, list)
}

// namespaces lists the namespaces of a cluster whose workloads the user may
// capture: all for an administrator.
func (h *Hub) namespaces(ctx context.Context, u User, cluster string) ([]string, error) {
	q := api.Query{Op: "namespaces", User: u.Name, Groups: u.Groups}
	if u.Admin {
		q.User, q.Groups = "", nil
	}
	res, err := h.agents.query(ctx, cluster, "", q)
	if res.Namespaces == nil {
		res.Namespaces = []string{}
	}
	return res.Namespaces, err
}

// listContainers names the containers of the workload in the query.
func (h *Hub) listContainers(w http.ResponseWriter, r *http.Request, u User) error {
	cluster, namespace, workload := r.PathValue("cluster"), r.PathValue("namespace"), r.URL.Query().Get("workload")
	if !api.ValidWorkload(workload) {
		return errWorkloadRequired
	}
	if err := h.allowed(r.Context(), u, cluster, namespace); err != nil {
		return err
	}
	res, err := h.agents.query(r.Context(), cluster, "", api.Query{Op: "workload", Namespace: namespace, Workload: workload})
	if err != nil {
		return err
	}
	return reply(w, res.Containers)
}

func (h *Hub) listWorkloads(w http.ResponseWriter, r *http.Request, u User) error {
	cluster, namespace := r.PathValue("cluster"), r.PathValue("namespace")
	if err := h.allowed(r.Context(), u, cluster, namespace); err != nil {
		return err
	}
	res, err := h.agents.query(r.Context(), cluster, "", api.Query{Op: "workloads", Namespace: namespace})
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
	in.Watch, in.Trigger, in.On = "", "", ""
	if err := in.Validate(); err != nil {
		return api.Capture{}, errStatus{http.StatusBadRequest, err.Error()}
	}
	for _, rec := range in.Recordings {
		if _, ok := rec.Params["before"]; ok {
			return api.Capture{}, errStatus{http.StatusBadRequest, "before only applies to a watch: a capture that starts now has nothing running beforehand"}
		}
	}
	if err := h.allowed(ctx, u, in.Cluster, in.Namespace); err != nil {
		return api.Capture{}, err
	}
	res, err := h.agents.query(ctx, in.Cluster, "", api.Query{Op: "resolve", Namespace: in.Namespace, Workload: in.Workload})
	if err != nil {
		return api.Capture{}, err
	}
	pods := slices.DeleteFunc(res.Pods, func(p api.Pod) bool { return len(in.Pods) > 0 && !slices.Contains(in.Pods, p.Name) })
	if len(pods) == 0 {
		return api.Capture{}, errStatus{http.StatusUnprocessableEntity, "the workload has no matching running pods"}
	}
	return h.record(ctx, u, in, pods, "capture.request", "")
}

// record stores a checked capture for the pods, under the audit action, and
// starts it unless it needs approval. The capture of an approved watch
// carries the watch's approver and needs none.
func (h *Hub) record(ctx context.Context, u User, in api.CaptureRequest, pods []api.Pod, action, approver string) (api.Capture, error) {
	c := api.Capture{ID: uuid.NewString(), CaptureRequest: in, Requester: u.Name, Sensitive: in.Sensitive(), State: api.StateQueued, Approver: approver, ExpiresAt: time.Now().Add(h.Retention)}
	if c.Sensitive && approver == "" {
		if h.approvesOwn(u) {
			// Asking this user for their own approval would add nothing.
			c.Approver = u.Name
		} else {
			c.State = api.StatePendingApproval
		}
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
	if c.Sensitive && c.Approver == u.Name && approver == "" {
		if err := h.Store.Audit(ctx, u.Name, "capture.approve", c.ID, map[string]bool{"own": true}); err != nil {
			return api.Capture{}, err
		}
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
	// A shared capture is also there for everyone who may capture in its
	// namespace, which the cluster's RBAC tells; for anyone else it does
	// not exist.
	if !owns(u, c) && (!c.Shared || h.allowed(ctx, u, c.Cluster, c.Namespace) != nil) {
		return c, ErrNotFound
	}
	c.RemainingSeconds = remaining(c, time.Now())
	return c, nil
}

// owns tells whether the capture is the user's to change: its requester's
// and every administrator's. Others may only look at one that is shared.
func owns(u User, c api.Capture) bool { return u.Admin || c.Requester == u.Name }

// own returns the capture if the user may change it.
func (h *Hub) own(ctx context.Context, u User, id string) (api.Capture, error) {
	c, err := h.visible(ctx, u, id)
	if err == nil && !owns(u, c) {
		err = errStatus{http.StatusForbidden, "only its requester and administrators may change a capture"}
	}
	return c, err
}

// shareCapture shares a capture with everyone who may capture in its
// namespace, or takes that back.
func (h *Hub) shareCapture(w http.ResponseWriter, r *http.Request, u User) error {
	var in struct{ Shared bool }
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		return errStatus{http.StatusBadRequest, "invalid JSON"}
	}
	c, err := h.own(r.Context(), u, r.PathValue("id"))
	if err != nil {
		return err
	}
	if err := h.Store.Share(r.Context(), c.ID, in.Shared); err != nil {
		return err
	}
	// What a colleague has open of it closes with the sharing.
	if !in.Shared {
		h.views.endOf(c.ID, true)
	}
	action := "capture.share"
	if !in.Shared {
		action = "capture.unshare"
	}
	if err := h.Store.Audit(r.Context(), u.Name, action, c.ID, nil); err != nil {
		return err
	}
	h.notify(c.ID)
	c.Shared = in.Shared
	return reply(w, c)
}

// remaining returns how many seconds of the time frame the capture's
// running recordings still have, or nil if none runs over time.
func remaining(c api.Capture, now time.Time) *int {
	if c.State != api.StateRunning {
		return nil
	}
	frame := time.Duration(c.DurationSeconds) * time.Second
	var most *int
	for _, t := range c.Tasks {
		for _, status := range t.Recordings {
			rec := c.Recording(status.Kind)
			if rec == nil || !rec.Timed(frame > 0) || status.State != api.StateRunning && status.State != api.StateWaiting {
				continue
			}
			left := frame // a waiting recording has all of it ahead
			if status.StartedAt != nil {
				left = max(0, frame-now.Sub(*status.StartedAt))
			}
			if seconds := int(left.Round(time.Second) / time.Second); most == nil || seconds > *most {
				most = &seconds
			}
		}
	}
	return most
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
	var shared []Place
	if u.Admin {
		requester = ""
	} else {
		// Of the namespaces that hold what others shared, those in which
		// this user may capture. A cluster that does not answer shares nothing.
		places, err := h.Store.SharedPlaces(ctx, u.Name)
		if err != nil {
			return nil, err
		}
		for _, p := range places {
			if h.allowed(ctx, u, p.Cluster, p.Namespace) == nil {
				shared = append(shared, p)
			}
		}
	}
	list, err := h.Store.Captures(ctx, requester, shared, before, limit)
	if list == nil {
		list = []api.Capture{}
	}
	for i := range list {
		list[i].RemainingSeconds = remaining(list[i], time.Now())
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

// approvesOwn reports whether the user's sensitive requests need nobody
// else: an administrator of an installation that allows self-approval.
func (h *Hub) approvesOwn(u User) bool { return u.Admin && h.AllowSelfApproval }

// mayApprove refuses an administrator's approval of their own request,
// unless the installation allows it.
func (h *Hub) mayApprove(u User, requester string) error {
	if requester == u.Name && !h.AllowSelfApproval {
		return errStatus{http.StatusForbidden, "another administrator must approve your request"}
	}
	return nil
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
	if state == api.StateQueued {
		if err := h.mayApprove(u, c.Requester); err != nil {
			return c, err
		}
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

// stopCapture ends the recordings that run over time now and keeps what
// they recorded: the capture then completes as if its time frame had ended.
func (h *Hub) stopCapture(w http.ResponseWriter, r *http.Request, u User) error {
	c, err := h.own(r.Context(), u, r.PathValue("id"))
	if err != nil {
		return err
	}
	// The stop is recorded first: an agent that is away, or receives its
	// task only later, learns it with the task.
	stopped, err := h.Store.Stop(r.Context(), c.ID)
	if err != nil {
		return err
	}
	if !stopped {
		return errStatus{http.StatusConflict, "the capture is not running"}
	}
	for _, t := range c.Tasks {
		h.agents.send(c.Cluster, t.Node, api.Command{Type: "stop", ID: c.ID})
	}
	h.notify(c.ID)
	return h.Store.Audit(r.Context(), u.Name, "capture.stop", c.ID, nil)
}

func (h *Hub) cancelCapture(w http.ResponseWriter, r *http.Request, u User) error {
	c, err := h.own(r.Context(), u, r.PathValue("id"))
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
	c, err := h.own(r.Context(), u, r.PathValue("id"))
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
	// Nobody keeps looking at files that are gone.
	h.views.endOf(id, false)
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
	if err := unpacked(w, blob, key, a.Packed); err != nil {
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
	// beforeId narrows the entries of the moment "before" to those that a page has not shown yet.
	beforeID := int64(math.MaxInt64)
	if v := r.URL.Query().Get("beforeId"); v != "" {
		if beforeID, err = strconv.ParseInt(v, 10, 64); err != nil {
			return errStatus{http.StatusBadRequest, "beforeId must be a number"}
		}
	} else if r.URL.Query().Get("before") != "" {
		beforeID = 0 // as before: everything older than the moment
	}
	list, err := h.Store.AuditLog(r.Context(), before, beforeID, limit)
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
		// The hint names nothing: every signed-in user has this stream, and
		// that a capture exists is its requester's to know.
		select {
		case ch <- "changed":
		default: // a slow reader misses the hint and reloads on its next event
		}
	}
}

// events streams a hint whenever a capture or a watch changes (Server-Sent
// Events). A client reloads what it shows; the hint itself carries no data.
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
	h.stream(r.Context(), w, ": connected", ch)
	return nil
}

// stream writes an event stream (Server-Sent Events) until ctx ends: first
// what it begins with, then every event that arrives, each as one line.
// While there is nothing to say it writes an empty comment at every beat,
// which a browser ignores. No event tells that a proxy on the way is about
// to give up a silent connection, so this goes by the clock.
func (h *Hub) stream(ctx context.Context, w http.ResponseWriter, first string, events <-chan string) {
	w.Header().Set("Content-Type", "text/event-stream")
	rc := http.NewResponseController(w)
	fmt.Fprintf(w, "%s\n\n", first)
	rc.Flush()
	beat := time.NewTicker(h.StreamBeat)
	defer beat.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-events:
			fmt.Fprintf(w, "data: %s\n\n", event)
		case <-beat.C:
			fmt.Fprint(w, ":\n\n")
		}
		rc.Flush()
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
