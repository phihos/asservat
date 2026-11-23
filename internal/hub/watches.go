package hub

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/google/uuid"

	"asservat.local/asservat/internal/api"
)

// A watch is a standing capture request: whenever a container of its
// workload crashes, the pod's node agent reports it and the hub creates the
// capture for that pod, as the user who created the watch.

// Watch validates and records a watch and hands it to the cluster's agents.
func (h *Hub) Watch(ctx context.Context, u User, in api.WatchRequest) (api.Watch, error) {
	in.Watch, in.Trigger, in.On, in.Pods = "", "", "", nil
	if err := in.Validate(); err != nil {
		return api.Watch{}, errStatus{http.StatusBadRequest, err.Error()}
	}
	if err := in.When.Validate(); err != nil {
		return api.Watch{}, errStatus{http.StatusBadRequest, err.Error()}
	}
	if in.When.Kind == api.OnAlert && h.AlertToken == "" {
		return api.Watch{}, errStatus{http.StatusBadRequest, "this hub accepts no alerts: it has no alert token (hub.alertToken in its Helm values) for Alertmanager to present"}
	}
	if dump := in.Recording(api.KindCoredump); dump != nil && dump.Params["process"] != "" && in.When.Crash() {
		return api.Watch{}, errStatus{http.StatusBadRequest, "a core dump watch for crashes records whichever process crashes; it takes no process"}
	}
	if in.Count < 0 || in.BeforeSeconds < 0 {
		return api.Watch{}, errStatus{http.StatusBadRequest, "count and beforeSeconds must not be negative"}
	}
	if err := h.allowed(ctx, u, in.Cluster, in.Namespace); err != nil {
		return api.Watch{}, err
	}
	res, err := h.agents.query(ctx, in.Cluster, "", api.Query{Op: "workload", Namespace: in.Namespace, Workload: in.Workload})
	if err != nil {
		return api.Watch{}, err
	}
	w := api.Watch{ID: uuid.NewString(), CaptureRequest: in.CaptureRequest, When: in.When, BeforeSeconds: in.BeforeSeconds, Requester: u.Name, Sensitive: in.Sensitive(), Selector: res.Selector, Remaining: max(in.Count, 1)}
	if w.Sensitive && h.approvesOwn(u) {
		w.Approver = u.Name
	}
	if err := h.Store.CreateWatch(ctx, w, u.Groups); err != nil {
		return w, err
	}
	if err := h.Store.Audit(ctx, u.Name, "watch.create", "", w); err != nil {
		return w, err
	}
	if w.Approver != "" {
		if err := h.Store.Audit(ctx, u.Name, "watch.approve", "", map[string]any{"id": w.ID, "own": true}); err != nil {
			return w, err
		}
	}
	h.pushWatches(ctx, w.Cluster)
	w, _, err = h.Store.Watch(ctx, w.ID)
	return w, err
}

// watches lists the user's watches, or everyone's for an administrator.
func (h *Hub) watches(ctx context.Context, u User) ([]api.Watch, error) {
	requester := u.Name
	if u.Admin {
		requester = ""
	}
	list, err := h.Store.Watches(ctx, requester)
	if list == nil {
		list = []api.Watch{}
	}
	return list, err
}

// Unwatch ends a watch of the user, or any for an administrator.
func (h *Hub) Unwatch(ctx context.Context, u User, id string) error {
	if uuid.Validate(id) != nil {
		return ErrNotFound
	}
	w, _, err := h.Store.Watch(ctx, id)
	if err != nil {
		return err
	}
	if !u.Admin && w.Requester != u.Name {
		return ErrNotFound
	}
	if err := h.Store.DeleteWatch(ctx, id); err != nil {
		return err
	}
	h.pushWatches(ctx, w.Cluster)
	return h.Store.Audit(ctx, u.Name, "watch.delete", "", map[string]string{"id": id})
}

// ApproveWatch lets a sensitive watch start. The approval precedes the crash,
// so it covers the captures that the watch creates.
func (h *Hub) ApproveWatch(ctx context.Context, u User, id string) (api.Watch, error) {
	if uuid.Validate(id) != nil {
		return api.Watch{}, ErrNotFound
	}
	w, _, err := h.Store.Watch(ctx, id)
	if err != nil {
		return w, err
	}
	if err := h.mayApprove(u, w.Requester); err != nil {
		return w, err
	}
	ok, err := h.Store.ApproveWatch(ctx, id, u.Name)
	if err != nil {
		return w, err
	}
	if !ok {
		return w, errStatus{http.StatusConflict, "the watch is not awaiting approval"}
	}
	if err := h.Store.Audit(ctx, u.Name, "watch.approve", "", map[string]string{"id": id}); err != nil {
		return w, err
	}
	h.pushWatches(ctx, w.Cluster)
	w, _, err = h.Store.Watch(ctx, id)
	return w, err
}

// pushWatches sends the cluster's watches to its connected agents and tells
// the event streams. An agent that is away receives them when it connects.
func (h *Hub) pushWatches(ctx context.Context, cluster string) {
	list, err := h.Store.ActiveWatches(ctx, cluster)
	if err != nil {
		// The agents keep their previous list until the next change or reconnect.
		slog.Error("watches not sent", "cluster", cluster, "error", err)
		return
	}
	for _, node := range h.agents.nodes(cluster) {
		h.agents.send(cluster, node, api.Command{Type: "watches", Watches: list})
	}
	h.notify("watches")
}

func (h *Hub) createWatch(w http.ResponseWriter, r *http.Request, u User) error {
	var in api.WatchRequest
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		return errStatus{http.StatusBadRequest, "invalid JSON"}
	}
	watch, err := h.Watch(r.Context(), u, in)
	if err != nil {
		return err
	}
	w.WriteHeader(http.StatusCreated)
	return reply(w, watch)
}

func (h *Hub) listWatches(w http.ResponseWriter, r *http.Request, u User) error {
	list, err := h.watches(r.Context(), u)
	if err != nil {
		return err
	}
	return reply(w, list)
}

func (h *Hub) approveWatch(w http.ResponseWriter, r *http.Request, u User) error {
	watch, err := h.ApproveWatch(r.Context(), u, r.PathValue("id"))
	if err != nil {
		return err
	}
	return reply(w, watch)
}

func (h *Hub) deleteWatch(w http.ResponseWriter, r *http.Request, u User) error {
	return h.Unwatch(r.Context(), u, r.PathValue("id"))
}

// agentTrigger creates the capture of a watch for a pod whose container
// crashed. The creator's permission is checked again: it may have been
// revoked since the watch was created.
func (h *Hub) agentTrigger(w http.ResponseWriter, r *http.Request, cluster string) error {
	var in api.Trigger
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || !api.ValidName(in.Pod) || in.Node == "" || uuid.Validate(in.ID) != nil {
		return errStatus{http.StatusBadRequest, "invalid trigger"}
	}
	id := r.PathValue("id")
	if uuid.Validate(id) != nil {
		return ErrNotFound
	}
	watch, groups, err := h.Store.Watch(r.Context(), id)
	if err == nil && (watch.Cluster != cluster || watch.Sensitive && watch.Approver == "") {
		err = ErrNotFound
	}
	if err != nil {
		return err
	}
	u := h.withAdmin(User{Name: watch.Requester, Groups: groups})
	if err := h.allowed(r.Context(), u, cluster, watch.Namespace); err != nil {
		return err
	}
	remaining, err := h.Store.FireWatch(r.Context(), id)
	if err != nil {
		return err
	}
	request := watch.CaptureRequest
	request.Watch, request.Trigger, request.On, request.Pods, request.Reason = id, in.ID, watch.When.Kind, []string{in.Pod}, in.Message
	if watch.Reason != "" {
		request.Reason += " (" + watch.Reason + ")"
	}
	if _, err := h.record(r.Context(), u, request, []api.Pod{{Name: in.Pod, Node: in.Node}}, "capture.trigger", watch.Approver); err != nil {
		// Nothing was recorded, so this time does not count.
		if e := h.Store.RefundWatch(context.WithoutCancel(r.Context()), id); e != nil {
			slog.Error("watch's count not given back", "watch", id, "error", e)
		}
		return err
	}
	if remaining > 0 {
		return nil
	}
	// The capture exists: a failed cleanup is no failed report.
	if err := h.Store.DeleteWatch(r.Context(), id); err != nil {
		slog.Error("ended watch not deleted", "watch", id, "error", err)
	}
	h.pushWatches(r.Context(), cluster)
	return nil
}
