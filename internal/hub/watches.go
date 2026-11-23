package hub

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"time"

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
	// Both attach to the process, which only one can do at a time.
	if trace := in.Recording(api.KindStrace); trace != nil && trace.Buffers() && in.Recording(api.KindCoredump) != nil && !in.When.Crash() {
		return api.Watch{}, errStatus{http.StatusBadRequest, "a trace of system calls that is kept running holds the process: the watch cannot take a core dump of it as well"}
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
	select { // the schedule looks at the watches again
	case h.scheduled <- struct{}{}:
	default:
	}
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

// fire creates the capture of a watch for something that the hub learns of
// itself, named by key, unless that was recorded before: of the pod named,
// or of all pods of the workload. The creator's permission is checked
// again, as for an agent's report.
func (h *Hub) fire(ctx context.Context, id, key, pod, on, message string) (api.Capture, error) {
	watch, groups, err := h.Store.Watch(ctx, id)
	if err == nil && watch.Sensitive && watch.Approver == "" {
		err = ErrNotFound
	}
	if err != nil {
		return api.Capture{}, err
	}
	u := h.withAdmin(User{Name: watch.Requester, Groups: groups})
	if err := h.allowed(ctx, u, watch.Cluster, watch.Namespace); err != nil {
		return api.Capture{}, err
	}
	res, err := h.agents.query(ctx, watch.Cluster, "", api.Query{Op: "resolve", Namespace: watch.Namespace, Workload: watch.Workload})
	if err != nil {
		return api.Capture{}, err
	}
	pods := slices.DeleteFunc(res.Pods, func(p api.Pod) bool { return pod != "" && p.Name != pod })
	if len(pods) == 0 {
		return api.Capture{}, errStatus{http.StatusUnprocessableEntity, "the watch's workload has no such running pod"}
	}
	remaining, err := h.Store.FireWatchOnce(ctx, id, key)
	if err != nil {
		return api.Capture{}, err
	}
	request := watch.CaptureRequest
	request.Watch, request.On, request.Reason = id, on, message
	for _, p := range pods {
		request.Pods = append(request.Pods, p.Name)
	}
	if watch.Reason != "" {
		request.Reason += " (" + watch.Reason + ")"
	}
	capture, err := h.record(ctx, u, request, pods, "capture.trigger", watch.Approver)
	if err != nil {
		if e := h.Store.RefundWatch(context.WithoutCancel(ctx), id); e != nil {
			slog.Error("watch's count not given back", "watch", id, "error", e)
		}
		return api.Capture{}, err
	}
	if remaining == 0 {
		if err := h.Store.DeleteWatch(ctx, id); err != nil {
			slog.Error("ended watch not deleted", "watch", id, "error", err)
		}
		h.pushWatches(ctx, watch.Cluster)
	}
	return capture, nil
}

// RecordNow makes a watch record at once, whatever it waits for: the pod
// named, or all pods of its workload. It uses up one of the watch's count.
func (h *Hub) RecordNow(ctx context.Context, u User, id, pod string) (api.Capture, error) {
	if uuid.Validate(id) != nil {
		return api.Capture{}, ErrNotFound
	}
	w, _, err := h.Store.Watch(ctx, id)
	if err != nil {
		return api.Capture{}, err
	}
	if !u.Admin && w.Requester != u.Name {
		return api.Capture{}, ErrNotFound
	}
	if w.Sensitive && w.Approver == "" {
		return api.Capture{}, errStatus{http.StatusConflict, "the watch awaits an administrator's approval"}
	}
	return h.fire(ctx, id, "asked "+uuid.NewString(), pod, api.OnAsked, "asked for by "+u.Name)
}

func (h *Hub) recordNow(w http.ResponseWriter, r *http.Request, u User) error {
	var in struct{ Pod string }
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil && err != io.EOF {
		return errStatus{http.StatusBadRequest, "invalid JSON"}
	}
	c, err := h.RecordNow(r.Context(), u, r.PathValue("id"), in.Pod)
	if err != nil {
		return err
	}
	w.WriteHeader(http.StatusCreated)
	return reply(w, c)
}

// RunSchedule records for the watches that wait for a time, when it comes.
// It sleeps until the next of their times and is woken when watches change.
// A time that came while the hub was down is recorded when it starts,
// unless another came since: of a time that repeats, only the last. A time
// that cannot be recorded, as while no agent is connected, is tried again
// after a pause until it can or the next one comes.
func (h *Hub) RunSchedule(ctx context.Context) {
	done := map[string]time.Time{} // the last time recorded for each watch
	for {
		list, err := h.Store.Watches(ctx, "")
		var timer <-chan time.Time
		if err != nil {
			slog.Error("schedule", "error", err)
			timer = time.After(time.Minute) // retry after a failure
		}
		var soonest time.Time
		for _, w := range list {
			if w.When.Kind != api.OnTime {
				continue
			}
			last, next := w.When.Due(time.Now())
			if !last.IsZero() && !done[w.ID].Equal(last) {
				// An agent that does not answer must not hold up the times
				// of the other watches: it gets as long as a retry waits.
				once, cancel := context.WithTimeout(ctx, h.ScheduleRetry)
				_, err := h.fire(once, w.ID, "time "+last.UTC().Format(time.RFC3339Nano), "", api.OnTime, "at the time set, "+last.UTC().Format(time.RFC3339))
				cancel()
				switch {
				case err == nil || err == ErrNotFound: // not found: recorded before, or the watch awaits approval
					done[w.ID] = last
				case ctx.Err() == nil:
					slog.Warn("time not recorded; trying again", "watch", w.ID, "in", h.ScheduleRetry, "error", err)
					timer = time.After(h.ScheduleRetry)
				}
			}
			if !next.IsZero() && (soonest.IsZero() || next.Before(soonest)) {
				soonest = next
			}
		}
		if !soonest.IsZero() && (timer == nil || time.Until(soonest) < h.ScheduleRetry) {
			timer = time.After(time.Until(soonest))
		}
		select {
		case <-ctx.Done():
			return
		case <-h.scheduled:
		case <-timer:
		}
	}
}
