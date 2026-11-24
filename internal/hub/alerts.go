package hub

import (
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"

	"asservat.local/asservat/internal/api"
)

// A watch can wait for a Prometheus alert. The query is an alerting rule in
// Prometheus, where queries belong; Alertmanager tells the hub when the
// alert fires, with its webhook receiver. So nothing is polled, and the hub
// needs neither the address nor the credentials of Prometheus, only a
// secret that Alertmanager presents.

// alertNotice is the part of Alertmanager's webhook payload (version 4)
// that the hub reads.
type alertNotice struct {
	Alerts []struct {
		Status      string            `json:"status"` // "firing" or "resolved"
		Labels      map[string]string `json:"labels"`
		Annotations map[string]string `json:"annotations"`
		StartsAt    string            `json:"startsAt"`
		Fingerprint string            `json:"fingerprint"`
	} `json:"alerts"`
}

// alerts takes a notification of Alertmanager and records for every firing
// alert the watches that wait for it. It answers with the number of
// captures it created.
func (h *Hub) alerts(w http.ResponseWriter, r *http.Request) {
	if h.AlertToken == "" {
		fail(w, ErrNotFound)
		return
	}
	if subtle.ConstantTimeCompare([]byte(h.AlertToken), []byte(bearer(r))) != 1 {
		fail(w, errStatus{http.StatusUnauthorized, "unknown alert token"})
		return
	}
	var notice alertNotice
	if err := json.NewDecoder(r.Body).Decode(&notice); err != nil {
		fail(w, errStatus{http.StatusBadRequest, "not an Alertmanager notification"})
		return
	}
	watches, err := h.Store.Watches(r.Context(), "")
	if err != nil {
		fail(w, err)
		return
	}
	created := 0
	for _, alert := range notice.Alerts {
		if alert.Status != "firing" {
			continue
		}
		for _, watch := range watches {
			// The alert's labels say where it fires, as far as it has them.
			if watch.When.Kind != api.OnAlert || watch.When.Params["name"] != alert.Labels["alertname"] ||
				differs(alert.Labels["namespace"], watch.Namespace) || differs(alert.Labels["cluster"], watch.Cluster) {
				continue
			}
			told := alert.Annotations["summary"]
			if told == "" {
				told = alert.Annotations["description"]
			}
			// One firing of an alert is one start time of one fingerprint:
			// Alertmanager repeats its notifications while the alert fires.
			_, err := h.fire(r.Context(), watch.ID, alert.Fingerprint+"@"+alert.StartsAt, alert.Labels["pod"], api.OnAlert, "alert "+alert.Labels["alertname"]+" fires"+separated(": ", told))
			switch {
			case err == nil:
				created++
			case err != ErrNotFound: // not found: recorded before, or the watch has ended
				slog.Warn("alert not recorded", "watch", watch.ID, "alert", alert.Labels["alertname"], "error", err)
			}
		}
	}
	reply(w, map[string]int{"captures": created})
}

// differs tells whether a label names something else than the watch does;
// a label that the alert lacks names nothing.
func differs(label, of string) bool { return label != "" && label != of }

func separated(by, text string) string {
	if text == "" {
		return ""
	}
	return by + text
}
