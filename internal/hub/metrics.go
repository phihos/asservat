package hub

import (
	"fmt"
	"net/http"
	"strings"
)

// The hub tells a monitoring system how it stands, in Prometheus's text
// format: above all whether every cluster's agents are connected, which
// otherwise shows only when evidence is wanted and cannot be recorded.
// The figures are counted when they are asked for, from the database and
// from what the hub holds open; nothing is counted meanwhile. They name
// clusters and states, no workload, namespace or person.

// Metrics serves the figures. It is meant for a port of its own that only
// the cluster's monitoring reaches: it asks for no sign-in.
func (h *Hub) Metrics() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b strings.Builder
		metric := func(name, help string) {
			fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name)
		}
		metric("asservat_cluster_agents_connected", "Node agents of a cluster whose stream to the hub is open.")
		for _, cluster := range h.clusterNames() {
			fmt.Fprintf(&b, "asservat_cluster_agents_connected{cluster=%q} %d\n", cluster, len(h.agents.nodes(cluster)))
		}
		counts, err := h.Store.Counts(r.Context())
		if err != nil {
			http.Error(w, "the database does not answer", http.StatusServiceUnavailable)
			return
		}
		metric("asservat_captures", "Captures that the hub holds, by state.")
		for _, state := range counts.States {
			fmt.Fprintf(&b, "asservat_captures{state=%q} %d\n", state.State, state.Count)
		}
		metric("asservat_watches", "Watches that wait for their condition.")
		fmt.Fprintf(&b, "asservat_watches %d\n", counts.Watches)
		metric("asservat_evidence_files", "Files of evidence that the hub stores.")
		fmt.Fprintf(&b, "asservat_evidence_files %d\n", counts.Files)
		metric("asservat_evidence_bytes", "What the stored evidence takes of the store, before encryption: a core dump without its holes.")
		fmt.Fprintf(&b, "asservat_evidence_bytes %d\n", counts.Bytes)
		h.views.mu.Lock()
		open := len(h.views.open)
		h.views.mu.Unlock()
		metric("asservat_views_open", "Files that are open in a viewer and held by a program in the hub.")
		fmt.Fprintf(&b, "asservat_views_open %d\n", open)
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Write([]byte(b.String()))
	})
}
