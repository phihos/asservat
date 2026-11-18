package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"

	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/postgres"
	configapp "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The hub's legacy namespaced Deny is present in the first LIST and changes
// on its original watch. A separate hub ClusterAccessBinding targets one
// remote. The other remote keeps its independent, audited Allow throughout.
func qualifyHubLegacyDeny(t *testing.T, admin, authority *pgxpool.Pool) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	root, hub, peer, blocked := custodyID(), custodyID(), custodyID(), custodyID()
	const issuer = "https://identity.example.invalid"
	ns := cfg.NamespaceRef{Name: "app", UID: custodyID()}
	permissions, err := postgres.NewPermissions(ctx, authority, root)
	if err != nil {
		t.Fatal(err)
	}
	deliveries, err := postgres.NewRemoteAccessBindings(ctx, connectorDeliveryPool(t, admin, authority), root)
	if err != nil {
		t.Fatal(err)
	}
	for _, cluster := range []string{peer, blocked} {
		grant := cfg.Binding{Resource: cfg.Resource{ClusterID: cluster, Namespace: ns.Name, NamespaceUID: ns.UID, Kind: "AccessBinding", Name: "readers", UID: custodyID(), ResourceVersion: "1", Generation: 1, SpecDigest: artifact.Digest{1}}, Scope: cfg.Scope{ClusterID: cluster, Namespace: ns}, Subjects: []cfg.Subject{{Kind: "Group", Issuer: issuer, ID: "team"}}, Roles: []string{"workload-maintainer"}, Effect: "Allow"}
		if err := deliveries.StoreRemoteBindings(ctx, cluster, time.Time{}, strings.Repeat("da", 32), []cfg.Binding{grant}, false); err != nil {
			t.Fatal(err)
		}
	}
	legacyID := strings.Repeat("x", 257)
	object := func(kind, name, effect, subject string, revision int) map[string]any {
		meta := map[string]any{"name": name, "uid": name, "generation": revision, "resourceVersion": strconv.Itoa(revision), "creationTimestamp": "2026-01-02T00:00:00Z"}
		spec := map[string]any{"effect": effect, "subjects": []map[string]string{{"kind": "Group", "issuer": issuer, "id": subject}}, "roles": []string{"workload-maintainer"}, "reason": "synthetic"}
		if kind == "AccessBinding" {
			meta["namespace"] = ns.Name
		} else {
			spec["clusters"] = []string{"blocked"}
		}
		return map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": kind, "metadata": meta, "spec": spec}
	}
	edits := make(chan map[string]any, 1)
	client := idleKubernetesBindingWatch(t, hub, func(w http.ResponseWriter, r *http.Request) {
		reply := json.NewEncoder(w)
		switch r.URL.Path {
		case "/api/v1/namespaces/app":
			_ = reply.Encode(map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]string{"name": ns.Name, "uid": ns.UID, "resourceVersion": "1", "creationTimestamp": "2026-01-01T00:00:00Z"}})
		case "/apis/asservat.io/v1alpha1/accessbindings":
			if r.URL.Query().Get("watch") == "true" {
				w.(http.Flusher).Flush()
				for {
					select {
					case <-r.Context().Done():
						return
					case e := <-edits:
						if reply.Encode(e) != nil {
							return
						}
						w.(http.Flusher).Flush()
					}
				}
			}
			// The hub startup LIST spans five seconds but fits its actual controller lease.
			select {
			case <-time.After(2600 * time.Millisecond):
			case <-r.Context().Done():
				return
			}
			metadata := map[string]string{"resourceVersion": "1"}
			item := object("AccessBinding", "local-grant", "Allow", "team", 1)
			if r.URL.Query().Get("continue") == "" {
				metadata["continue"] = "remaining"
			} else {
				item = object("AccessBinding", "legacy", "Deny", legacyID, 1)
			}
			_ = reply.Encode(map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "AccessBindingList", "metadata": metadata, "items": []map[string]any{item}})
		case "/apis/asservat.io/v1alpha1/clusteraccessbindings":
			_ = reply.Encode(map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "ClusterAccessBindingList", "metadata": map[string]string{"resourceVersion": "1"}, "items": []map[string]any{object(cfg.ClusterAccessBindingKind, "other-cluster", "Deny", legacyID, 1)}})
		default:
			http.NotFound(w, r)
		}
	}).WithClusterNames(map[string]string{"blocked": blocked, "healthy": peer})
	writer := &observedPermissionWriter{permissions, make(chan cfg.PermissionAcceptance, 1), make(chan cfg.PermissionFence, 1), make(chan struct{}, 1)}
	trust, err := kube.NewPlainPermissionTrust(client, artifact.Digest{4})
	if err != nil {
		t.Fatal(err)
	}
	r := configapp.BindingReconciler{RootID: root, NamespaceClusterID: hub, RegisteredClusters: []string{peer, blocked}, Reader: client, Watcher: client, Trust: trust, RemoteBindings: deliveries, Store: writer, NewID: custodyID, Now: time.Now}
	done := make(chan struct{})
	go func() { defer close(done); r.RunEpoch(ctx) }()
	defer func() { cancel(); <-done }()
	check := func(local string) {
		t.Helper()
		select {
		case <-writer.accepted:
		case <-done:
			t.Fatal("hub-local Deny suspended the fleet permission epoch")
		case <-ctx.Done():
			t.Fatal("permission acceptance timed out")
		}
		for cluster, want := range map[string]string{hub: local, blocked: "Unavailable", peer: "Allow"} {
			target := authorization.Target{ClusterID: cluster, NamespaceUID: ns.UID, WorkloadUID: "fixture-workload", PodUID: "fixture-pod"}
			projection, err := permissions.Permissions(ctx, target)
			if want == "Unavailable" {
				if !errors.Is(err, cfg.ErrUnavailable) {
					t.Fatal("cluster remained usable", cluster, err)
				}
				continue
			}
			if err != nil {
				t.Fatal("independent permissions unavailable", cluster, err)
			}
			now := time.Now()
			who := identity.Identity{Principal: identity.Principal{Kind: identity.Human, Issuer: issuer, Subject: "developer", ClientID: "console"}, Groups: []string{"team"}, Scopes: []string{"evidence:capture"}, Policy: identity.Revision{UID: "policy", Generation: 1, Digest: artifact.Digest{1}}, VerifiedAt: now, ValidUntil: now.Add(30 * time.Second)}
			result := authorization.ContextEligibility(who, projection, target, now)
			if (want == "Allow" && !result.Eligible) || (want == "ExplicitDeny" && result.Reason != want) {
				t.Fatal("unexpected cluster decision", cluster, want, result.Reason)
			}
		}
	}
	check("Unavailable")
	edits <- map[string]any{"type": "MODIFIED", "object": object("AccessBinding", "legacy", "Deny", "team", 2)}
	check("ExplicitDeny")
	edits <- map[string]any{"type": "MODIFIED", "object": object("AccessBinding", "legacy", "Deny", legacyID, 3)}
	check("Unavailable")
	edits <- map[string]any{"type": "DELETED", "object": object("AccessBinding", "legacy", "Deny", legacyID, 4)}
	check("Allow")

	t.Run("inert-binding-does-not-keep-removed-allow", func(t *testing.T) {
		ctx := t.Context()
		cluster := custodyID()
		var removed atomic.Bool
		client := idleKubernetesBindingWatch(t, cluster, func(w http.ResponseWriter, r *http.Request) {
			reply := json.NewEncoder(w)
			switch r.URL.Path {
			case "/api/v1/namespaces/app":
				_ = reply.Encode(map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]string{"name": ns.Name, "uid": ns.UID, "resourceVersion": "1", "creationTimestamp": "2026-01-01T00:00:00Z"}})
			case "/apis/asservat.io/v1alpha1/accessbindings":
				item := object("AccessBinding", "removed", "Allow", "team", 1)
				rv := "1"
				if removed.Load() {
					rv = "2"
					item = object("AccessBinding", "previous-incarnation", "Allow", "team", 1)
					item["metadata"].(map[string]any)["creationTimestamp"] = "2025-12-31T00:00:00Z"
				}
				_ = reply.Encode(map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "AccessBindingList", "metadata": map[string]string{"resourceVersion": rv}, "items": []map[string]any{item}})
			case "/apis/asservat.io/v1alpha1/clusteraccessbindings":
				_ = reply.Encode(map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "ClusterAccessBindingList", "metadata": map[string]string{"resourceVersion": "1"}, "items": []any{}})
			default:
				http.NotFound(w, r)
			}
		})
		decoder, err := kube.NewAccessBindingSpecDecoder()
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []int{1, 0} {
			_, previous, err := deliveries.RemoteBindingsDigest(ctx, cluster)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := client.AccessBindingDelivery(ctx)
			if err != nil {
				t.Fatal(err)
			}
			bindings, err := decoder.DeliveredBindings(cluster, wire)
			if err != nil {
				t.Fatal("replacement refused", err)
			}
			if err = deliveries.StoreRemoteBindings(ctx, cluster, previous, wire.Digest(), bindings, false); err != nil {
				t.Fatal(err)
			}
			rows, err := deliveries.RemoteBindings(ctx)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, row := range rows {
				if row.ClusterID == cluster {
					found = true
					if row.Unavailable || len(row.Bindings) != want || (want == 1 && row.Bindings[0].Resource.Name != "removed") {
						t.Fatal("unexpected published replacement", want, row)
					}
				}
			}
			if !found {
				t.Fatal("missing SQL delivery")
			}
			removed.Store(true)
		}
	})
}
