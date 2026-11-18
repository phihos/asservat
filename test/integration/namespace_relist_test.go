package integration

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	configapp "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

type namespaceRelistFixture struct {
	remoteBindingHubFixture
	ns                        cfg.NamespaceRef
	source                    cfg.Source
	lossKind                  string
	status                    int
	expired, blocked, release chan struct{}
	blockedOnce               sync.Once
	watches                   atomic.Int32
}

func (f *namespaceRelistFixture) lost() bool {
	select {
	case <-f.expired:
		return true
	default:
		return false
	}
}
func (f *namespaceRelistFixture) restored() bool {
	select {
	case <-f.release:
		return true
	default:
		return false
	}
}
func (f *namespaceRelistFixture) serve(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Path[strings.LastIndexByte(r.URL.Path, '/')+1:]
	affected := kind == f.lossKind
	if kind == "namespaces" && r.URL.Query().Get("watch") != "true" {
		rv, team := "1", "old"
		if f.lost() && affected {
			f.blockedOnce.Do(func() { close(f.blocked) })
			if f.status != http.StatusForbidden {
				select {
				case <-r.Context().Done():
					return
				case <-f.release:
				}
			}
			// The LIST may remain authorized throughout a watch-only denial.
			rv, team = "2", "new"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": "v1", "kind": "NamespaceList", "metadata": map[string]string{"resourceVersion": rv}, "items": []any{map[string]any{"metadata": map[string]any{"name": f.ns.Name, "uid": f.ns.UID, "resourceVersion": rv, "labels": map[string]string{"team": team, "managed": "true"}}}}})
		return
	}
	if r.URL.Query().Get("watch") != "true" {
		version := "1"
		items := []any{}
		var objectKind string
		switch kind {
		case f.ns.Name:
			_ = json.NewEncoder(w).Encode(map[string]any{"kind": "Namespace", "apiVersion": "v1", "metadata": map[string]string{"name": f.ns.Name, "uid": f.ns.UID, "resourceVersion": "1", "creationTimestamp": "2026-10-01T00:00:00Z"}})
			return
		case "accessbindings":
			objectKind = "AccessBinding"
			b := f.bindings[0]
			items = append(items, map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": objectKind, "metadata": map[string]any{"name": b.Resource.Name, "namespace": f.ns.Name, "uid": b.Resource.UID, "resourceVersion": "1", "generation": 1, "creationTimestamp": "2026-10-10T00:00:00Z"}, "spec": map[string]any{"reason": "synthetic direct access", "effect": "Allow", "roles": b.Roles, "subjects": []any{map[string]string{"kind": "Group", "issuer": b.Subjects[0].Issuer, "id": "direct-team"}}}})
		case "clusteraccessbindings":
			objectKind = "ClusterAccessBinding"
		case "permissionsources":
			objectKind = "PermissionSource"
		default:
			http.NotFound(w, r)
			return
		}
		if affected && kind != "accessbindings" && f.lost() {
			f.blockedOnce.Do(func() { close(f.blocked) })
			select {
			case <-r.Context().Done():
				return
			case <-f.release:
			}
			version = "2"
		}
		if kind == "permissionsources" && !(f.lost() && f.lossKind != "namespaces") {
			s := f.source
			items = append(items, map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": objectKind, "metadata": map[string]any{"name": s.Resource.Name, "namespace": "asservat", "uid": s.Resource.UID, "resourceVersion": "1", "generation": 1}, "spec": map[string]any{"enabled": true, "cluster": "local", "type": "namespaceMetadata", "namespaceSelector": map[string]any{"matchLabels": map[string]string{"managed": "true"}}, "excludedNamespaces": []string{"kube-system"}, "role": s.Role, "protection": map[string]string{"mode": "administratorManaged", "reviewRef": "platform-review"}, "metadataMapping": map[string]any{"field": "label", "key": "team", "mode": "valueMap", "issuer": s.Mapping.Issuer, "values": s.Mapping.Values}}})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": objectKind + "List", "metadata": map[string]string{"resourceVersion": version}, "items": items})
		return
	}
	if affected {
		f.watches.Add(1)
		if f.lost() && !f.restored() {
			if kind == "accessbindings" {
				f.blockedOnce.Do(func() { close(f.blocked) })
				select {
				case <-r.Context().Done():
					return
				case <-f.release:
				}
			}
			if f.status == http.StatusUnprocessableEntity {
				_, _ = io.WriteString(w, `{"type":"MODIFIED","type":"DELETED","object":{}}`)
				return
			}
			w.WriteHeader(f.status)
			_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": "v1", "kind": "Status", "status": "Failure", "code": f.status, "reason": http.StatusText(f.status)})
			return
		}
	}
	w.(http.Flusher).Flush()
	if affected && !f.lost() {
		select {
		case <-r.Context().Done():
		case <-f.expired:
			switch {
			case kind == "accessbindings":
				_, _ = io.WriteString(w, `{"type":"ERROR","object":{"kind":"Status","code":410,"reason":"Expired"}}`)
			case f.status == http.StatusUnprocessableEntity:
				_, _ = io.WriteString(w, `{"type":"MODIFIED","type":"DELETED","object":{}}`)
			}
		}
		return // EOF, then the real watch opener encounters the status above.
	}
	<-r.Context().Done()
}

func qualifyBlockedNamespaceRelist(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	for _, tc := range []struct {
		kind   string
		status int
	}{{"namespaces", http.StatusGone}, {"namespaces", http.StatusForbidden}, {"namespaces", http.StatusUnprocessableEntity}, {"accessbindings", http.StatusForbidden}, {"permissionsources", http.StatusGone}, {"clusteraccessbindings", http.StatusGone}} {
		t.Run(tc.kind+"-"+http.StatusText(tc.status), func(t *testing.T) { qualifyLostPermissionWatch(t, pool, tc.kind, tc.status) })
	}
}

func qualifyLostPermissionWatch(t *testing.T, pool *pgxpool.Pool, kind string, status int) {
	ctx, cancel := context.WithTimeout(t.Context(), 55*time.Second)
	defer cancel()
	root, cluster, issuer := custodyID(), custodyID(), "https://identity.synthetic.invalid"
	ns := cfg.NamespaceRef{Name: "app", UID: custodyID()}
	source := cfg.Source{Resource: cfg.Resource{ClusterID: cluster, Namespace: "asservat", NamespaceUID: cluster, Kind: "PermissionSource", Name: "owner", UID: custodyID(), Generation: 1, ResourceVersion: "1", SpecDigest: artifact.Digest{1}}, Enabled: true, Type: "namespaceMetadata", ClusterID: cluster, Role: "evidence-reader", Protection: cfg.Protection{Mode: "administratorManaged", ReviewRef: "platform-review"}, Mapping: cfg.Mapping{Field: "label", Key: "team", Mode: "valueMap", Issuer: issuer, Values: map[string][]string{"old": {"old-team"}, "new": {"new-team"}}}}
	direct := cfg.Binding{Resource: cfg.Resource{ClusterID: cluster, Namespace: ns.Name, NamespaceUID: ns.UID, Kind: "AccessBinding", Name: "direct", UID: custodyID(), Generation: 1, ResourceVersion: "1", SpecDigest: artifact.Digest{2}}, Scope: cfg.Scope{ClusterID: cluster, Namespace: ns}, Effect: "Allow", Roles: []string{"evidence-reader"}, Subjects: []cfg.Subject{{Kind: "Group", Issuer: issuer, ID: "direct-team"}}}
	hub := &namespaceRelistFixture{lossKind: kind, status: status, remoteBindingHubFixture: remoteBindingHubFixture{cluster: cluster, bindings: []cfg.Binding{direct}}, ns: ns, source: source, expired: make(chan struct{}), blocked: make(chan struct{}), release: make(chan struct{})}
	permissions, err := postgres.NewPermissions(ctx, pool, root)
	if err != nil {
		t.Fatal(err)
	}
	writer := &observedPermissionWriter{permissions, make(chan cfg.PermissionAcceptance, 6), make(chan cfg.PermissionFence, 1), make(chan struct{}, 1)}
	watcher := idleKubernetesBindingWatch(t, cluster, hub.serve)
	directRead, err := watcher.PermissionSnapshot(ctx)
	if err != nil || len(directRead.Bindings) != 1 || directRead.Bindings[0].Invalid {
		t.Fatal("production binding baseline", len(directRead.Bindings), err)
	}
	sourceRead, err := watcher.PermissionSources(ctx)
	if err != nil || len(sourceRead.Sources) != 1 {
		t.Fatal("production source baseline", len(sourceRead.Sources), len(sourceRead.InvalidSources), err)
	}
	r := configapp.BindingReconciler{RootID: root, NamespaceClusterID: cluster, Reader: watcher, ReadSources: watcher.PermissionSources, Watcher: watcher, Trust: hub, Namespaces: watcher, WatchConfiguration: watcher.WatchConfiguration, Store: writer, NewID: custodyID, Now: time.Now}
	done := make(chan error, 1)
	var workers sync.WaitGroup
	start := func() {
		workers.Go(func() {
			err := r.Run(ctx)
			select {
			case done <- err:
			case <-ctx.Done():
			}
		})
	}
	start()
	defer func() { cancel(); workers.Wait() }()
	target := authorization.Target{ClusterID: cluster, NamespaceUID: ns.UID, WorkloadUID: custodyID(), PodUID: custodyID()}
	eligible := func(old, new bool) bool {
		t.Helper()

		projection, err := permissions.Permissions(ctx, target)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		member := identity.Identity{Principal: identity.Principal{Issuer: issuer, Subject: "viewer", ClientID: "console", Kind: identity.Human}, Policy: identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{1}}, Scopes: []string{"evidence:read"}, VerifiedAt: now, ValidUntil: now.Add(30 * time.Second)}
		for team, want := range map[string]bool{"old-team": old, "new-team": new, "direct-team": true} {
			member.Groups = []string{team}
			if got := authorization.ScopeEligibility(member, projection, authorization.ReadApproved, target, now); got.Eligible != want {
				if team == "direct-team" {
					t.Fatalf("independent direct binding unavailable: %s", got.Reason)
				}
				return false
			}
		}
		return true
	}
	expect := func(old, new bool) {
		t.Helper()
		for {
			select {
			case <-writer.accepted:
				if eligible(old, new) {
					return
				}
			case err := <-done:
				t.Fatal("permission worker stopped", err)
			case <-ctx.Done():
				t.Fatal("expected permission decision missing", old, new)
			}
		}
	}
	expect(true, false)
	if status == http.StatusForbidden && kind == "namespaces" {
		select {
		case <-writer.renewed:
		case <-ctx.Done():
			t.Fatal("idle selector did not reach lease renewal")
		}
		if hub.watches.Load() != 1 {
			t.Fatal("idle selector reopened its watch", hub.watches.Load())
		}
		if !eligible(true, false) {
			t.Fatal("idle ownership lost")
		}
	}
	close(hub.expired)
	if kind == "clusteraccessbindings" || kind == "accessbindings" {
		// A missing cluster Deny can affect every assignment. The current
		// epoch must already be suspended when its successor starts to LIST.
		select {
		case err := <-done:
			if !errors.Is(err, cfg.ErrChanged) {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal("history loss left epoch running")
		}
		start()
	}
	select {
	case <-hub.blocked:
	case <-ctx.Done():
		t.Fatal("replacement LIST never started")
	}
	if kind == "clusteraccessbindings" || kind == "accessbindings" {
		if _, err := permissions.Permissions(ctx, target); !errors.Is(err, cfg.ErrUnavailable) {
			t.Fatal("old grants still current during cluster binding relist", err)
		}
	} else {
		expect(false, false)
		if status == http.StatusForbidden || kind == "permissionsources" {
			select {
			case <-writer.renewed:
			case <-ctx.Done():
				t.Fatal("no lease renewal during denied watch")
			}
			if !eligible(false, false) {
				t.Fatal("stalled source regained derived rights")
			}
		}
	}
	close(hub.release)
	if kind == "accessbindings" {
		select {
		case err := <-done:
			if !errors.Is(err, cfg.ErrDenied) {
				t.Fatal("watch denial missing", err)
			}
		case <-ctx.Done():
			t.Fatal("blocked opening failed to end epoch")
		}
		if _, err := permissions.Permissions(ctx, target); !errors.Is(err, cfg.ErrUnavailable) {
			t.Fatal("denied watch published the listed Allow", err)
		}
		return
	}
	expect(false, kind == "namespaces")
}
