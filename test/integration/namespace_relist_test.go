package integration

import (
	"context"
	"encoding/json"
	"errors"
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
func (f *namespaceRelistFixture) PermissionSnapshot(ctx context.Context) (cfg.Snapshot, error) {
	s, err := f.remoteBindingHubFixture.PermissionSnapshot(ctx)
	s.Sources = []cfg.Source{f.source}
	s.ClusterBindingResourceVersion, s.SourceResourceVersion = "1", "1"
	if f.lossKind != "namespaces" && f.lost() {
		f.blockedOnce.Do(func() { close(f.blocked) })
		select {
		case <-ctx.Done():
			return cfg.Snapshot{}, ctx.Err()
		case <-f.release:
		}
		s.Sources = nil
		s.ClusterBindingResourceVersion, s.SourceResourceVersion = "2", "2"
	}
	return s, err
}

func (f *namespaceRelistFixture) serve(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Path[strings.LastIndexByte(r.URL.Path, '/')+1:]
	affected := kind == f.lossKind
	if kind == "namespaces" && r.URL.Query().Get("watch") != "true" {
		rv, team := "1", "old"
		if f.lost() && affected {
			f.blockedOnce.Do(func() { close(f.blocked) })
			if f.status == http.StatusGone {
				select {
				case <-r.Context().Done():
					return
				case <-f.release:
				}
			}
			// The LIST may remain authorized throughout a watch-only denial.
			rv, team = "2", "new"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": "v1", "kind": "NamespaceList", "metadata": map[string]string{"resourceVersion": rv}, "items": []any{map[string]any{"metadata": map[string]any{"name": f.ns.Name, "uid": f.ns.UID, "resourceVersion": rv, "labels": map[string]string{"team": team}}}}})
		return
	}
	if r.URL.Query().Get("watch") != "true" {
		http.NotFound(w, r)
		return
	}
	if affected {
		f.watches.Add(1)
		if f.lost() && !f.restored() {
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
		}
		return // EOF, then the real watch opener encounters the status above.
	}
	<-r.Context().Done()
}

func qualifyBlockedNamespaceRelist(t *testing.T, pool *pgxpool.Pool, flush func(*testing.T, *postgres.Permissions)) {
	t.Helper()
	for _, tc := range []struct {
		kind   string
		status int
	}{{"namespaces", http.StatusGone}, {"namespaces", http.StatusForbidden}, {"permissionsources", http.StatusGone}, {"clusteraccessbindings", http.StatusGone}} {
		t.Run(tc.kind+"-"+http.StatusText(tc.status), func(t *testing.T) { qualifyLostPermissionWatch(t, pool, flush, tc.kind, tc.status) })
	}
}

func qualifyLostPermissionWatch(t *testing.T, pool *pgxpool.Pool, flush func(*testing.T, *postgres.Permissions), kind string, status int) {
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
	r := configapp.BindingReconciler{RootID: root, NamespaceClusterID: cluster, Reader: hub, Watcher: watcher, Trust: hub, Namespaces: watcher, WatchConfiguration: watcher.WatchConfiguration, Store: writer, NewID: custodyID, Now: time.Now}
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
	eligible := func(old, new bool) {
		t.Helper()
		flush(t, permissions)
		projection, err := permissions.Permissions(ctx, target)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		member := identity.Identity{Principal: identity.Principal{Issuer: issuer, Subject: "viewer", ClientID: "console", Kind: identity.Human}, Policy: identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{1}}, Scopes: []string{"evidence:read"}, VerifiedAt: now, ValidUntil: now.Add(30 * time.Second)}
		for team, want := range map[string]bool{"old-team": old, "new-team": new, "direct-team": true} {
			member.Groups = []string{team}
			if got := authorization.ScopeEligibility(member, projection, authorization.ReadApproved, target, now); got.Eligible != want {
				t.Fatalf("%s eligibility: %t, want %t (%s)", team, got.Eligible, want, got.Reason)
			}
		}
	}
	expect := func(old, new bool) {
		t.Helper()
		select {
		case <-writer.accepted:
		case err := <-done:
			t.Fatal("permission worker stopped", err)
		case <-ctx.Done():
			t.Fatal("permission transition missing")
		}
		eligible(old, new)
	}
	// Start with the explicit binding. The initial namespace LIST can
	// already have committed by the time its predecessor's audit drains.
	select {
	case <-writer.accepted:
	case <-ctx.Done():
		t.Fatal("initial permission baseline missing")
	}
	expect(true, false)
	if status == http.StatusForbidden {
		select {
		case <-writer.renewed:
		case <-ctx.Done():
			t.Fatal("idle selector did not reach lease renewal")
		}
		if hub.watches.Load() != 1 {
			t.Fatal("idle selector reopened its watch", hub.watches.Load())
		}
		eligible(true, false)
	}
	close(hub.expired)
	if kind == "clusteraccessbindings" {
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
	if kind == "clusteraccessbindings" {
		if _, err := permissions.Permissions(ctx, target); !errors.Is(err, cfg.ErrUnavailable) {
			t.Fatal("old grants still current during cluster binding relist", err)
		}
	} else {
		expect(false, false)
		if status == http.StatusForbidden {
			select {
			case <-writer.renewed:
			case <-ctx.Done():
				t.Fatal("no lease renewal during denied watch")
			}
			eligible(false, false)
		}
	}
	close(hub.release)
	expect(false, kind == "namespaces")
}
