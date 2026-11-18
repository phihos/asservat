package integration

import (
	"context"
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
	expired, blocked, release chan struct{}
}

func (f namespaceRelistFixture) PermissionSnapshot(ctx context.Context) (cfg.Snapshot, error) {
	s, err := f.remoteBindingHubFixture.PermissionSnapshot(ctx)
	s.Sources = []cfg.Source{f.source}
	return s, err
}

func (f namespaceRelistFixture) ListNamespaces(ctx context.Context, keys cfg.NamespaceKeys) (cfg.NamespaceList, error) {
	version, team := "1", "old"
	select {
	case <-f.expired:
		close(f.blocked)
		select {
		case <-ctx.Done():
			return cfg.NamespaceList{}, ctx.Err()
		case <-f.release:
		}
		version, team = "2", "new"
	default:
	}
	n := cfg.ObservedNamespace{Name: f.ns.Name, UID: f.ns.UID, ResourceVersion: version, Labels: map[string]string{"team": configapp.ValueDigest(team)}}
	return cfg.NamespaceList{ClusterID: f.cluster, ResourceVersion: version, Keys: keys, ObservedAt: time.Now(), Namespaces: []cfg.ObservedNamespace{n}}, nil
}

type namespaceHistoryWatch <-chan struct{}

func (w namespaceHistoryWatch) Close() {}
func (w namespaceHistoryWatch) Next(ctx context.Context) (cfg.NamespaceEvent, error) {
	select {
	case <-ctx.Done():
		return cfg.NamespaceEvent{}, ctx.Err()
	case <-w:
		return cfg.NamespaceEvent{}, cfg.ErrChanged // Kubernetes 410
	}
}

func (f namespaceRelistFixture) WatchNamespaces(_ context.Context, rv string, _ cfg.NamespaceKeys) (configapp.NamespaceWatch, error) {
	if rv == "1" {
		return namespaceHistoryWatch(f.expired), nil
	}
	return namespaceHistoryWatch(nil), nil
}

func qualifyBlockedNamespaceRelist(t *testing.T, pool *pgxpool.Pool, flush func(*testing.T, *postgres.Permissions)) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	root, cluster, issuer := custodyID(), custodyID(), "https://identity.synthetic.invalid"
	ns := cfg.NamespaceRef{Name: "app", UID: custodyID()}
	source := cfg.Source{Resource: cfg.Resource{ClusterID: cluster, Namespace: "asservat", NamespaceUID: cluster, Kind: "PermissionSource", Name: "owner", UID: custodyID(), Generation: 1, ResourceVersion: "1", SpecDigest: artifact.Digest{1}}, Enabled: true, Type: "namespaceMetadata", ClusterID: cluster, Role: "evidence-reader", Protection: cfg.Protection{Mode: "administratorManaged", ReviewRef: "platform-review"}, Mapping: cfg.Mapping{Field: "label", Key: "team", Mode: "valueMap", Issuer: issuer, Values: map[string][]string{"old": {"old-team"}, "new": {"new-team"}}}}
	direct := cfg.Binding{Resource: cfg.Resource{ClusterID: cluster, Namespace: ns.Name, NamespaceUID: ns.UID, Kind: "AccessBinding", Name: "direct", UID: custodyID(), Generation: 1, ResourceVersion: "1", SpecDigest: artifact.Digest{2}}, Scope: cfg.Scope{ClusterID: cluster, Namespace: ns}, Effect: "Allow", Roles: []string{"evidence-reader"}, Subjects: []cfg.Subject{{Kind: "Group", Issuer: issuer, ID: "direct-team"}}}
	hub := namespaceRelistFixture{remoteBindingHubFixture: remoteBindingHubFixture{cluster: cluster, bindings: []cfg.Binding{direct}}, ns: ns, source: source, expired: make(chan struct{}), blocked: make(chan struct{}), release: make(chan struct{})}
	permissions, err := postgres.NewPermissions(ctx, pool, root)
	if err != nil {
		t.Fatal(err)
	}
	writer := &observedPermissionWriter{permissions, make(chan cfg.PermissionAcceptance, 6), make(chan cfg.PermissionFence, 1), make(chan struct{}, 1)}
	watcher := idleKubernetesBindingWatch(t, cluster)
	r := configapp.BindingReconciler{RootID: root, NamespaceClusterID: cluster, Reader: hub, Watcher: watcher, Trust: hub, Namespaces: hub, Store: writer, NewID: custodyID, Now: time.Now}
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	target := authorization.Target{ClusterID: cluster, NamespaceUID: ns.UID, WorkloadUID: custodyID(), PodUID: custodyID()}
	expect := func(old, new bool) {
		t.Helper()
		select {
		case <-writer.accepted:
		case err := <-done:
			t.Fatal("permission worker stopped", err)
		case <-ctx.Done():
			t.Fatal("permission transition missing")
		}
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
	// Start with the explicit binding. The initial namespace LIST can
	// already have committed by the time its predecessor's audit drains.
	select {
	case <-writer.accepted:
	case <-ctx.Done():
		t.Fatal("initial permission baseline missing")
	}
	expect(true, false)
	close(hub.expired)
	select {
	case <-hub.blocked:
	case <-ctx.Done():
		t.Fatal("namespace relist never started")
	}
	expect(false, false)
	close(hub.release)
	expect(false, true)
}
