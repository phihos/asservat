package integration

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	configapp "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5/pgxpool"
)

func qualifyRegistrationWithdrawal(t *testing.T, admin, authority *pgxpool.Pool, permissions *postgres.Permissions, target authorization.Target, batch cfg.PermissionBatch, flush func(*testing.T, *postgres.Permissions)) {
	t.Helper()
	ctx := t.Context()
	const password = "synthetic-delivery"
	role := narrowRole(t, ctx, admin, "delivery_", password, func(role string) []string {
		grants, ok := postgres.PublicRuntimeRoleGrantSQL("connector-delivery", role)
		if !ok {
			t.Fatal("missing connector delivery grants")
		}
		return grants
	})
	pc := authority.Config()
	pc.ConnConfig.User, pc.ConnConfig.Password = role, password
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if _, err = pool.Exec(ctx, "UPDATE permission_stream SET suspended=true WHERE false"); err == nil {
		t.Fatal("delivery role can edit arbitrary permission streams")
	}
	if _, err = authority.Exec(ctx, "SELECT public.withdraw_remote_bindings($1,'{}'::uuid[])", batch.RootID); err == nil {
		t.Fatal("withdrawal function available outside delivery role")
	}
	deliveries := func(root string) *postgres.RemoteAccessBindings {
		t.Helper()
		r, err := postgres.NewRemoteAccessBindings(ctx, pool, root)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	store, otherRoot := deliveries(batch.RootID), deliveries(custodyID())
	active := custodyID()
	sum := strings.Repeat("ac", 32)
	basis := batch.Bases[0]
	original := cfg.Binding{Resource: basis.Resource, Scope: basis.Scope, Subjects: basis.Subjects, Roles: basis.Roles, Effect: basis.Effect}
	original.Resource.ClusterID = target.ClusterID
	original.Resource.Name, original.Resource.Namespace, original.Resource.NamespaceUID = "readers", basis.Scope.Namespace.Name, basis.Scope.Namespace.UID
	for _, d := range []struct {
		s       *postgres.RemoteAccessBindings
		cluster string
	}{{store, active}, {store, target.ClusterID}, {otherRoot, target.ClusterID}} {
		b := cfg.RemoteBindings{ClusterID: d.cluster, ObservedAt: time.Now().UTC(), Bindings: []cfg.Binding{}}
		if d.cluster == target.ClusterID {
			b.Bindings = []cfg.Binding{original}
		}
		if err := d.s.StoreRemoteBindings(ctx, b, sum); err != nil {
			t.Fatal(err)
		}
	}
	both := []string{active, target.ClusterID}
	if err := store.WithdrawUnregistered(ctx, both); err != nil {
		t.Fatal(err)
	}
	if got, err := permissions.Permissions(ctx, target); err != nil || len(got.Allows) != 1 {
		t.Fatal("unchanged registrations interrupted the current Allow", err)
	}
	done := make(chan error, 2)
	for range 2 {
		go func() { done <- store.WithdrawUnregistered(ctx, []string{active}) }()
	}
	for range 2 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if got, err := permissions.Permissions(ctx, target); !errors.Is(err, cfg.ErrUnavailable) || len(got.Allows) != 0 {
		t.Fatal("withdrawal left the old projection current", err)
	}
	if _, err := permissions.RenewPermissions(ctx, cfg.PermissionFence{RootID: batch.RootID, Epoch: batch.Epoch, TrustDigest: batch.TrustDigest}); !errors.Is(err, cfg.ErrChanged) {
		t.Fatal("withdrawn permission epoch could renew", err)
	}
	if err := store.WithdrawUnregistered(ctx, both); err != nil {
		t.Fatal(err)
	}
	for _, d := range []struct {
		s               *postgres.RemoteAccessBindings
		cluster, digest string
	}{{store, active, sum}, {store, target.ClusterID, ""}, {otherRoot, target.ClusterID, sum}} {
		got, observed, err := d.s.RemoteBindingsDigest(ctx, d.cluster)
		if observed.IsZero() {
			t.Fatal("missing database observation", err)
		}
		if err != nil || got != d.digest {
			t.Fatal("incorrect delivery after same-name registration", got, err)
		}
	}

	// Stand up the permission worker before the replacement's first delivery.
	// The ordinary SQL notification then drives acceptance of its own subject.
	live, stop := context.WithTimeout(ctx, 15*time.Second)
	defer stop()
	changes := postgres.Listen(live, pool, postgres.RemoteBindingsChannel)
	select {
	case <-changes: // LISTEN established
	case <-live.Done():
		t.Fatal("binding notification connection unavailable")
	}
	hub := remoteBindingHubFixture{cluster: custodyID()}
	writer := &observedPermissionWriter{permissions, make(chan cfg.PermissionAcceptance, 4), make(chan cfg.PermissionFence, 4), make(chan struct{}, 4)}
	reconciler := configapp.BindingReconciler{RootID: batch.RootID, NamespaceClusterID: hub.cluster, Reader: hub, Watcher: idleKubernetesBindingWatch(t, hub.cluster), Trust: hub, RemoteBindings: store, RemoteBindingChanges: changes, Store: writer, NewID: custodyID, Now: time.Now}
	ended := make(chan struct{})
	go func() { defer close(ended); reconciler.RunEpoch(live) }()
	defer func() { stop(); <-ended }()
	projection := func() authorization.Projection {
		t.Helper()
		select {
		case <-writer.accepted:
		case <-ended:
			t.Fatal("permission reconciler stopped before acceptance")
		case <-live.Done():
			t.Fatal("permission acceptance timed out")
		}
		flush(t, permissions)
		got, err := permissions.Permissions(ctx, target)
		if err != nil || !got.DeniesComplete {
			t.Fatal("replacement projection unavailable", err)
		}
		return got
	}
	if got := projection(); len(got.Allows) != 0 {
		t.Fatal("old grant reactivated before replacement sent bindings")
	}
	replacement := original
	replacement.Resource.UID = custodyID()
	replacement.Subjects = []cfg.Subject{{Kind: "Group", Issuer: original.Subjects[0].Issuer, ID: "replacement-team"}}
	d := cfg.RemoteBindings{ClusterID: target.ClusterID, ObservedAt: time.Now().UTC(), Bindings: []cfg.Binding{replacement}}
	if err := store.StoreRemoteBindings(ctx, d, strings.Repeat("bd", 32)); err != nil {
		t.Fatal(err)
	}
	if got := projection(); len(got.Allows) != 1 || got.Allows[0].Audience.SubjectID != "replacement-team" || got.Allows[0].Audience.BasisUID != replacement.Resource.UID {
		t.Fatal("same-name replacement did not receive only its own grant")
	}
}
