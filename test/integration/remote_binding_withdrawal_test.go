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
		if err := d.s.StoreRemoteBindings(ctx, b.ClusterID, time.Time{}, sum, b.Bindings); err != nil {
			t.Fatal(err)
		}
	}
	// A stale change cannot overwrite a later confirmation, and a stale
	// confirmation cannot acknowledge a digest replaced by a concurrent writer.
	// Exercise the same exchanges with a stored timestamp ahead of the clock.
	if _, err := admin.Exec(ctx, "UPDATE remote_access_binding_delivery SET observed_at=clock_timestamp()+interval '1 hour' WHERE root_id=$1 AND cluster_id=$2", batch.RootID, active); err != nil {
		t.Fatal(err)
	}
	_, initial, err := store.RemoteBindingsDigest(ctx, active)
	if err != nil || !initial.After(time.Now()) {
		t.Fatal("future predecessor", err)
	}
	if err := store.StoreRemoteBindings(ctx, active, initial, sum, nil); err != nil {
		t.Fatal("confirm", err)
	}
	replacementDigest := strings.Repeat("ca", 32)
	if err := store.StoreRemoteBindings(ctx, active, initial, replacementDigest, nil); !errors.Is(err, cfg.ErrChanged) {
		t.Fatal("stale replacement acknowledged")
	}
	_, confirmed, err := store.RemoteBindingsDigest(ctx, active)
	if err != nil || !confirmed.After(initial) {
		t.Fatal("confirmation did not advance revision", err)
	}
	if err := store.StoreRemoteBindings(ctx, active, confirmed, replacementDigest, nil); err != nil {
		t.Fatal("replace", err)
	}
	if err := store.StoreRemoteBindings(ctx, active, confirmed, sum, nil); !errors.Is(err, cfg.ErrChanged) {
		t.Fatal("stale confirmation acknowledged")
	}
	_, current, err := store.RemoteBindingsDigest(ctx, target.ClusterID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.StoreRemoteBindings(ctx, target.ClusterID, current, sum, nil); err != nil {
		t.Fatal("confirm populated delivery", err)
	}
	rows, err := store.RemoteBindings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var preserved bool
	for _, row := range rows {
		if row.ClusterID == target.ClusterID {
			preserved = len(row.Bindings) == 1 && row.Bindings[0].Resource.UID == original.Resource.UID
		}
	}
	if !preserved {
		t.Fatal("confirmation discarded the populated delivery")
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
	}{{store, active, replacementDigest}, {store, target.ClusterID, ""}, {otherRoot, target.ClusterID, sum}} {
		got, observed, err := d.s.RemoteBindingsDigest(ctx, d.cluster)
		if observed.IsZero() != (d.digest == "") {
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
	if err := store.StoreRemoteBindings(ctx, d.ClusterID, time.Time{}, strings.Repeat("bd", 32), d.Bindings); err != nil {
		t.Fatal(err)
	}
	if got := projection(); len(got.Allows) != 1 || got.Allows[0].Audience.SubjectID != "replacement-team" || got.Allows[0].Audience.BasisUID != replacement.Resource.UID {
		t.Fatal("same-name replacement did not receive only its own grant")
	}
}
