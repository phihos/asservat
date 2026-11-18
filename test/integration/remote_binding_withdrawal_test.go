package integration

import (
	"errors"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5/pgxpool"
)

func qualifyRegistrationWithdrawal(t *testing.T, admin, authority *pgxpool.Pool, permissions *postgres.Permissions, target authorization.Target, batch cfg.PermissionBatch) {
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
	for _, d := range []struct {
		s       *postgres.RemoteAccessBindings
		cluster string
	}{{store, active}, {store, target.ClusterID}, {otherRoot, target.ClusterID}} {
		b := cfg.RemoteBindings{ClusterID: d.cluster, ObservedAt: time.Now().UTC(), Bindings: []cfg.Binding{}}
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
		got, err := d.s.RemoteBindingsDigest(ctx, d.cluster)
		if err != nil || got != d.digest {
			t.Fatal("incorrect delivery after same-name registration", got, err)
		}
	}
}
