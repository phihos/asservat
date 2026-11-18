package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/postgres"
	configapp "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
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
		if err := d.s.StoreRemoteBindings(ctx, b.ClusterID, time.Time{}, sum, b.Bindings, false); err != nil {
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
	if err := store.StoreRemoteBindings(ctx, active, initial, sum, nil, false); err != nil {
		t.Fatal("confirm", err)
	}
	replacementDigest := strings.Repeat("ca", 32)
	if err := store.StoreRemoteBindings(ctx, active, initial, replacementDigest, nil, false); !errors.Is(err, cfg.ErrChanged) {
		t.Fatal("stale replacement acknowledged")
	}
	_, confirmed, err := store.RemoteBindingsDigest(ctx, active)
	if err != nil || !confirmed.After(initial) {
		t.Fatal("confirmation did not advance revision", err)
	}
	if err := store.StoreRemoteBindings(ctx, active, confirmed, replacementDigest, nil, false); err != nil {
		t.Fatal("replace", err)
	}
	if err := store.StoreRemoteBindings(ctx, active, confirmed, sum, nil, false); !errors.Is(err, cfg.ErrChanged) {
		t.Fatal("stale confirmation acknowledged")
	}
	_, current, err := store.RemoteBindingsDigest(ctx, target.ClusterID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.StoreRemoteBindings(ctx, target.ClusterID, current, sum, nil, false); err != nil {
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
	// A fleet administrator has already entitled a subject in the remote
	// cluster. A missing workload Deny observation must still block it.
	hubGrant := original
	hubGrant.Resource.Kind = cfg.ClusterAccessBindingKind
	hubGrant.Resource.Name, hubGrant.Resource.UID = "hub-readers", custodyID()
	hubGrant.Resource.Namespace, hubGrant.Resource.NamespaceUID = "", ""
	hubGrant.Scope.Namespace = cfg.AllNamespaces
	hubGrant.Subjects = []cfg.Subject{{Kind: "Group", Issuer: original.Subjects[0].Issuer, ID: "hub-team"}}
	hub := remoteWithdrawalHub{remoteBindingHubFixture{cluster: custodyID()}, hubGrant}
	writer := &observedPermissionWriter{permissions, make(chan cfg.PermissionAcceptance, 4), make(chan cfg.PermissionFence, 4), make(chan struct{}, 4)}
	reconciler := configapp.BindingReconciler{RootID: batch.RootID, NamespaceClusterID: hub.cluster, RegisteredClusters: both, Reader: hub, Watcher: idleKubernetesBindingWatch(t, hub.cluster), Trust: hub, RemoteBindings: store, RemoteBindingChanges: changes, Store: writer, NewID: custodyID, Now: time.Now}
	ended := make(chan struct{})
	go func() { defer close(ended); reconciler.RunEpoch(live) }()
	defer func() { stop(); <-ended }()
	awaitAcceptance := func() {
		t.Helper()
		select {
		case <-writer.accepted:
		case <-ended:
			t.Fatal("permission reconciler stopped before acceptance")
		case <-live.Done():
			t.Fatal("permission acceptance timed out")
		}
		flush(t, permissions)
	}
	projection := func() authorization.Projection {
		t.Helper()
		awaitAcceptance()
		got, err := permissions.Permissions(ctx, target)
		if err != nil || !got.DeniesComplete {
			t.Fatal("replacement projection unavailable", err)
		}
		return got
	}
	awaitAcceptance()
	if got, err := permissions.Permissions(ctx, target); !errors.Is(err, cfg.ErrUnavailable) || len(got.Allows) != 0 {
		t.Fatal("hub-wide Allow granted before first complete remote observation", err)
	}
	replacement := original
	replacement.Resource.UID = custodyID()
	replacement.Subjects = []cfg.Subject{{Kind: "Group", Issuer: original.Subjects[0].Issuer, ID: "replacement-team"}}
	d := cfg.RemoteBindings{ClusterID: target.ClusterID, ObservedAt: time.Now().UTC(), Bindings: []cfg.Binding{replacement}}
	if err := store.StoreRemoteBindings(ctx, d.ClusterID, time.Time{}, strings.Repeat("bd", 32), d.Bindings, false); err != nil {
		t.Fatal(err)
	}
	if got := projection(); len(got.Allows) != 2 || !slices.ContainsFunc(got.Allows, func(a authorization.CurrentAssignment) bool {
		return a.Audience.SubjectID == "replacement-team" && a.Audience.BasisUID == replacement.Resource.UID
	}) {
		t.Fatal("same-name replacement did not receive only its own grant")
	}

	// The old Allow must stop working if the replacement will not fit. A
	// scoped unavailable observation leaves the rest of the fleet usable.
	replace := func(bindings []cfg.Binding, digest string, unavailable bool) {
		t.Helper()
		_, previous, err := store.RemoteBindingsDigest(ctx, target.ClusterID)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.StoreRemoteBindings(ctx, target.ClusterID, previous, digest, bindings, unavailable); err != nil {
			t.Fatal(err)
		}
	}
	replace(nil, strings.Repeat("cb", 32), true)
	awaitAcceptance()
	if got, err := permissions.Permissions(ctx, target); !errors.Is(err, cfg.ErrUnavailable) || len(got.Allows) != 0 {
		t.Fatal("old access survived an unavailable replacement", err)
	}
	peerTarget := target
	peerTarget.ClusterID = active
	if got, err := permissions.Permissions(ctx, peerTarget); err != nil || !got.DeniesComplete {
		t.Fatal("unavailable delivery disabled the other cluster", err)
	}
	decoder, err := kube.NewAccessBindingSpecDecoder()
	if err != nil {
		t.Fatal(err)
	}
	issuer := replacement.Subjects[0].Issuer
	clusterBinding := func(effect, role, reason string, subjects []map[string]string) cfg.Binding {
		t.Helper()
		raw, err := json.Marshal(map[string]any{"effect": effect, "roles": []string{role}, "subjects": subjects, "reason": reason})
		if err != nil {
			t.Fatal(err)
		}
		d := contracts.AccessBindingDelivery{ResourceVersion: "1", Items: []contracts.DeliveredAccessBinding{{Kind: cfg.ClusterAccessBindingKind, Name: strings.ToLower(effect), UID: custodyID(), Generation: 1, ResourceVersion: "1", Spec: raw}}}
		bindings, err := decoder.DeliveredBindings(target.ClusterID, d.Bounded())
		if err != nil || len(bindings) != 1 {
			t.Fatal("cluster-wide delivery", err)
		}
		return bindings[0]
	}
	// Unrelated approvers do not expand this user's capture evidence audience.
	subjects := make([]map[string]string, 257)
	for i := range subjects {
		subjects[i] = map[string]string{"kind": "User", "issuer": issuer, "id": fmt.Sprintf("approver-%d", i)}
	}
	wide := clusterBinding("Allow", "action-approver", "cluster approvers", subjects)
	replace([]cfg.Binding{replacement, wide}, strings.Repeat("ab", 32), false)
	p := projection()
	now := time.Now()
	who := identity.Identity{Principal: identity.Principal{Issuer: issuer, Subject: "developer", ClientID: "console", Kind: identity.Human}, Groups: []string{replacement.Subjects[0].ID}, Scopes: []string{"evidence:capture"}, Policy: identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{1}}, VerifiedAt: now, ValidUntil: now.Add(30 * time.Second)}
	if got := authorization.ContextEligibility(who, p, target, now); len(p.Allows) != 259 || !got.Eligible || len(got.DefaultAudience) != 2 {
		t.Fatal("unrelated subjects obscured independent grant", len(p.Allows), got.Reason)
	}
	deny := clusterBinding("Deny", "workload-maintainer", strings.Repeat("x", 70<<10), []map[string]string{{"kind": "Group", "issuer": issuer, "id": replacement.Subjects[0].ID}})
	replace([]cfg.Binding{replacement, wide, deny}, strings.Repeat("db", 32), false)
	p = projection()
	if got := authorization.ContextEligibility(who, p, target, time.Now()); len(p.Denies) != 1 || got.Eligible || got.Reason != "ExplicitDeny" {
		t.Fatal("large cluster-wide Deny missing alongside overlapping Allow", len(p.Denies), got.Reason)
	}
}

type remoteWithdrawalHub struct {
	remoteBindingHubFixture
	grant cfg.Binding
}

func (h remoteWithdrawalHub) PermissionSnapshot(ctx context.Context) (cfg.Snapshot, error) {
	snapshot, err := h.remoteBindingHubFixture.PermissionSnapshot(ctx)
	snapshot.ClusterBindings = []cfg.Binding{h.grant}
	return snapshot, err
}
