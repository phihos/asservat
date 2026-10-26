package sharing

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/authorization"
	capture "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/fleet"
)

type administration struct{ a fleet.Administration }

func (a administration) FleetAdministration(context.Context) (fleet.Administration, error) {
	return a.a, nil
}

// fleetOperators names the "platform" group of the fixture issuer as the
// installation administrators.
func (f *fixture) fleetOperators() administration {
	return administration{fleet.Administration{InstallationID: testID(3), IssuerEpoch: testID(22), Issuer: f.i.Principal.Issuer, Revision: f.p.Revision,
		ObservedAt: f.now, FreshUntil: f.now.Add(5 * time.Second), Clients: []string{"mcp"}, Groups: []string{"platform"}, DeliveryProfiles: []string{"enrollment"},
		MaxActiveBootstraps: 1, MaxBootstrapHistory: 1, MaxClusters: 1}}
}

// ADR-238: explicit management at creation is limited to the creator's own
// current owner assignments; a team the creator does not hold is refused,
// never dropped.
func TestShareExplicitManagement(t *testing.T) {
	ctx := context.Background()
	f, s := newFixture()
	b := f.addOwnerTeam("owners-b", 13)
	f.addOwnerTeam("owners-c", 16) // an owner team the creator is not in
	f.i.Groups = []string{"owners", "owners-b"}

	in := f.input("k1")
	in.Management = value.ManagementRequest{Mode: "teams", Teams: []string{"owners-b"}}
	share, _, err := s.Create(ctx, f, in)
	if err != nil || len(share.Management) != 1 || share.Management[0].AssignmentID != b.AssignmentID {
		t.Fatal("explicit team selection", err, share.Management)
	}
	// The selection is part of the request: the same key without it conflicts.
	if _, _, err := s.Create(ctx, f, f.input("k1")); !errors.Is(err, capture.ErrConflict) {
		t.Fatal("selection is not part of the request digest", err)
	}
	for n, m := range []value.ManagementRequest{{Mode: "teams", Teams: []string{"owners-c"}}, {Mode: "teams", Teams: []string{"owners", "owners-c"}}, {Mode: "creator"}} {
		in := f.input(fmt.Sprint("k-", n))
		in.Management = m
		if _, _, err := s.Create(ctx, f, in); !errors.Is(err, ErrManagementNotHeld) {
			t.Fatal("selection of an assignment the creator does not hold", m, err)
		}
	}
	in = f.input("k-empty")
	in.Management = value.ManagementRequest{Mode: "teams"}
	if _, _, err := s.Create(ctx, f, in); !errors.Is(err, capture.ErrInvalid) {
		t.Fatal("empty team selection", err)
	}
	if len(f.store.created) != 1 {
		t.Fatal("a refused selection created a share", len(f.store.created))
	}
}

// ADR-238: a current manager transfers management to teams they hold now; a
// team they do not hold is refused; the replaced team no longer manages; the
// transferred share is suspended when the new team loses its assignment;
// expiry and creator never change.
func TestShareTransfer(t *testing.T) {
	ctx := context.Background()
	f, s := newFixture()
	b := f.addOwnerTeam("owners-b", 13)
	f.addOwnerTeam("owners-c", 16)
	creator := f.i
	share, _, err := s.Create(ctx, f, f.input("k1"))
	if err != nil || len(share.Management) != 1 || share.Management[0].SubjectID != "owners" {
		t.Fatal(err, share.Management)
	}
	to := func(key string, rev int64, teams ...string) TransferInput {
		return TransferInput{ShareID: share.ID, ExpectedRevision: rev, Management: value.ManagementRequest{Mode: "teams", Teams: teams}, IdempotencyKey: key}
	}
	mate := creator
	mate.Principal.Subject, mate.Groups = "mate", []string{"owners", "owners-b"}
	f.i = mate
	if _, _, err := s.Transfer(ctx, f, to("t0", 1, "owners-c")); !errors.Is(err, ErrManagementNotHeld) {
		t.Fatal("transfer to a team the caller does not hold", err)
	}
	if _, _, err := s.Transfer(ctx, f, TransferInput{ShareID: share.ID, ExpectedRevision: 1, Management: value.ManagementRequest{Mode: "creator"}, IdempotencyKey: "t0"}); !errors.Is(err, ErrManagementNotHeld) {
		t.Fatal("a member chose creator management", err)
	}
	// A non-manager (owner of another team) is refused before any catalog read.
	outsider := mate
	outsider.Principal.Subject, outsider.Groups = "outsider", []string{"owners-b"}
	f.i = outsider
	reads := f.catalogReads
	if _, _, err := s.Transfer(ctx, f, to("t0", 1, "owners-b")); !errors.Is(err, capture.ErrDenied) || f.catalogReads != reads {
		t.Fatal("a non-manager transferred, or read the catalog", err, f.catalogReads-reads)
	}
	f.i = mate
	moved, replay, err := s.Transfer(ctx, f, to("t1", 1, "owners-b"))
	if err != nil || replay || moved.Revision != 2 || len(moved.Management) != 1 || moved.Management[0].AssignmentID != b.AssignmentID || !moved.ExpiresAt.Equal(share.ExpiresAt) || moved.Creator != share.Creator {
		t.Fatal("transfer", err, moved)
	}
	if again, replay, err := s.Transfer(ctx, f, to("t1", 1, "owners-b")); err != nil || !replay || again.Revision != 2 {
		t.Fatal("transfer replay", err, replay)
	}
	if _, _, err := s.Transfer(ctx, f, to("t1", 1, "owners")); !errors.Is(err, capture.ErrConflict) {
		t.Fatal("same key for another selection", err)
	}
	if _, _, err := s.Transfer(ctx, f, to("t2", 1, "owners")); !errors.Is(err, capture.ErrConflict) {
		t.Fatal("stale revision", err)
	}
	// A member of only the replaced team no longer manages the share.
	member := creator
	member.Principal.Subject, member.Groups = "old-member", []string{"owners"}
	f.i = member
	if _, _, err := s.Revoke(ctx, f, share.ID, 2, "r-old"); !errors.Is(err, capture.ErrDenied) {
		t.Fatal("a member of the replaced team still manages", err)
	}
	if owned, _, _ := s.List(ctx, f, "owned", 20); len(owned) != 0 {
		t.Fatal("the replaced team still lists the share", owned)
	}
	recipient := creator
	recipient.Principal.Subject, recipient.Groups = "reader", []string{"outsiders"}
	f.i = recipient
	if got, _, _ := s.List(ctx, f, "received", 20); len(got) != 1 {
		t.Fatal("transferred share not received", got)
	}
	// The new team loses its assignment: Suspended, and the recipient loses it.
	f.dropAllow(b.AssignmentID)
	if got, _, _ := s.List(ctx, f, "received", 20); len(got) != 0 {
		t.Fatal("suspended share still received", got)
	}
	f.i = creator
	if owned, _, _ := s.List(ctx, f, "owned", 20); func() bool { p, ok := listed(owned, share.ID); return !ok || p != value.ShareSuspended }() {
		t.Fatal("transferred share not suspended after the new team lost its rights", owned)
	}
	// Nobody manages a suspended share, so nobody can transfer it back.
	f.i = mate
	if _, _, err := s.Transfer(ctx, f, to("t3", 2, "owners")); !errors.Is(err, capture.ErrDenied) {
		t.Fatal("suspended share transferred", err)
	}
}

// ADR-238: an installation administrator revokes another team's share
// without any evidence right; a non-admin non-manager is refused; an
// administrator cannot transfer.
func TestShareAdministratorRevoke(t *testing.T) {
	ctx := context.Background()
	f, s := newFixture()
	owner := f.i
	share, _, err := s.Create(ctx, f, f.input("k1"))
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := s.Create(ctx, f, f.input("k2"))
	if err != nil {
		t.Fatal(err)
	}
	admin := owner
	admin.Principal.Subject, admin.Groups = "admin", []string{"platform"}
	f.i = admin
	if _, _, err := s.Revoke(ctx, f, share.ID, 1, "r"); !errors.Is(err, capture.ErrDenied) {
		t.Fatal("revoke without a configured administration", err)
	}
	s.Administration = f.fleetOperators()
	stranger := admin
	stranger.Principal.Subject, stranger.Groups = "stranger", []string{"team"}
	f.i = stranger
	if _, _, err := s.Revoke(ctx, f, share.ID, 1, "r"); !errors.Is(err, capture.ErrDenied) {
		t.Fatal("non-admin non-manager revoked", err)
	}
	f.i = admin
	if _, _, err := s.Transfer(ctx, f, TransferInput{ShareID: share.ID, ExpectedRevision: 1, Management: value.ManagementRequest{Mode: "teams", Teams: []string{"platform"}}, IdempotencyKey: "t"}); !errors.Is(err, capture.ErrDenied) {
		t.Fatal("administrator transferred management", err)
	}
	// No projection for the target: an administrator's revocation still
	// restricts.
	f.p.Target.PodUID = "elsewhere"
	revoked, _, err := s.Revoke(ctx, f, share.ID, 1, "admin-revoke")
	if err != nil || revoked.Revision != 2 || len(f.store.revokers) != 1 || !f.store.revokers[0].Administrator || f.store.revokers[0].Actor.Subject != "admin" {
		t.Fatal("administrator revoke", err, f.store.revokers)
	}
	f.p.Target.PodUID = "pod"
	// A suspended or foreign administration grants nothing.
	ops := f.fleetOperators()
	ops.a.Suspended = true
	s.Administration = ops
	if _, _, err := s.Revoke(ctx, f, second.ID, 1, "r2"); !errors.Is(err, capture.ErrDenied) {
		t.Fatal("suspended administration revoked", err)
	}
	ops = f.fleetOperators()
	ops.a.InstallationID = testID(99)
	s.Administration = ops
	if _, _, err := s.Revoke(ctx, f, second.ID, 1, "r2"); !errors.Is(err, capture.ErrDenied) {
		t.Fatal("another installation's administration revoked", err)
	}
	// A manager's revocation is not an administrator's.
	f.i = owner
	if _, _, err := s.Revoke(ctx, f, second.ID, 1, "r3"); err != nil || f.store.revokers[1].Administrator {
		t.Fatal("creator revoke", err)
	}
}
