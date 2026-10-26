package sharing

import (
	"context"
	"errors"
	"fmt"
	"slices"
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
// administrator cannot assign a group that is not a current owner team.
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
	if _, _, err := s.Transfer(ctx, f, TransferInput{ShareID: share.ID, ExpectedRevision: 1, Management: value.ManagementRequest{Mode: "teams", Teams: []string{"platform"}}, IdempotencyKey: "t"}); !errors.Is(err, ErrManagementNotHeld) {
		t.Fatal("administrator assigned a group that is not an owner team", err)
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

// ADR-238 scoped delegation: an administrator who is also an owner may name
// current owner teams they do not belong to (inside the retained audience);
// a non-admin may not; nothing outside the audience is ever pinned.
func TestShareAdministratorAssignsManagement(t *testing.T) {
	ctx := context.Background()
	f, s := newFixture()
	c := f.addOwnerTeam("owners-c", 16) // the creator is not a member
	s.Administration = f.fleetOperators()
	in := f.input("k1")
	in.Management = value.ManagementRequest{Mode: "teams", Teams: []string{"owners-c"}}
	if _, _, err := s.Create(ctx, f, in); !errors.Is(err, ErrManagementNotHeld) {
		t.Fatal("non-admin assigned a team they do not hold", err)
	}
	f.i.Groups = append(f.i.Groups, "platform")
	share, _, err := s.Create(ctx, f, in)
	if err != nil || len(share.Management) != 1 || share.Management[0] != c {
		t.Fatal("administrator delegation at creation", err, share.Management)
	}
	// A current owner team outside the artifact's retained audience (added
	// after the capture) cannot be assigned, not even by an administrator.
	late := f.record.Audience[1]
	late.SubjectID, late.AssignmentID = "owners-late", testID(17)
	f.p.Allows = append(f.p.Allows, value.CurrentAssignment{Audience: late, ObservedAt: f.now, FreshUntil: f.now.Add(30 * time.Second)})
	in = f.input("k2")
	in.Management = value.ManagementRequest{Mode: "teams", Teams: []string{"owners-late"}}
	if _, _, err := s.Create(ctx, f, in); !errors.Is(err, ErrManagementNotHeld) {
		t.Fatal("administrator widened the artifact audience", err)
	}
	// An administrator without any owner right cannot share at all.
	admin := f.i
	admin.Principal.Subject, admin.Groups = "admin", []string{"platform"}
	f.i = admin
	in = f.input("k3")
	in.Management = value.ManagementRequest{Mode: "teams", Teams: []string{"owners-c"}}
	if _, _, err := s.Create(ctx, f, in); !errors.Is(err, capture.ErrDenied) {
		t.Fatal("administrator without owner rights created a share", err)
	}
}

// ADR-238 authority recovery: once every manager is lost the share is
// Suspended; an administrator re-pins current owner teams (new revision,
// creator and expiry unchanged) and the recipient reads again. A non-admin
// cannot; a revoked share cannot be recovered.
func TestShareAdministratorRecovery(t *testing.T) {
	ctx := context.Background()
	f, s := newFixture()
	b := f.addOwnerTeam("owners-b", 13)
	s.Administration = f.fleetOperators()
	creator := f.i
	share, _, err := s.Create(ctx, f, f.input("k1"))
	if err != nil {
		t.Fatal(err)
	}
	f.dropAllow(share.Management[0].AssignmentID)
	recipient := creator
	recipient.Principal.Subject, recipient.Groups = "reader", []string{"outsiders"}
	f.i = recipient
	if got, _, _ := s.List(ctx, f, "received", 20); len(got) != 0 {
		t.Fatal("suspended share received", got)
	}
	recover := TransferInput{ShareID: share.ID, ExpectedRevision: 1, Management: value.ManagementRequest{Mode: "teams", Teams: []string{"owners-b"}}, IdempotencyKey: "recover"}
	member := creator
	member.Principal.Subject, member.Groups = "b-member", []string{"owners-b"}
	f.i = member
	if _, _, err := s.Transfer(ctx, f, recover); !errors.Is(err, capture.ErrDenied) {
		t.Fatal("non-admin recovered a suspended share", err)
	}
	admin := creator
	admin.Principal.Subject, admin.Groups = "admin", []string{"platform"}
	f.i = admin
	reads := f.catalogReads
	if _, _, err := s.Transfer(ctx, f, TransferInput{ShareID: share.ID, ExpectedRevision: 1, Management: value.ManagementRequest{Mode: "creator"}, IdempotencyKey: "c"}); !errors.Is(err, ErrManagementNotHeld) {
		t.Fatal("administrator chose creator management", err)
	}
	recovered, _, err := s.Transfer(ctx, f, recover)
	if err != nil || recovered.Revision != 2 || len(recovered.Management) != 1 || recovered.Management[0] != b || recovered.Creator != share.Creator || !recovered.ExpiresAt.Equal(share.ExpiresAt) || f.catalogReads == reads {
		t.Fatal("administrator recovery", err, recovered)
	}
	if t2 := f.store.transfers[share.ID]; !t2.Administrator || t2.Actor.Subject != "admin" {
		t.Fatal("recovery not recorded as administrative", t2)
	}
	f.i = recipient
	if got, _, _ := s.List(ctx, f, "received", 20); len(got) != 1 {
		t.Fatal("recovered share not received", got)
	}
	f.i = member
	if owned, _, _ := s.List(ctx, f, "owned", 20); len(owned) != 1 || owned[0].Phase != value.ShareActive {
		t.Fatal("new team does not manage the recovered share", owned)
	}
	f.i = admin
	if _, _, err := s.Revoke(ctx, f, share.ID, 2, "r"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Transfer(ctx, f, TransferInput{ShareID: share.ID, ExpectedRevision: 3, Management: recover.Management, IdempotencyKey: "again"}); !errors.Is(err, capture.ErrDenied) {
		t.Fatal("revoked share recovered", err)
	}
}

// ADR-238 management-only administrator listing: administrators only,
// bounded keyset pages with a cursor, derived phases.
func TestShareAdministeredListing(t *testing.T) {
	ctx := context.Background()
	f, s := newFixture()
	var ids []string
	for n := 0; n < 5; n++ {
		share, _, err := s.Create(ctx, f, f.input(fmt.Sprint("k", n)))
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, share.ID)
		f.now = f.now.Add(time.Microsecond)
	}
	if _, _, _, err := s.ListAdministered(ctx, f, "", 2); !errors.Is(err, capture.ErrDenied) {
		t.Fatal("listing without an administration", err)
	}
	s.Administration = f.fleetOperators()
	if _, _, _, err := s.ListAdministered(ctx, f, "", 2); !errors.Is(err, capture.ErrDenied) {
		t.Fatal("non-admin listed all shares", err)
	}
	f.i.Principal.Subject, f.i.Groups = "admin", []string{"platform"}
	var seen []string
	cursor := ""
	for page := 0; page < 4; page++ {
		rows, next, until, err := s.ListAdministered(ctx, f, cursor, 2)
		if err != nil || !until.After(f.now) {
			t.Fatal(err)
		}
		for _, r := range rows {
			seen = append(seen, r.Share.ID)
			if r.Phase != value.ShareActive {
				t.Fatal("phase", r.Phase)
			}
		}
		if next == "" {
			break
		}
		cursor = next
	}
	slices.Reverse(ids)
	if !slices.Equal(seen, ids) {
		t.Fatal("pages", seen, ids)
	}
	for _, bad := range []string{"s1.x." + ids[0], "s2.1." + ids[0], "garbage"} {
		if _, _, _, err := s.ListAdministered(ctx, f, bad, 2); !errors.Is(err, capture.ErrInvalid) {
			t.Fatal("bad cursor", bad, err)
		}
	}
	if _, _, _, err := s.ListAdministered(ctx, f, "", 101); !errors.Is(err, capture.ErrInvalid) {
		t.Fatal("page above 100", err)
	}
}
