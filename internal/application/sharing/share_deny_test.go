package sharing

import (
	"context"
	"errors"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/capture"
)

// A current Deny removes a team member's management; removing it restores
// management. A stale projection is Unavailable, never a loss of management.
// Creator and administrator revocation do not consult the Deny.
func TestShareManagerDeny(t *testing.T) {
	ctx := context.Background()
	f, s := newFixture()
	s.Administration = f.administrators()
	creator := f.i
	share, _, err := s.Create(ctx, f, f.input("k1"))
	if err != nil {
		t.Fatal(err)
	}
	mate := creator
	mate.Principal.Subject = "mate"
	deny := f.p.Allows[1]
	deny.Audience.Kind, deny.Audience.SubjectID, deny.Audience.AssignmentID = "User", "mate", testID(70)

	f.i = mate
	if owned, _, _, err := s.List(ctx, f, "owned", "", 20); err != nil || len(owned) != 1 {
		t.Fatal("team member does not list the share", err, owned)
	}
	f.p.Denies = []value.CurrentAssignment{deny}
	if denied, current := value.ManagerDenied(f.p, f.p.Target, mate, f.now); !denied || !current {
		t.Fatal("ManagerDenied", denied, current)
	}
	if owned, _, _, err := s.List(ctx, f, "owned", "", 20); err != nil || len(owned) != 0 {
		t.Fatal("denied member lists the share", err, owned)
	}
	if _, _, err := s.Revoke(ctx, f, RevokeInput{OperationID: testID(900), ShareID: share.ID, ExpectedRevision: 1, IdempotencyKey: "denied"}); !errors.Is(err, capture.ErrDenied) {
		t.Fatal("denied member revoked", err)
	}
	f.p.Denies = nil
	if owned, _, _, err := s.List(ctx, f, "owned", "", 20); err != nil || len(owned) != 1 {
		t.Fatal("management not restored after the Deny was removed", err, owned)
	}

	// A stale projection is Unavailable for listing, transfer and revocation.
	stale := f.p
	f.p.FreshUntil = f.now.Add(-time.Second)
	if _, current := value.ManagerDenied(f.p, f.p.Target, mate, f.now); current {
		t.Fatal("stale projection reported current")
	}
	if _, _, _, err := s.List(ctx, f, "owned", "", 20); !errors.Is(err, capture.ErrUnavailable) {
		t.Fatal("stale projection hid or listed team shares", err)
	}
	if _, _, err := s.Revoke(ctx, f, RevokeInput{OperationID: testID(900), ShareID: share.ID, ExpectedRevision: 1, IdempotencyKey: "stale"}); !errors.Is(err, capture.ErrUnavailable) {
		t.Fatal("stale projection revoke", err)
	}
	f.p = stale

	// The creator revokes under a Deny of their own management.
	creatorDeny := deny
	creatorDeny.Audience.SubjectID = creator.Principal.Subject
	f.p.Denies = []value.CurrentAssignment{creatorDeny}
	f.i = creator
	if revoked, _, err := s.Revoke(ctx, f, RevokeInput{OperationID: testID(900), ShareID: share.ID, ExpectedRevision: 1, IdempotencyKey: "creator"}); err != nil || revoked.RevokedAt.IsZero() {
		t.Fatal("creator revocation under a Deny", err)
	}

	// An administrator revokes a share whose manager is denied.
	f.p.Denies = nil
	second, _, err := s.Create(ctx, f, f.input("k2"))
	if err != nil {
		t.Fatal(err)
	}
	admin := creator
	admin.Principal.Subject, admin.Groups = "admin", []string{"platform", "owners"}
	adminDeny := deny
	adminDeny.Audience.SubjectID = "admin"
	f.p.Denies = []value.CurrentAssignment{adminDeny}
	f.i = admin
	if revoked, _, err := s.Revoke(ctx, f, RevokeInput{OperationID: testID(901), ShareID: second.ID, ExpectedRevision: 1, IdempotencyKey: "admin"}); err != nil || revoked.RevokedAt.IsZero() || !f.store.revokers[len(f.store.revokers)-1].Administrator {
		t.Fatal("administrator revocation under a Deny", err)
	}
}
