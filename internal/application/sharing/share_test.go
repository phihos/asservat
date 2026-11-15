package sharing

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	capture "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/catalog"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
)

func testID(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }

// fixture is one published artifact on one target: team "owners" holds
// evidence-owner, team "team" evidence-reader; both are in the retained
// audience. It implements every port the service reads.
type fixture struct {
	now          time.Time
	i            identity.Identity
	p            value.Projection
	record       authapp.ContextDownloadEvidence
	route        catalog.ContextCaseRoute
	caseID       string
	catalogReads int
	store        *memoryStore
}

func (f *fixture) ResolveIdentity(context.Context) (identity.Identity, error) { return f.i, nil }
func (f *fixture) Permissions(_ context.Context, t value.Target) (value.Projection, error) {
	if t != f.p.Target {
		return value.Projection{}, errors.New("unknown target")
	}
	return f.p, nil
}
func (f *fixture) ContextDownloadEvidence(_ context.Context, id string) (authapp.ContextDownloadEvidence, error) {
	f.catalogReads++
	if id != f.route.ArtifactID {
		return authapp.ContextDownloadEvidence{}, errors.New("unknown artifact")
	}
	return f.record, nil
}
func (f *fixture) ResolveContextCase(_ context.Context, q catalog.CaseRouteQuery) (catalog.ContextCaseRoutes, error) {
	if q.CaseID != f.caseID {
		return catalog.ContextCaseRoutes{}, errors.New("unknown case")
	}
	return catalog.ContextCaseRoutes{CaseID: f.caseID, Routes: []catalog.ContextCaseRoute{f.route}, ObservedAt: f.now, ValidUntil: f.now.Add(5 * time.Second)}, nil
}

// memoryStore is an in-memory share ledger with the SQL adapter's replay,
// conflict and creator-or-pinned-manager revocation rules.
type memoryStore struct {
	now       func() time.Time
	rows      []value.Share
	created   []Request
	revokers  []Revocation
	transfers map[string]Transfer
}

func (s *memoryStore) stamp(v value.Share) value.Share {
	v.ObservedAt, v.ValidUntil = s.now(), s.now().Add(5*time.Second)
	return v
}
func (s *memoryStore) RecipientShares(_ context.Context, artifactID string, caller identity.Identity) ([]value.Share, error) {
	keys := value.RecipientKeys(caller)
	var out []value.Share
	for _, r := range s.rows {
		match := false
		for _, x := range r.Recipients {
			match = match || slices.Contains(keys, x.Key())
		}
		if r.ArtifactID == artifactID && r.RevokedAt.IsZero() && s.now().Before(r.ExpiresAt) && match {
			out = append(out, s.stamp(r))
		}
	}
	return out, nil
}
func (s *memoryStore) CreateShare(_ context.Context, r Request) (value.Share, bool, error) {
	for _, c := range s.created {
		if c.IdempotencyKey == r.IdempotencyKey {
			if c.RequestDigest != r.RequestDigest {
				return value.Share{}, false, capture.ErrConflict
			}
			return s.stamp(c.Share), true, nil
		}
	}
	r.Share.CreatedAt = s.now()
	s.created = append(s.created, r)
	s.rows = append(s.rows, r.Share)
	return s.stamp(r.Share), false, nil
}
func (s *memoryStore) Share(_ context.Context, id string) (value.Share, error) {
	for _, r := range s.rows {
		if r.ID == id {
			return s.stamp(r), nil
		}
	}
	return value.Share{}, capture.ErrDenied
}

// OwnedShares mirrors the SQL candidates: created rows, plus unrevoked,
// unexpired rows pinning one of the caller's user/group subjects.
func (s *memoryStore) OwnedShares(_ context.Context, caller identity.Identity, _ ShareCursor, _ int) ([]value.Share, error) {
	var out []value.Share
	for _, r := range s.rows {
		pinned := false
		for _, a := range r.Management {
			pinned = pinned || a.Issuer == caller.Principal.Issuer && (a.Kind == "User" && a.SubjectID == caller.Principal.Subject || a.Kind == "Group" && slices.Contains(caller.Groups, a.SubjectID))
		}
		if r.Creator.Subject == caller.Principal.Subject || pinned && r.RevokedAt.IsZero() && s.now().Before(r.ExpiresAt) {
			out = append(out, s.stamp(r))
		}
	}
	return out, nil
}
func (s *memoryStore) ReceivedShares(ctx context.Context, caller identity.Identity, _ ShareCursor, _ int) ([]value.Share, error) {
	out := []value.Share{}
	for _, r := range s.rows {
		rows, _ := s.RecipientShares(ctx, r.ArtifactID, caller)
		for _, x := range rows {
			if x.ID == r.ID {
				out = append(out, x)
			}
		}
	}
	return out, nil
}
func (s *memoryStore) RevokeShare(_ context.Context, r Revocation) (value.Share, bool, error) {
	for i := range s.rows {
		pinned := len(r.Managers) > 0
		for _, id := range r.Managers {
			pinned = pinned && slices.ContainsFunc(s.rows[i].Management, func(a artifact.AudienceAssignment) bool { return a.AssignmentID == id })
		}
		if s.rows[i].ID == r.ShareID && (r.Administrator || s.rows[i].Creator.Subject == r.Actor.Subject || pinned) {
			if !s.rows[i].RevokedAt.IsZero() {
				return s.stamp(s.rows[i]), true, nil
			}
			if s.rows[i].Revision != r.ExpectedRevision {
				return value.Share{}, false, capture.ErrConflict
			}
			s.rows[i].RevokedAt, s.rows[i].Revision = s.now(), s.rows[i].Revision+1
			s.revokers = append(s.revokers, r)
			return s.stamp(s.rows[i]), false, nil
		}
	}
	return value.Share{}, false, capture.ErrDenied
}

// AdministeredShares mirrors the SQL keyset page: newest first, strictly
// after the cursor.
func (s *memoryStore) AdministeredShares(_ context.Context, after ShareCursor, limit int) ([]value.Share, error) {
	rows := slices.Clone(s.rows)
	slices.SortFunc(rows, func(a, b value.Share) int {
		if c := b.CreatedAt.Compare(a.CreatedAt); c != 0 {
			return c
		}
		return strings.Compare(b.ID, a.ID)
	})
	var out []value.Share
	for _, r := range rows {
		if after != (ShareCursor{}) && (r.CreatedAt.After(after.CreatedAt) || r.CreatedAt.Equal(after.CreatedAt) && r.ID >= after.ID) {
			continue
		}
		if len(out) < limit {
			out = append(out, s.stamp(r))
		}
	}
	return out, nil
}

// TransferShare mirrors the SQL adapter: pinned current managers only, the
// latest transfer key replays, a stale revision conflicts.
func (s *memoryStore) TransferShare(_ context.Context, t Transfer) (value.Share, bool, error) {
	for i := range s.rows {
		if s.rows[i].ID != t.ShareID {
			continue
		}
		pinned := len(t.Managers) > 0
		for _, id := range t.Managers {
			pinned = pinned && slices.ContainsFunc(s.rows[i].Management, func(a artifact.AudienceAssignment) bool { return a.AssignmentID == id })
		}
		switch {
		case !pinned && !t.Administrator:
			return value.Share{}, false, capture.ErrDenied
		case s.transfers[t.ShareID].IdempotencyKey == t.IdempotencyKey:
			if s.transfers[t.ShareID].RequestDigest != t.RequestDigest {
				return value.Share{}, false, capture.ErrConflict
			}
			return s.stamp(s.rows[i]), true, nil
		case !s.rows[i].RevokedAt.IsZero() || s.rows[i].Revision != t.ExpectedRevision:
			return value.Share{}, false, capture.ErrConflict
		}
		s.rows[i].Management, s.rows[i].Revision = slices.Clone(t.Management), s.rows[i].Revision+1
		if s.transfers == nil {
			s.transfers = map[string]Transfer{}
		}
		s.transfers[t.ShareID] = t
		return s.stamp(s.rows[i]), false, nil
	}
	return value.Share{}, false, capture.ErrDenied
}

func newFixture() (*fixture, Service) {
	n := time.Now().UTC().Truncate(time.Microsecond)
	rev := identity.Revision{UID: testID(20), Generation: 1, Digest: artifact.Digest{1}}
	issuer := "https://issuer.invalid"
	target := value.Target{ClusterID: testID(2), NamespaceUID: "namespace", WorkloadUID: "workload", PodUID: "pod"}
	reader := artifact.AudienceAssignment{Kind: "Group", Issuer: issuer, SubjectID: "team", Role: "evidence-reader", BasisKind: "AccessBinding", BasisUID: "binding", BasisDigest: artifact.Digest{2}, AssignmentID: testID(11)}
	owner := reader
	owner.SubjectID, owner.Role, owner.AssignmentID = "owners", "evidence-owner", testID(12)
	reg := artifact.Registration{Location: artifact.Location{ClusterID: target.ClusterID, ArtifactID: testID(5), AttemptID: testID(6)}, StoreID: testID(7), AllocationID: testID(8), PoolRevision: 1, AllocationRevision: 1, NativeLimit: 4096, AnchorAt: n.Add(-time.Minute), WriteUntil: n.Add(-time.Second), ExpiresAt: n.Add(time.Hour), DeleteBy: n.Add(2 * time.Hour)}
	dates := privacy.Deadlines{AnchorAt: reg.AnchorAt, ExpiresAt: reg.ExpiresAt, DeleteBy: reg.DeleteBy}
	f := &fixture{now: n, caseID: testID(9),
		i: identity.Identity{Principal: identity.Principal{Issuer: issuer, Subject: "owner", ClientID: "mcp", Kind: identity.Human}, Scopes: []string{"evidence:read", value.ShareScope}, Groups: []string{"owners"}, Policy: rev, VerifiedAt: n, ValidUntil: n.Add(30 * time.Second)},
		p: value.Projection{Target: target, Revision: rev, ObservedAt: n, FreshUntil: n.Add(30 * time.Second), DeniesComplete: true, DeniesObservedAt: n, DeniesFreshUntil: n.Add(5 * time.Second),
			Allows: []value.CurrentAssignment{{Audience: reader, ObservedAt: n, FreshUntil: n.Add(30 * time.Second)}, {Audience: owner, ObservedAt: n, FreshUntil: n.Add(30 * time.Second)}}},
		record: authapp.ContextDownloadEvidence{PurposeRef: "diagnostics", DataClass: "metadata", CaptureID: testID(4), Version: artifact.Digest{3}, Audience: []artifact.AudienceAssignment{reader, owner},
			Retained:   privacy.RetainedArtifact{RootID: testID(1), Registration: reg, Input: privacy.Input{Target: target, PrivacyClass: "potentialPersonalData", EvidenceType: "context", RequestedSeconds: 3600, AnchorAt: reg.AnchorAt}, OriginPolicies: []artifact.RetentionRule{{UID: "baseline", Generation: 1, Digest: artifact.Digest{5}}}, Effective: dates},
			ObservedAt: n, ValidUntil: n.Add(5 * time.Second)},
		route: catalog.ContextCaseRoute{CaptureID: testID(4), ArtifactID: testID(5), Target: target}}
	f.store = &memoryStore{now: func() time.Time { return f.now }}
	next := 50
	return f, Service{RootID: testID(1), InstallationID: testID(3), Routes: f, Permissions: f, Catalog: f, Store: f.store,
		NewID: func() string { next++; return testID(next) }, Now: func() time.Time { return f.now }}
}

func (f *fixture) input(key string) CreateInput {
	return CreateInput{OperationID: testID(900), CaseID: f.caseID, ArtifactID: f.route.ArtifactID, Version: f.record.Version, Recipients: []value.ShareRecipient{{Kind: "Group", Issuer: f.i.Principal.Issuer, ID: "outsiders"}}, ExpiresAt: f.now.Add(48 * time.Hour), Reason: "incident review", IdempotencyKey: key}
}

func TestShareCreateListRevoke(t *testing.T) {
	f, s := newFixture()
	created, replay, err := s.Create(context.Background(), f, f.input("k1"))
	if err != nil || replay || len(created.Management) != 1 || created.Management[0].Role != "evidence-owner" || created.Creator.Subject != "owner" {
		t.Fatalf("create: %v %+v", err, created)
	}
	// The share never outlives the artifact's effective access deadline.
	if !created.ExpiresAt.Equal(f.record.Retained.Effective.ExpiresAt) {
		t.Fatal("share outlives artifact retention", created.ExpiresAt)
	}
	if again, replay, err := s.Create(context.Background(), f, f.input("k1")); err != nil || !replay || again.ID != created.ID {
		t.Fatal("idempotent replay", err, replay)
	}
	changed := f.input("k1")
	changed.Reason = "another reason"
	if _, _, err := s.Create(context.Background(), f, changed); !errors.Is(err, capture.ErrConflict) {
		t.Fatal("changed request under the same key", err)
	}
	owned, _, _, err := s.List(context.Background(), f, "owned", "", 20)
	if err != nil || len(owned) != 1 || owned[0].Phase != value.ShareActive {
		t.Fatal("owned list", err, owned)
	}
	if _, _, err := s.Revoke(context.Background(), f, RevokeInput{OperationID: testID(900), ShareID: created.ID, ExpectedRevision: 1, IdempotencyKey: "r1"}); err != nil {
		t.Fatal("revoke", err)
	}
	if _, replay, err := s.Revoke(context.Background(), f, RevokeInput{OperationID: testID(900), ShareID: created.ID, ExpectedRevision: 1, IdempotencyKey: "r1"}); err != nil || !replay {
		t.Fatal("revoke replay", err, replay)
	}
	owned, _, _, _ = s.List(context.Background(), f, "owned", "", 20)
	if len(owned) != 1 || owned[0].Phase != value.ShareRevoked {
		t.Fatal("revoked phase", owned)
	}
	// Loss of the recorded owner assignment does not change a share (ADR-330 D11).
	second, _, err := s.Create(context.Background(), f, f.input("k2"))
	if err != nil {
		t.Fatal(err)
	}
	f.p.Allows = f.p.Allows[:1]
	owned, _, _, _ = s.List(context.Background(), f, "owned", "", 20)
	for _, v := range owned {
		if v.Share.ID == second.ID && v.Phase != value.ShareActive {
			t.Fatal("owner loss changed the share", v.Phase)
		}
	}
}

func TestShareCreateRefusals(t *testing.T) {
	for _, name := range []string{"no-share-scope", "not-owner", "foreign-recipient-issuer", "past-expiry", "changed-version", "unrelated-caller", "workload-caller", "raw-artifact"} {
		t.Run(name, func(t *testing.T) {
			f, s := newFixture()
			in := f.input("k")
			want := capture.ErrDenied
			switch name {
			case "no-share-scope":
				f.i.Scopes = []string{"evidence:read"}
			case "not-owner":
				f.i.Groups = []string{"team"}
			case "foreign-recipient-issuer":
				in.Recipients[0].Issuer, want = "https://other.invalid", capture.ErrInvalid
			case "past-expiry":
				in.ExpiresAt, want = f.now.Add(-time.Second), capture.ErrInvalid
			case "changed-version":
				in.Version, want = artifact.Digest{99}, capture.ErrChanged
			case "unrelated-caller":
				f.i.Groups = nil
			case "workload-caller":
				f.i.Principal.Kind = identity.Workload
			case "raw-artifact":
				// ADR-279: raw output is never shared before S-06 raw-share approval.
				f.record.DataClass = "raw"
			}
			if _, _, err := s.Create(context.Background(), f, in); !errors.Is(err, want) || len(f.store.created) != 0 {
				t.Fatalf("refusal %s: %v (want %v)", name, err, want)
			}
			// No evidence lookup without current ordinary target eligibility.
			if name == "unrelated-caller" && f.catalogReads != 0 {
				t.Fatal("catalog read without ordinary target eligibility")
			}
		})
	}
}

func TestShareReceivedListsOnlyReadableShares(t *testing.T) {
	f, s := newFixture()
	if _, _, err := s.Create(context.Background(), f, f.input("k1")); err != nil {
		t.Fatal(err)
	}
	other := f.input("k2")
	other.Recipients = []value.ShareRecipient{{Kind: "User", Issuer: f.i.Principal.Issuer, ID: "stranger"}}
	if _, _, err := s.Create(context.Background(), f, other); err != nil {
		t.Fatal(err)
	}
	f.i.Principal.Subject, f.i.Groups, f.i.Scopes = "outsider", []string{"outsiders"}, []string{"evidence:read"}
	got, _, _, err := s.List(context.Background(), f, "received", "", 20)
	if err != nil || len(got) != 1 || got[0].Phase != value.ShareActive {
		t.Fatal("received list", err, got)
	}
	// A current deny of the recipient hides it.
	d := f.p.Allows[0]
	d.Audience.Kind, d.Audience.SubjectID, d.Audience.AssignmentID = "User", "outsider", testID(62)
	f.p.Denies = []value.CurrentAssignment{d}
	if got, _, _, err := s.List(context.Background(), f, "received", "", 20); err != nil || len(got) != 0 {
		t.Fatal("denied recipient listed a share", err, got)
	}
	// Without evidence:share the owned view is refused.
	if _, _, _, err := s.List(context.Background(), f, "owned", "", 20); !errors.Is(err, capture.ErrDenied) {
		t.Fatal("owned list without evidence:share", err)
	}
}

func TestShareOwnedListSurvivesUnavailableProjection(t *testing.T) {
	f, s := newFixture()
	revoked, _, err := s.Create(context.Background(), f, f.input("k1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Revoke(context.Background(), f, RevokeInput{OperationID: testID(900), ShareID: revoked.ID, ExpectedRevision: 1, IdempotencyKey: "r1"}); err != nil {
		t.Fatal(err)
	}
	active, _, err := s.Create(context.Background(), f, f.input("k2"))
	if err != nil {
		t.Fatal(err)
	}
	// The target's projection becomes unavailable: the owned list needs none.
	f.p.Target.WorkloadUID = "gone"
	owned, _, _, err := s.List(context.Background(), f, "owned", "", 20)
	if err != nil || len(owned) != 2 {
		t.Fatal("owned list failed on an unavailable projection", err, owned)
	}
	for _, v := range owned {
		if want := map[string]value.SharePhase{revoked.ID: value.ShareRevoked, active.ID: value.ShareActive}[v.Share.ID]; v.Phase != want {
			t.Fatal("phase", v.Share.ID, v.Phase, want)
		}
	}
}

func TestShareReceivedListTrimsAfterFiltering(t *testing.T) {
	f, s := newFixture()
	for _, k := range []string{"k1", "k2"} {
		if _, _, err := s.Create(context.Background(), f, f.input(k)); err != nil {
			t.Fatal(err)
		}
	}
	f.i.Principal.Subject, f.i.Groups, f.i.Scopes = "outsider", []string{"outsiders"}, []string{"evidence:read"}
	if got, _, _, err := s.List(context.Background(), f, "received", "", 1); err != nil || len(got) != 1 {
		t.Fatal("received page", err, got)
	}
}

// addOwnerTeam adds a current evidence-owner Group assignment that is also in
// the retained audience (an owner team at capture time).
func (f *fixture) addOwnerTeam(group string, n int) artifact.AudienceAssignment {
	a := f.record.Audience[1]
	a.SubjectID, a.AssignmentID = group, testID(n)
	f.p.Allows = append(f.p.Allows, value.CurrentAssignment{Audience: a, ObservedAt: f.now, FreshUntil: f.now.Add(30 * time.Second)})
	f.record.Audience = append(f.record.Audience, a)
	return a
}

func (f *fixture) dropAllow(assignmentID string) {
	f.p.Allows = slices.DeleteFunc(f.p.Allows, func(a value.CurrentAssignment) bool { return a.Audience.AssignmentID == assignmentID })
}

func listed(views []View, id string) (value.SharePhase, bool) {
	for _, v := range views {
		if v.Share.ID == id {
			return v.Phase, true
		}
	}
	return "", false
}

// Management is the creator's owner teams; any current member manages; the
// creator's departure keeps the share.
func TestShareTeamManagement(t *testing.T) {
	ctx := context.Background()
	f, s := newFixture()
	f.addOwnerTeam("owners-b", 13)
	creator := f.i
	creator.Groups = []string{"owners", "owners-b"}
	f.i = creator
	share, _, err := s.Create(ctx, f, f.input("k1"))
	if err != nil || len(share.Management) != 2 || share.Management[0].Kind != "Group" || share.Management[1].Kind != "Group" {
		t.Fatal("create with two owner teams", err, share.Management)
	}
	mate := creator
	mate.Principal.Subject, mate.Groups = "mate", []string{"owners"}
	// A team member who did not create the share manages it.
	f.i = mate
	if owned, _, _, err := s.List(ctx, f, "owned", "", 20); err != nil {
		t.Fatal(err)
	} else if phase, ok := listed(owned, share.ID); !ok || phase != value.ShareActive {
		t.Fatal("team member does not see the managed share", owned)
	}
	// The creator leaves both teams: the share stays Active, still listed
	// for the creator (created) and the member revokes it.
	f.i = creator
	f.i.Groups = nil
	if owned, _, _, _ := s.List(ctx, f, "owned", "", 20); len(owned) != 1 || owned[0].Phase != value.ShareActive {
		t.Fatal("creator departure changed the share", owned)
	}
	f.i = mate
	if revoked, _, err := s.Revoke(ctx, f, RevokeInput{OperationID: testID(900), ShareID: share.ID, ExpectedRevision: 1, IdempotencyKey: "r-mate"}); err != nil || revoked.Revision != 2 {
		t.Fatal("team member could not revoke", err)
	}
	// A revoked team share leaves the member's (not the creator's) view.
	if owned, _, _, _ := s.List(ctx, f, "owned", "", 20); len(owned) != 0 {
		t.Fatal("revoked team share still listed for the member", owned)
	}

}

func TestShareManagementPersonalTeamsAndDeny(t *testing.T) {
	ctx := context.Background()
	// Individually assigned only: creator-only management.
	f, s := newFixture()
	personal := f.record.Audience[1]
	personal.Kind, personal.SubjectID, personal.AssignmentID = "User", "owner", testID(15)
	f.p.Allows = []value.CurrentAssignment{f.p.Allows[0], {Audience: personal, ObservedAt: f.now, FreshUntil: f.now.Add(30 * time.Second)}}
	f.record.Audience = []artifact.AudienceAssignment{f.record.Audience[0], personal}
	share, _, err := s.Create(ctx, f, f.input("k1"))
	if err != nil || len(share.Management) != 1 || share.Management[0].Kind != "User" {
		t.Fatal("individual owner", err, share.Management)
	}
	other := f.i
	other.Principal.Subject = "someone-else"
	f.i = other
	if _, _, err := s.Revoke(ctx, f, RevokeInput{OperationID: testID(900), ShareID: share.ID, ExpectedRevision: 1, IdempotencyKey: "r"}); !errors.Is(err, capture.ErrDenied) {
		t.Fatal("another user managed a personal share", err)
	}

	// Team and individual owner: the teams manage (not the personal row).
	f, s = newFixture()
	personal.SubjectID = f.i.Principal.Subject
	f.p.Allows = append(f.p.Allows, value.CurrentAssignment{Audience: personal, ObservedAt: f.now, FreshUntil: f.now.Add(30 * time.Second)})
	f.record.Audience = append(f.record.Audience, personal)
	share, _, err = s.Create(ctx, f, f.input("k1"))
	if err != nil || len(share.Management) != 1 || share.Management[0].Kind != "Group" {
		t.Fatal("team management not preferred", err, share.Management)
	}
	mate := f.i
	mate.Principal.Subject = "mate"
	f.i = mate
	if _, _, err := s.Revoke(ctx, f, RevokeInput{OperationID: testID(900), ShareID: share.ID, ExpectedRevision: 1, IdempotencyKey: "r"}); err != nil {
		t.Fatal("member revoke", err)
	}
}
