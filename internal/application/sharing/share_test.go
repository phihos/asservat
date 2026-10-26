package sharing

import (
	"context"
	"errors"
	"fmt"
	"slices"
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
	recovery     artifact.RecoveryProof
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
func (f *fixture) RecoveryState(context.Context) (artifact.RecoveryProof, error) {
	return f.recovery, nil
}

// memoryStore is an in-memory share ledger with the SQL adapter's replay,
// conflict and creator-or-pinned-manager revocation rules.
type memoryStore struct {
	now     func() time.Time
	rows    []value.Share
	created []Request
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
func (s *memoryStore) CreateShare(_ context.Context, r Request, _ artifact.RecoveryProof) (value.Share, bool, error) {
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
func (s *memoryStore) OwnedShares(_ context.Context, caller identity.Identity, _ int) ([]value.Share, error) {
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
func (s *memoryStore) ReceivedShares(ctx context.Context, caller identity.Identity, _ int) ([]value.Share, error) {
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
func (s *memoryStore) RevokeShare(_ context.Context, r Revocation, _ artifact.RecoveryProof) (value.Share, bool, error) {
	for i := range s.rows {
		pinned := len(r.Managers) > 0
		for _, id := range r.Managers {
			pinned = pinned && slices.ContainsFunc(s.rows[i].Management, func(a artifact.AudienceAssignment) bool { return a.AssignmentID == id })
		}
		if s.rows[i].ID == r.ShareID && (s.rows[i].Creator.Subject == r.Actor.Subject || pinned) {
			if !s.rows[i].RevokedAt.IsZero() {
				return s.stamp(s.rows[i]), true, nil
			}
			if s.rows[i].Revision != r.ExpectedRevision {
				return value.Share{}, false, capture.ErrConflict
			}
			s.rows[i].RevokedAt, s.rows[i].Revision = s.now(), 2
			return s.stamp(s.rows[i]), false, nil
		}
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
		record: authapp.ContextDownloadEvidence{PurposeRef: "diagnostics", CaptureID: testID(4), Version: artifact.Digest{3}, Audience: []artifact.AudienceAssignment{reader, owner},
			Retained:   privacy.RetainedArtifact{RootID: testID(1), Registration: reg, Input: privacy.Input{Target: target, PrivacyClass: "potentialPersonalData", EvidenceType: "context", RequestedSeconds: 3600, AnchorAt: reg.AnchorAt}, OriginPolicies: []artifact.RetentionRule{{UID: "baseline", Generation: 1, Digest: artifact.Digest{5}}}, Effective: dates},
			ObservedAt: n, ValidUntil: n.Add(5 * time.Second)},
		route:    catalog.ContextCaseRoute{CaptureID: testID(4), ArtifactID: testID(5), Target: target},
		recovery: artifact.RecoveryProof{InstallationID: testID(3), IssuerEpoch: testID(22), Revision: rev, ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}}
	f.store = &memoryStore{now: func() time.Time { return f.now }}
	next := 50
	return f, Service{RootID: testID(1), InstallationID: testID(3), Routes: f, Permissions: f, Catalog: f, Store: f.store, Recovery: f,
		NewID: func() string { next++; return testID(next) }, Now: func() time.Time { return f.now }}
}

func (f *fixture) input(key string) CreateInput {
	return CreateInput{CaseID: f.caseID, ArtifactID: f.route.ArtifactID, Version: f.record.Version, Recipients: []value.ShareRecipient{{Kind: "Group", Issuer: f.i.Principal.Issuer, ID: "outsiders"}}, ExpiresAt: f.now.Add(48 * time.Hour), Reason: "incident review", IdempotencyKey: key}
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
	owned, _, err := s.List(context.Background(), f, "owned", 20)
	if err != nil || len(owned) != 1 || owned[0].Phase != value.ShareActive {
		t.Fatal("owned list", err, owned)
	}
	if _, _, err := s.Revoke(context.Background(), f, created.ID, 1, "r1"); err != nil {
		t.Fatal("revoke", err)
	}
	if _, replay, err := s.Revoke(context.Background(), f, created.ID, 1, "r1"); err != nil || !replay {
		t.Fatal("revoke replay", err, replay)
	}
	owned, _, _ = s.List(context.Background(), f, "owned", 20)
	if len(owned) != 1 || owned[0].Phase != value.ShareRevoked {
		t.Fatal("revoked phase", owned)
	}
	// Loss of the pinned owner assignment suspends a share in the owned view.
	second, _, err := s.Create(context.Background(), f, f.input("k2"))
	if err != nil {
		t.Fatal(err)
	}
	f.p.Allows = f.p.Allows[:1]
	owned, _, _ = s.List(context.Background(), f, "owned", 20)
	for _, v := range owned {
		if v.Share.ID == second.ID && v.Phase != value.ShareSuspended {
			t.Fatal("owner loss did not suspend", v.Phase)
		}
	}
}

func TestShareCreateRefusals(t *testing.T) {
	for _, name := range []string{"no-share-scope", "not-owner", "foreign-recipient-issuer", "too-long", "changed-version", "unrelated-caller", "too-many-recipients", "workload-caller"} {
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
			case "too-long":
				in.ExpiresAt, want = f.now.Add(value.ShareMaxLifetime+time.Second), capture.ErrInvalid
			case "changed-version":
				in.Version, want = artifact.Digest{99}, capture.ErrChanged
			case "unrelated-caller":
				f.i.Groups = nil
			case "too-many-recipients":
				for len(in.Recipients) <= value.ShareMaxRecipients {
					in.Recipients = append(in.Recipients, value.ShareRecipient{Kind: "Group", Issuer: f.i.Principal.Issuer, ID: string(rune('a' + len(in.Recipients)))})
				}
				want = capture.ErrInvalid
			case "workload-caller":
				f.i.Principal.Kind = identity.Workload
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
	got, _, err := s.List(context.Background(), f, "received", 20)
	if err != nil || len(got) != 1 || got[0].Phase != value.ShareActive {
		t.Fatal("received list", err, got)
	}
	// A current deny of the recipient hides it.
	d := f.p.Allows[0]
	d.Audience.Kind, d.Audience.SubjectID, d.Audience.AssignmentID = "User", "outsider", testID(62)
	f.p.Denies = []value.CurrentAssignment{d}
	if got, _, err := s.List(context.Background(), f, "received", 20); err != nil || len(got) != 0 {
		t.Fatal("denied recipient listed a share", err, got)
	}
	// Without evidence:share the owned view is refused.
	if _, _, err := s.List(context.Background(), f, "owned", 20); !errors.Is(err, capture.ErrDenied) {
		t.Fatal("owned list without evidence:share", err)
	}
}

func TestShareOwnedListSurvivesUnavailableProjection(t *testing.T) {
	f, s := newFixture()
	revoked, _, err := s.Create(context.Background(), f, f.input("k1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Revoke(context.Background(), f, revoked.ID, 1, "r1"); err != nil {
		t.Fatal(err)
	}
	active, _, err := s.Create(context.Background(), f, f.input("k2"))
	if err != nil {
		t.Fatal(err)
	}
	// The target's projection becomes unavailable: the list still answers,
	// the revoked row keeps its final phase and the other shows Suspended.
	f.p.Target.WorkloadUID = "gone"
	owned, _, err := s.List(context.Background(), f, "owned", 20)
	if err != nil || len(owned) != 2 {
		t.Fatal("owned list failed on an unavailable projection", err, owned)
	}
	for _, v := range owned {
		if want := map[string]value.SharePhase{revoked.ID: value.ShareRevoked, active.ID: value.ShareSuspended}[v.Share.ID]; v.Phase != want {
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
	if got, _, err := s.List(context.Background(), f, "received", 1); err != nil || len(got) != 1 {
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

// ADR-232 increment 4: management is the creator's owner teams; any current
// member manages; the creator's departure keeps the share; losing every team
// suspends it; a newly added owner assignment manages no older share.
func TestShareTeamManagement(t *testing.T) {
	ctx := context.Background()
	f, s := newFixture()
	teamB := f.addOwnerTeam("owners-b", 13)
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
	if owned, _, err := s.List(ctx, f, "owned", 20); err != nil {
		t.Fatal(err)
	} else if phase, ok := listed(owned, share.ID); !ok || phase != value.ShareActive {
		t.Fatal("team member does not see the managed share", owned)
	}
	// The creator leaves both teams: the share stays Active, still listed
	// for the creator (created) and the member revokes it.
	f.i = creator
	f.i.Groups = nil
	if owned, _, _ := s.List(ctx, f, "owned", 20); len(owned) != 1 || owned[0].Phase != value.ShareActive {
		t.Fatal("creator departure changed the share", owned)
	}
	f.i = mate
	if revoked, _, err := s.Revoke(ctx, f, share.ID, 1, "r-mate"); err != nil || revoked.Revision != 2 {
		t.Fatal("team member could not revoke", err)
	}
	// A revoked team share leaves the member's (not the creator's) view.
	if owned, _, _ := s.List(ctx, f, "owned", 20); len(owned) != 0 {
		t.Fatal("revoked team share still listed for the member", owned)
	}

	f.i = creator
	second, _, err := s.Create(ctx, f, f.input("k2"))
	if err != nil {
		t.Fatal(err)
	}
	// Team "owners" loses its assignment: its member no longer manages, the
	// share stays Active through owners-b.
	owners := f.p.Allows[1].Audience
	f.dropAllow(owners.AssignmentID)
	f.i = mate
	if _, _, err := s.Revoke(ctx, f, second.ID, 1, "r-lost"); !errors.Is(err, capture.ErrDenied) {
		t.Fatal("member of a team without a current assignment revoked", err)
	}
	if owned, _, _ := s.List(ctx, f, "owned", 20); len(owned) != 0 {
		t.Fatal("member of a lost team lists the share", owned)
	}
	f.i = creator
	if owned, _, _ := s.List(ctx, f, "owned", 20); func() bool { p, ok := listed(owned, second.ID); return !ok || p != value.ShareActive }() {
		t.Fatal("share with one remaining team not Active", owned)
	}
	// Both teams lost: Suspended.
	f.dropAllow(teamB.AssignmentID)
	if owned, _, _ := s.List(ctx, f, "owned", 20); func() bool { p, ok := listed(owned, second.ID); return !ok || p != value.ShareSuspended }() {
		t.Fatal("share without a current team not Suspended", owned)
	}
	// Re-granting "owners" is a new assignment ID: no restoration, and its
	// members cannot manage the old share.
	regranted := owners
	regranted.AssignmentID = testID(14)
	f.p.Allows = append(f.p.Allows, value.CurrentAssignment{Audience: regranted, ObservedAt: f.now, FreshUntil: f.now.Add(30 * time.Second)})
	if owned, _, _ := s.List(ctx, f, "owned", 20); func() bool { p, ok := listed(owned, second.ID); return !ok || p != value.ShareSuspended }() {
		t.Fatal("re-granted owner binding restored a suspended share", owned)
	}
	f.i = mate
	if _, _, err := s.Revoke(ctx, f, second.ID, 1, "r-new"); !errors.Is(err, capture.ErrDenied) {
		t.Fatal("newly added owner managed an old share", err)
	}
	if owned, _, _ := s.List(ctx, f, "owned", 20); len(owned) != 0 {
		t.Fatal("newly added owner lists an old share", owned)
	}
	// The creator can still revoke the suspended share.
	f.i = creator
	if _, _, err := s.Revoke(ctx, f, second.ID, 1, "r-creator"); err != nil {
		t.Fatal("creator could not revoke a suspended share", err)
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
	if _, _, err := s.Revoke(ctx, f, share.ID, 1, "r"); !errors.Is(err, capture.ErrDenied) {
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
	// A current deny of a member removes their management.
	mate := f.i
	mate.Principal.Subject = "mate"
	d := f.p.Allows[0]
	d.Audience.Kind, d.Audience.SubjectID, d.Audience.AssignmentID = "User", "mate", testID(63)
	f.p.Denies = []value.CurrentAssignment{d}
	f.i = mate
	if _, _, err := s.Revoke(ctx, f, share.ID, 1, "r"); !errors.Is(err, capture.ErrDenied) {
		t.Fatal("denied member revoked", err)
	}
	f.p.Denies = nil
	if _, _, err := s.Revoke(ctx, f, share.ID, 1, "r"); err != nil {
		t.Fatal("member revoke", err)
	}

	// More than eight owner teams: refused, never truncated.
	f, s = newFixture()
	for n := 0; n < value.ShareMaxManagers; n++ {
		f.i.Groups = append(f.i.Groups, f.addOwnerTeam(fmt.Sprintf("owners-%d", n), 30+n).SubjectID)
	}
	if _, _, err := s.Create(ctx, f, f.input("k1")); !errors.Is(err, ErrManagementTooBroad) || len(f.store.created) != 0 {
		t.Fatal("nine owner teams", err)
	}
}
