package authorization

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

const previewCluster = "22222222-3333-4444-8555-666666666666"

type previewFixture struct {
	caller     identity.Identity
	admin      identity.Policy
	snapshot   cfg.PreviewSnapshot
	snapErr    error
	reads      []cfg.PreviewRead
	decodeErr  error
	identities int
}

func (f *previewFixture) ResolveIdentity(context.Context) (identity.Identity, error) {
	f.identities++
	return f.caller, nil
}
func (f *previewFixture) IdentityPolicy(_ context.Context, issuer string) (identity.Policy, error) {
	if issuer != f.admin.Issuer {
		return identity.Policy{}, identity.ErrDenied
	}
	return f.admin, nil
}
func (f *previewFixture) PreviewProjections(_ context.Context, r cfg.PreviewRead) (cfg.PreviewSnapshot, error) {
	f.reads = append(f.reads, r)
	return f.snapshot, f.snapErr
}
func (f *previewFixture) DecodeAccessBindingSpec(spec []byte) (cfg.Binding, error) {
	if f.decodeErr != nil || string(spec) != `{"effect":"Deny"}` {
		return cfg.Binding{}, cfg.ErrInvalid
	}
	return cfg.Binding{Resource: cfg.Resource{SpecDigest: artifact.Digest{7}}, Effect: "Deny", Subjects: []cfg.Subject{{Kind: "Group", Issuer: f.caller.Principal.Issuer, ID: "team-a"}}, Roles: []string{"evidence-reader"}}, nil
}
func (f *previewFixture) DecodePermissionSourceSpec([]byte) (cfg.Source, error) {
	return cfg.Source{}, cfg.ErrInvalid
}

func newPreviewFixture() (*previewFixture, AccessPreviewer) {
	n := time.Now().UTC()
	rev := identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{1}}
	f := &previewFixture{}
	f.caller = identity.Identity{Principal: identity.Principal{Issuer: "https://id.example.invalid", Subject: "admin", ClientID: "console", Kind: identity.Human}, Groups: []string{"platform-admins"}, Policy: rev, VerifiedAt: n, ValidUntil: n.Add(30 * time.Second)}
	f.admin = identity.Policy{Issuer: f.caller.Principal.Issuer, Revision: rev, ObservedAt: n, FreshUntil: n.Add(30 * time.Second), AdministratorGroups: []string{"platform-admins"}}
	target := value.Target{ClusterID: previewCluster, NamespaceUID: "ns", WorkloadUID: cfg.OtherWorkloads, PodUID: cfg.OtherWorkloads}
	a := artifact.AudienceAssignment{Kind: "Group", Issuer: f.caller.Principal.Issuer, SubjectID: "team-a", Role: "evidence-reader", BasisKind: "AccessBinding", BasisUID: "binding", AssignmentID: "44444444-5555-4666-8777-888888888888", BasisDigest: artifact.Digest{2}}
	p := value.Projection{Target: target, Revision: rev, ObservedAt: n, FreshUntil: n.Add(30 * time.Second), DeniesComplete: true, DeniesObservedAt: n, DeniesFreshUntil: n.Add(30 * time.Second),
		Allows: []value.CurrentAssignment{{Audience: a, ObservedAt: n, FreshUntil: n.Add(30 * time.Second)}}}
	f.snapshot = cfg.PreviewSnapshot{Cells: []cfg.PreviewCell{{Target: target, Projection: p}}}
	return f, AccessPreviewer{InstallationID: explainInstallation, Administrators: f, Projections: f, Decoder: f, Clusters: []string{previewCluster}, Now: time.Now}
}

// ADR-329: the proposed binding's namespace is its scope.
var addDeny = []ProposedChange{{Action: "create", Kind: "AccessBinding", Spec: []byte(`{"effect":"Deny"}`), ClusterID: previewCluster, Namespace: cfg.NamespaceRef{Name: "payments", UID: "ns"}}}

// ADR-237: an administrator previews a proposed deny over the current
// projection with the real evaluator.
func TestAccessPreviewAdministrator(t *testing.T) {
	f, s := newPreviewFixture()
	got, until, err := s.Preview(context.Background(), f, addDeny)
	if err != nil || until.IsZero() || len(f.reads) != 1 {
		t.Fatalf("preview: %v reads=%d", err, len(f.reads))
	}
	if got.DeltasTotal != 2 || got.Deltas[0].Before != value.Allow || got.Deltas[0].After != value.Deny || got.Deltas[0].AfterUnmet != value.UnmetExplicitDeny {
		t.Fatalf("deltas %+v", got.Deltas)
	}
	if r := f.reads[0]; len(r.Namespaces) != 1 || r.Namespaces[0] != (cfg.PreviewNamespace{ClusterID: previewCluster, NamespaceUID: "ns"}) {
		t.Fatalf("read %+v", r)
	}
}

// A caller who is not a listed administrator, or of another issuer, is
// refused before any proposal is decoded or projection read.
func TestAccessPreviewNonAdministratorRefused(t *testing.T) {
	for _, change := range []func(*previewFixture){
		func(f *previewFixture) { f.caller.Groups = []string{"team-a"} },
		func(f *previewFixture) { f.caller.Principal.Issuer = "https://other.example.invalid" },
	} {
		f, s := newPreviewFixture()
		change(f)
		f.decodeErr = errors.New("must not decode")
		if _, _, err := s.Preview(context.Background(), f, addDeny); !errors.Is(err, identity.ErrDenied) || len(f.reads) != 0 {
			t.Fatalf("err=%v reads=%d", err, len(f.reads))
		}
	}
}

func TestAccessPreviewRefusals(t *testing.T) {
	f, s := newPreviewFixture()
	if _, _, err := s.Preview(context.Background(), f, []ProposedChange{{Action: "create", Kind: "AccessBinding", Spec: []byte(`{}`)}}); !errors.Is(err, cfg.ErrInvalid) {
		t.Fatalf("invalid spec: %v", err)
	}
}

// An unavailable projection is reported Indeterminate, never evaluated.
func TestAccessPreviewUnavailableProjection(t *testing.T) {
	f, s := newPreviewFixture()
	f.snapshot.Cells[0].Unavailable = value.UnmetClusterNotObserved
	got, _, err := s.Preview(context.Background(), f, addDeny)
	if err != nil || got.Complete() || len(got.Deltas) != 0 || got.Unavailable[0].Unavailable != value.UnmetClusterNotObserved {
		t.Fatalf("%v %+v", err, got)
	}
}
