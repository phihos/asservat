package authorization

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

const previewCluster = "22222222-3333-4444-8555-666666666666"

type previewFixture struct {
	caller     identity.Identity
	admin      fleet.Administration
	snapshot   cfg.PreviewSnapshot
	snapErr    error
	recovery   artifact.RecoveryProof
	reads      []cfg.PreviewRead
	decodeErr  error
	identities int
}

func (f *previewFixture) ResolveIdentity(context.Context) (identity.Identity, error) {
	f.identities++
	return f.caller, nil
}
func (f *previewFixture) FleetAdministration(context.Context) (fleet.Administration, error) {
	return f.admin, nil
}
func (f *previewFixture) PreviewProjections(_ context.Context, r cfg.PreviewRead) (cfg.PreviewSnapshot, error) {
	f.reads = append(f.reads, r)
	return f.snapshot, f.snapErr
}
func (f *previewFixture) RecoveryState(context.Context) (artifact.RecoveryProof, error) {
	return f.recovery, nil
}
func (f *previewFixture) DecodeAccessBindingSpec(spec []byte) (cfg.Binding, error) {
	if f.decodeErr != nil || string(spec) != `{"effect":"Deny"}` {
		return cfg.Binding{}, cfg.ErrInvalid
	}
	return cfg.Binding{Resource: cfg.Resource{SpecDigest: artifact.Digest{7}}, Effect: "Deny", Subjects: []cfg.Subject{{Kind: "Group", Issuer: f.caller.Principal.Issuer, ID: "team-a"}}, Roles: []string{"evidence-reader"},
		Scope: cfg.Scope{ClusterID: previewCluster, Namespace: cfg.NamespaceRef{Name: "payments", UID: "ns"}}}, nil
}

func newPreviewFixture() (*previewFixture, AccessPreviewer) {
	n := time.Now().UTC()
	rev := identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{1}}
	f := &previewFixture{}
	f.caller = identity.Identity{Principal: identity.Principal{Issuer: "https://id.example.invalid", Subject: "admin", ClientID: "console", Kind: identity.Human}, Groups: []string{"platform-admins"}, Policy: rev, VerifiedAt: n, ValidUntil: n.Add(30 * time.Second)}
	f.admin = fleet.Administration{InstallationID: explainInstallation, IssuerEpoch: explainInstallation, Issuer: f.caller.Principal.Issuer, Revision: rev, ObservedAt: n, FreshUntil: n.Add(5 * time.Second),
		Clients: []string{"console"}, Groups: []string{"platform-admins"}, DeliveryProfiles: []string{"kv"}, MaxActiveBootstraps: 1, MaxBootstrapHistory: 1, MaxClusters: 1}
	f.recovery = artifact.RecoveryProof{InstallationID: explainInstallation, IssuerEpoch: explainInstallation, Revision: rev, ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}
	target := value.Target{ClusterID: previewCluster, NamespaceUID: "ns", WorkloadUID: cfg.OtherWorkloads, PodUID: cfg.OtherWorkloads}
	a := artifact.AudienceAssignment{Kind: "Group", Issuer: f.caller.Principal.Issuer, SubjectID: "team-a", Role: "evidence-reader", BasisKind: "AccessBinding", BasisUID: "binding", AssignmentID: "44444444-5555-4666-8777-888888888888", BasisDigest: artifact.Digest{2}}
	p := value.Projection{Target: target, Revision: rev, ObservedAt: n, FreshUntil: n.Add(30 * time.Second), DeniesComplete: true, DeniesObservedAt: n, DeniesFreshUntil: n.Add(30 * time.Second),
		Allows: []value.CurrentAssignment{{Audience: a, ObservedAt: n, FreshUntil: n.Add(30 * time.Second)}}}
	f.snapshot = cfg.PreviewSnapshot{Cells: []cfg.PreviewCell{{Target: target, Projection: p}}}
	return f, AccessPreviewer{InstallationID: explainInstallation, Administration: f, Projections: f, Decoder: f, Recovery: f, Clusters: []string{previewCluster}, Now: time.Now}
}

var addDeny = []ProposedChange{{Action: "create", Kind: "AccessBinding", Spec: []byte(`{"effect":"Deny"}`)}}

// ADR-237: a fleet operator previews a proposed deny over the current
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

// A caller who is not a current fleet operator, or uses another client, is
// refused before any proposal is decoded or projection read.
func TestAccessPreviewNonAdministratorRefused(t *testing.T) {
	for _, change := range []func(*previewFixture){
		func(f *previewFixture) { f.caller.Groups = []string{"team-a"} },
		func(f *previewFixture) { f.caller.Principal.ClientID = "mcp" },
		func(f *previewFixture) { f.admin.Suspended = true },
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
	many := make([]ProposedChange, cfg.MaxPreviewChanges+1)
	if _, _, err := s.Preview(context.Background(), f, many); !errors.Is(err, cfg.ErrLimit) {
		t.Fatalf("too many changes: %v", err)
	}
	f.snapErr = cfg.ErrLimit
	if _, _, err := s.Preview(context.Background(), f, addDeny); !errors.Is(err, cfg.ErrLimit) {
		t.Fatalf("more than 1,000 targets: %v", err)
	}
	f.snapErr = nil
	f.recovery.FreshUntil = time.Now().Add(-time.Second)
	if _, _, err := s.Preview(context.Background(), f, addDeny); !errors.Is(err, identity.ErrUnavailable) {
		t.Fatalf("recovery: %v", err)
	}
}

// An unavailable projection is reported Indeterminate, never evaluated.
func TestAccessPreviewUnavailableProjection(t *testing.T) {
	f, s := newPreviewFixture()
	f.snapshot.Cells[0].Unavailable = value.UnmetPermissionStale
	got, _, err := s.Preview(context.Background(), f, addDeny)
	if err != nil || got.Complete() || len(got.Deltas) != 0 || got.Unavailable[0].Unavailable != value.UnmetPermissionStale {
		t.Fatalf("%v %+v", err, got)
	}
}
