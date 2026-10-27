package privacy

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
)

const (
	retentionPreviewInstallation = "11111111-2222-4333-8444-555555555555"
	retentionPreviewCluster      = "22222222-3333-4444-8555-666666666666"
)

type retentionPreviewFixture struct {
	caller   identity.Identity
	admin    fleet.Administration
	adminErr error
	recovery artifact.RecoveryProof
	catalog  value.PreviewCatalog
	reads    int
	decodes  int
	resolved int
	// changeCaller replaces the caller on the second identity resolution.
	changeCaller func(*identity.Identity)
}

func (f *retentionPreviewFixture) ResolveIdentity(context.Context) (identity.Identity, error) {
	f.resolved++
	i := f.caller
	if f.resolved > 1 && f.changeCaller != nil {
		f.changeCaller(&i)
	}
	return i, nil
}
func (f *retentionPreviewFixture) FleetAdministration(context.Context) (fleet.Administration, error) {
	return f.admin, f.adminErr
}
func (f *retentionPreviewFixture) RecoveryState(context.Context) (artifact.RecoveryProof, error) {
	return f.recovery, nil
}
func (f *retentionPreviewFixture) RetentionPreviewCatalog(_ context.Context, limit int) (value.PreviewCatalog, error) {
	f.reads++
	if limit != value.MaxRetentionPreviewArtifacts {
		return value.PreviewCatalog{}, value.ErrInvalid
	}
	return f.catalog, nil
}
func (f *retentionPreviewFixture) DecodeRetentionPolicySpec(spec []byte, hub bool) (value.ScopedPolicy, error) {
	f.decodes++
	if string(spec) != `{"maxima":"short"}` || !hub {
		return value.ScopedPolicy{}, value.ErrInvalid
	}
	return value.ScopedPolicy{Policy: value.Policy{Revision: identity.Revision{Digest: artifact.Digest{9}}, Baseline: true, PurposeRef: "diagnostics", DefaultSeconds: 600, MaximumSeconds: 3600, DeletionBudgetSeconds: 300}, CaseDefaultSeconds: 3600, CaseMaximumSeconds: 7200, AuditDefaultSeconds: 3600, AuditMaximumSeconds: 7200, LegalExceptions: "disabled"}, nil
}

func newRetentionPreviewFixture() (*retentionPreviewFixture, RetentionPreviewer) {
	n := time.Now().UTC()
	rev := identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{1}}
	f := &retentionPreviewFixture{}
	f.caller = identity.Identity{Principal: identity.Principal{Issuer: "https://id.example.invalid", Subject: "admin", ClientID: "console", Kind: identity.Human}, Groups: []string{"platform-admins"}, Policy: rev, VerifiedAt: n, ValidUntil: n.Add(30 * time.Second)}
	f.admin = fleet.Administration{InstallationID: retentionPreviewInstallation, IssuerEpoch: retentionPreviewInstallation, Issuer: f.caller.Principal.Issuer, Revision: rev, ObservedAt: n, FreshUntil: n.Add(5 * time.Second),
		Clients: []string{"console"}, Groups: []string{"platform-admins"}, DeliveryProfiles: []string{"kv"}, MaxActiveBootstraps: 1, MaxBootstrapHistory: 1, MaxClusters: 1}
	f.recovery = artifact.RecoveryProof{InstallationID: retentionPreviewInstallation, IssuerEpoch: retentionPreviewInstallation, Revision: rev, ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}
	baseline := value.ScopedPolicy{Name: "baseline", Policy: value.Policy{Revision: identity.Revision{UID: "baseline", Generation: 1, Digest: artifact.Digest{1}}, Baseline: true, PurposeRef: "diagnostics", DefaultSeconds: 600, MaximumSeconds: 7200, DeletionBudgetSeconds: 300}, CaseDefaultSeconds: 3600, CaseMaximumSeconds: 7200, AuditDefaultSeconds: 3600, AuditMaximumSeconds: 7200, LegalExceptions: "disabled"}
	snapshot := value.PolicySnapshot{SourceClusterID: retentionPreviewCluster, ControlNamespaceUID: "control", Hub: true, Revision: rev, ObservedAt: n, FreshUntil: n.Add(5 * time.Second), Policies: []value.ScopedPolicy{baseline}}
	f.catalog = value.PreviewCatalog{Sources: []value.PreviewSource{{Ref: value.PolicySourceRef{ClusterID: retentionPreviewCluster, ControlNamespaceUID: "control", Hub: true}, Ready: true, Current: &snapshot}}}
	return f, RetentionPreviewer{InstallationID: retentionPreviewInstallation, Administration: f, Catalog: f, Decoder: f, Recovery: f, Now: time.Now}
}

var shortenBaseline = []ProposedRetentionChange{{Action: "update", UID: "baseline", Spec: []byte(`{"maxima":"short"}`)}}

// ADR-240: a current fleet operator previews a proposed change over the
// catalog; the reply deadline never exceeds identity, administration or
// recovery freshness.
func TestRetentionPreviewFleetOperator(t *testing.T) {
	f, s := newRetentionPreviewFixture()
	got, until, err := s.Preview(context.Background(), f, shortenBaseline)
	if err != nil || f.reads != 1 || !got.Complete() || got.Scanned != 0 || until.After(f.admin.FreshUntil) || until.After(f.recovery.FreshUntil) || f.resolved != 2 {
		t.Fatalf("%+v %v %v reads=%d", got, until, err, f.reads)
	}
}

// Callers who are not current fleet operators learn nothing: no proposal is
// decoded and no catalog read.
func TestRetentionPreviewNonOperatorRefused(t *testing.T) {
	for name, change := range map[string]func(*retentionPreviewFixture){
		"other-group":  func(f *retentionPreviewFixture) { f.caller.Groups = []string{"team-a"} },
		"other-client": func(f *retentionPreviewFixture) { f.caller.Principal.ClientID = "mcp" },
		"suspended":    func(f *retentionPreviewFixture) { f.admin.Suspended = true },
		"expired":      func(f *retentionPreviewFixture) { f.caller.ValidUntil = time.Now().Add(-time.Second) },
	} {
		f, s := newRetentionPreviewFixture()
		change(f)
		if _, _, err := s.Preview(context.Background(), f, shortenBaseline); !errors.Is(err, identity.ErrDenied) || f.reads != 0 || f.decodes != 0 {
			t.Fatalf("%s: %v reads=%d decodes=%d", name, err, f.reads, f.decodes)
		}
	}
	f, s := newRetentionPreviewFixture()
	f.adminErr = errors.New("settings unavailable")
	if _, _, err := s.Preview(context.Background(), f, shortenBaseline); !errors.Is(err, identity.ErrUnavailable) || f.reads != 0 || f.decodes != 0 {
		t.Fatal(err)
	}
	// An operator who loses the role during the request gets no result.
	f, s = newRetentionPreviewFixture()
	f.changeCaller = func(i *identity.Identity) { i.Groups = nil }
	if _, _, err := s.Preview(context.Background(), f, shortenBaseline); !errors.Is(err, identity.ErrDenied) {
		t.Fatal(err)
	}
}

func TestRetentionPreviewRefusesInvalidProposalAndRecovery(t *testing.T) {
	f, s := newRetentionPreviewFixture()
	if _, _, err := s.Preview(context.Background(), f, []ProposedRetentionChange{{Action: "update", UID: "baseline", Spec: []byte(`{}`)}}); !errors.Is(err, value.ErrInvalid) || f.reads != 0 {
		t.Fatal(err)
	}
	if _, _, err := s.Preview(context.Background(), f, []ProposedRetentionChange{{Action: "delete", UID: "baseline", Spec: []byte(`{}`)}}); !errors.Is(err, value.ErrInvalid) {
		t.Fatal(err)
	}
	if _, _, err := s.Preview(context.Background(), f, make([]ProposedRetentionChange, value.MaxRetentionPreviewChanges+1)); !errors.Is(err, value.ErrPreviewLimit) || f.reads != 0 {
		t.Fatal(err)
	}
	// A local source's spec is decoded as local (never a baseline).
	if _, _, err := s.Preview(context.Background(), f, []ProposedRetentionChange{{Action: "create", SourceClusterID: retentionPreviewCluster, Spec: []byte(`{"maxima":"short"}`)}}); !errors.Is(err, value.ErrInvalid) {
		t.Fatal(err)
	}
	f, s = newRetentionPreviewFixture()
	f.recovery.InstallationID = retentionPreviewCluster
	if _, _, err := s.Preview(context.Background(), f, shortenBaseline); !errors.Is(err, identity.ErrUnavailable) || f.reads != 0 {
		t.Fatal(err)
	}
}
