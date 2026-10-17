package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	configapp "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"testing"
)

func TestPermissionContinuityRequiresExactVersionsOrVerifiedTransitions(t *testing.T) {
	next := cfg.PermissionBasis{Resource: cfg.Resource{Kind: "AccessBinding", Generation: 3, ResourceVersion: "opaque-new", SpecDigest: artifact.Digest{1}}, Effect: "Allow", ScopeDigest: artifact.Digest{2}}
	old := custodydb.PermissionBasis{Kind: "AccessBinding", Generation: 3, ResourceVersion: "opaque-old", SpecDigest: []byte{1}, Effect: "Allow", ScopeDigest: next.ScopeDigest[:]}
	old.SpecDigest = append([]byte{}, next.Resource.SpecDigest[:]...)
	if equivalentBasis(old, next) {
		t.Fatal("matching final spec and generation hid a possible ownership cycle")
	}
	next.Resource.ResourceVersion = old.ResourceVersion
	if !equivalentBasis(old, next) {
		t.Fatal("exact unchanged observation discarded")
	}
	next.Resource.ResourceVersion = "opaque-new"
	next.Continuous = true
	if !equivalentBasis(old, next) {
		t.Fatal("verified metadata-only transition discarded")
	}
	next.Resource.Generation += 2
	if equivalentBasis(old, next) {
		t.Fatal("generation gap accepted")
	}
}
func TestScopeDigestNormalizationAndBasisIdentity(t *testing.T) {
	a := cfg.PermissionBasis{Resource: cfg.Resource{Kind: "AccessBinding", UID: "foo"}, Scope: cfg.Scope{ClusterID: "11111111-1111-4111-8111-111111111111", Namespace: cfg.NamespaceRef{Name: "app", UID: "bar:22222222-2222-4222-8222-222222222222:baz"}}, Effect: "Allow"}
	b := a
	b.Resource.UID = "foo:" + a.Scope.ClusterID + ":bar"
	b.Scope.ClusterID = "22222222-2222-4222-8222-222222222222"
	b.Scope.Namespace.UID = "baz"
	if a.Key() == b.Key() {
		t.Fatal("delimiter collision in persistent basis identity")
	}
	b = a
	b.Scope.Workloads = []cfg.WorkloadRef{}
	if configapp.PermissionScopeDigest(a) != configapp.PermissionScopeDigest(b) {
		t.Fatal("empty list changed scope")
	}
	b.Scope.Namespace.UID = "other"
	if configapp.PermissionScopeDigest(a) == configapp.PermissionScopeDigest(b) {
		t.Fatal("namespace replacement kept scope digest")
	}
}
