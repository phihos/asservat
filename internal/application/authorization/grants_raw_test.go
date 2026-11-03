package authorization

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

func TestRawArgumentResultUsesExistingExactChild(t *testing.T) {
	f := newGrantFixture(t)
	in := f.input(7, f.access())
	in.DataClass = "raw"
	in.Reasons = []value.SensitiveReason{{ActionID: "a1", Code: "syscallArguments"}}
	in.Review.Actions[0].Kind = "syscallTrace"
	in.Scope = []byte(`{"schemaVersion":"recorder-preview/v1","actions":[{"actionID":"a1","kind":"syscallTrace","mode":"arguments"}]}`)
	in.ExecutionDigest = sha256.Sum256(in.Scope)
	dev := grantIdentity{f.requester, &f.now}
	g, _, err := f.svc.Request(t.Context(), dev, in)
	if err != nil {
		t.Fatal(err)
	}
	g = f.approve(t, g)
	scope := artifact.DownloadScope{RootID: grantRoot, ArtifactID: grantID(507), CaptureID: g.CaptureID, ClusterID: f.target.ClusterID, NamespaceUID: f.target.NamespaceUID, WorkloadUID: f.target.WorkloadUID, PodUID: f.target.PodUID, Version: artifact.Digest{5}, Principal: f.requester.Principal}
	f.store.locator[scope.ArtifactID] = g.CaptureID
	if _, err := f.svc.CurrentResultAccess(t.Context(), dev, scope, "a1"); err != nil {
		t.Fatal("argument result child refused", err)
	}
	use := value.GrantUse{Operation: value.GrantDownloadOperation, Bytes: 10, Operations: 1}
	if err := f.svc.ReserveRawResult(t.Context(), dev, scope, grantID(600), use); err != nil {
		t.Fatal("argument result spend refused", err)
	}
	if err := f.svc.ReserveRawResult(t.Context(), dev, scope, grantID(600), use); err != nil || f.store.rows[g.ID].Spent.Bytes != 10 {
		t.Fatal("argument result replay refilled or repeated spend", err)
	}
	other := scope
	other.Version[0]++
	if err := f.svc.ReserveRawResult(t.Context(), dev, other, grantID(601), use); !errors.Is(err, value.ErrGrantScope) {
		t.Fatal("argument version substitution admitted", err)
	}
}

// rawGrant approves a raw ad hoc grant with result access and publishes one
// artifact of its capture; it returns the requester's download scope.
func rawGrant(t *testing.T, f *grantFixture, capture int) (value.Grant, artifact.DownloadScope) {
	t.Helper()
	in := f.input(capture, f.access())
	in.DataClass = "raw"
	g, _, err := f.svc.Request(context.Background(), grantIdentity{f.requester, &f.now}, in)
	if err != nil {
		t.Fatal(err)
	}
	g = f.approve(t, g)
	scope := artifact.DownloadScope{RootID: grantRoot, ArtifactID: grantID(500 + capture), CaptureID: g.CaptureID, ClusterID: f.target.ClusterID, NamespaceUID: f.target.NamespaceUID, WorkloadUID: f.target.WorkloadUID, PodUID: f.target.PodUID, Version: artifact.Digest{5}, Principal: f.requester.Principal}
	return g, scope
}

// ADR-279: the first raw download materializes the requester's child after
// verified commit; every later batch reserves one use of the shared pool.
func TestRawResultAccessMaterializesAndReserves(t *testing.T) {
	ctx := context.Background()
	f := newGrantFixture(t)
	g, scope := rawGrant(t, f, 7)
	dev := grantIdentity{f.requester, &f.now}
	if _, err := f.svc.CurrentResultAccess(ctx, dev, scope, "a1"); !errors.Is(err, value.ErrGrantScope) {
		t.Fatal("unpublished artifact admitted", err)
	}
	f.store.locator[scope.ArtifactID] = g.CaptureID
	until, err := f.svc.CurrentResultAccess(ctx, dev, scope, "a1")
	if err != nil || !until.Equal(f.now.Add(30*time.Second)) || len(f.store.children) != 1 {
		t.Fatal("current child", until, err, len(f.store.children))
	}
	if _, err = f.svc.CurrentResultAccess(ctx, dev, scope, "a1"); err != nil || len(f.store.children) != 1 || f.store.rows[g.ID].Spent.Artifacts != 1 {
		t.Fatal("repeated check created another child", err)
	}
	reserve := func(who identity.Identity, s artifact.DownloadScope, id int, bytes int64) error {
		return f.svc.ReserveRawResult(ctx, grantIdentity{who, &f.now}, s, grantID(id), value.GrantUse{Operation: value.GrantDownloadOperation, Bytes: bytes, Operations: 1})
	}
	if err = reserve(f.requester, scope, 600, 60); err != nil {
		t.Fatal(err)
	}
	if err = reserve(f.requester, scope, 600, 60); err != nil || f.store.rows[g.ID].Spent.Bytes != 60 {
		t.Fatal("batch replay charged again", err)
	}
	if err = reserve(f.requester, scope, 601, 41); !errors.Is(err, value.ErrGrantPoolExhausted) {
		t.Fatal("pool exceeded", err)
	}
	// Another version of the artifact is not this child.
	other := scope
	other.Version = artifact.Digest{6}
	if err = reserve(f.requester, other, 602, 1); !errors.Is(err, value.ErrGrantScope) {
		t.Fatal("other version reserved", err)
	}
	// An approved second client needs its own child, created on its first check.
	agent := f.requester
	agent.Principal.ClientID = "agent"
	agentScope := scope
	agentScope.Principal = agent.Principal
	if err = reserve(agent, agentScope, 603, 1); !errors.Is(err, ErrGrantNotFound) {
		t.Fatal("reserved without a child", err)
	}
	if _, err = f.svc.CurrentResultAccess(ctx, grantIdentity{agent, &f.now}, agentScope, "a1"); err != nil || f.store.rows[g.ID].Spent.Artifacts != 1 {
		t.Fatal("second approved client", err)
	}
	if err = reserve(agent, agentScope, 604, 10); err != nil || f.store.rows[g.ID].Spent.Bytes != 70 {
		t.Fatal("second client spends the shared pool", err)
	}
	// Unlisted clients and other humans never reach a child or the pool.
	cli := f.requester
	cli.Principal.ClientID = "cli"
	cliScope := scope
	cliScope.Principal = cli.Principal
	if _, err = f.svc.CurrentResultAccess(ctx, grantIdentity{cli, &f.now}, cliScope, "a1"); !errors.Is(err, value.ErrGrantScope) {
		t.Fatal("unlisted client admitted", err)
	}
	outsider := f.outside
	outsider.Scopes = append(outsider.Scopes, "evidence:download")
	outScope := scope
	outScope.Principal = outsider.Principal
	children := len(f.store.children)
	if _, err = f.svc.CurrentResultAccess(ctx, grantIdentity{outsider, &f.now}, outScope, "a1"); !errors.Is(err, value.ErrGrantPrincipal) || len(f.store.children) != children {
		t.Fatal("another human admitted or materialized", err)
	}
	if err = reserve(outsider, outScope, 605, 1); !errors.Is(err, value.ErrGrantPrincipal) {
		t.Fatal("another human reserved", err)
	}
	// A scope naming someone other than the caller is refused.
	if _, err = f.svc.CurrentResultAccess(ctx, grantIdentity{outsider, &f.now}, scope, "a1"); !errors.Is(err, value.ErrGrantPrincipal) {
		t.Fatal("caller used another principal's scope", err)
	}
	// Revocation stops the facet and every reservation.
	g = f.store.rows[g.ID]
	if _, _, err = f.svc.Revoke(ctx, grantIdentity{f.approver, &f.now}, g.ID, g.Revision, "stop"); err != nil {
		t.Fatal(err)
	}
	if _, err = f.svc.CurrentResultAccess(ctx, dev, scope, "a1"); !errors.Is(err, value.ErrGrantRevoked) {
		t.Fatal("revoked parent admitted", err)
	}
	if err = reserve(f.requester, scope, 606, 1); !errors.Is(err, value.ErrGrantRevoked) {
		t.Fatal("revoked parent reserved", err)
	}
}

func TestRawResultAccessRefusesExpiredAndNonRawGrants(t *testing.T) {
	ctx := context.Background()
	f := newGrantFixture(t)
	g, scope := rawGrant(t, f, 7)
	f.store.locator[scope.ArtifactID] = g.CaptureID
	dev := grantIdentity{f.requester, &f.now}
	if _, err := f.svc.CurrentResultAccess(ctx, dev, scope, "a1"); err != nil {
		t.Fatal(err)
	}
	f.now = g.ExpiresAt
	if _, err := f.svc.CurrentResultAccess(ctx, dev, scope, "a1"); !errors.Is(err, value.ErrGrantExpired) {
		t.Fatal("expired parent admitted", err)
	}
	if err := f.svc.ReserveRawResult(ctx, dev, scope, grantID(600), value.GrantUse{Operation: value.GrantDownloadOperation, Bytes: 1}); !errors.Is(err, value.ErrGrantExpired) {
		t.Fatal("expired parent reserved", err)
	}
	// A grant reviewed for another class never admits a raw download.
	f = newGrantFixture(t)
	m := f.approve(t, f.request(t, 8, f.access()))
	scope.CaptureID, scope.ArtifactID = m.CaptureID, grantID(508)
	f.store.locator[scope.ArtifactID] = m.CaptureID
	if _, err := f.svc.CurrentResultAccess(ctx, grantIdentity{f.requester, &f.now}, scope, "a1"); !errors.Is(err, value.ErrGrantScope) {
		t.Fatal("non-raw grant admitted raw", err)
	}
	// No grant for the capture at all.
	scope.CaptureID = grantID(9)
	if _, err := f.svc.CurrentResultAccess(ctx, grantIdentity{f.requester, &f.now}, scope, "a1"); !errors.Is(err, value.ErrApprovalRequired) {
		t.Fatal("capture without a grant admitted", err)
	}
}
