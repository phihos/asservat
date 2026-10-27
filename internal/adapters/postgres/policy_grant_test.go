package postgres

import (
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgtype"
)

func policyGrantTestRow(t *testing.T) custodydb.AccessGrant {
	t.Helper()
	p := previewTestValue(t)
	a := authorization.AcceptedPolicyAuthority{InstallationID: p.InstallationID, PolicyUID: "policy", Creator: p.Actor,
		Executor: authorization.PolicyPrincipal(p.InstallationID, "policy"), ScopeDigest: p.ScopeDigest,
		ClusterID: p.Target.ClusterID, NamespaceUID: p.Target.Namespace.UID, WorkloadUID: p.Target.Workload.UID,
		Delegation: identity.Revision{UID: "binding", Generation: 1, Digest: artifact.Digest{2}}, Owners: p.Audience,
		Actions: []string{"packetCapture"}, Limits: authorization.AutomationLimits{MaxExecutions: 10, MaxBytes: 10000000},
		IssuedAt: p.CreatedAt.Add(-time.Hour), NotAfter: p.CreatedAt.Add(30 * 24 * time.Hour)}
	scope := authorization.PolicyGrantScope{Authority: a, RecipeDigest: artifact.Digest{4}, Limits: a.Limits,
		ApprovalPolicyRef: identity.Revision{UID: "settings", Generation: 1, Digest: artifact.Digest{5}}, ApprovalMaxAge: 30 * 24 * time.Hour}
	b, err := json.Marshal(scope)
	if err != nil {
		t.Fatal(err)
	}
	r := custodydb.AccessGrant{ID: id(p.ID), RootID: id(p.RootID), Kind: authorization.GrantPolicy, ClusterID: id(a.ClusterID), NamespaceUid: a.NamespaceUID, WorkloadUid: a.WorkloadUID,
		ExecutionDigest: a.ScopeDigest[:], ReviewDigest: make([]byte, 32), DataClass: "extract", Reasons: []byte(`[{"actionID":"packet","code":"rawBytePredicate"}]`), Review: []byte(`{}`), Scope: p.CanonicalScope,
		RequesterIssuer: p.Actor.Issuer, RequesterSubject: p.Actor.Subject, RequesterClient: p.Actor.ClientID, RequesterKind: string(p.Actor.Kind), RequestOperation: "requestPolicyGrant",
		LifetimeSeconds: 604800, RequestedAt: ts(p.CreatedAt), ReviewUntil: ts(p.CreatedAt.Add(time.Hour)), Revision: 1,
		PolicyUid: grantText(a.PolicyUID), PolicyAcceptanceID: id(p.CaseID), PolicyScope: b, PolicyNotAfter: ts(p.CreatedAt.Add(7 * 24 * time.Hour)),
		PolicyMaxExecutions: pgtype.Int8{Int64: a.Limits.MaxExecutions, Valid: true}, PolicyMaxBytes: pgtype.Int8{Int64: a.Limits.MaxBytes, Valid: true}, PolicyMaxObservedBytes: pgtype.Int8{Valid: true}}
	r.ReviewDigest[0] = 9
	return r
}

func TestPolicyGrantRowSeparatesWorkloadScopeAndRequestPrincipal(t *testing.T) {
	r := policyGrantTestRow(t)
	g, err := grantFromRow(r)
	if err != nil || g.Target != (authorization.Target{}) || g.Policy == nil || g.Policy.Workload().WorkloadUID != r.WorkloadUid || !g.Valid() {
		t.Fatal("policy row lost typed workload or original scope", g, err)
	}
	r.RequesterKind = string(identity.Workload)
	g, err = grantFromRow(r)
	if err != nil || g.Requester.Kind != identity.Workload {
		t.Fatal("authenticated service became a human", err)
	}
	for name, change := range map[string]func(*custodydb.AccessGrant){
		"capture substitution":     func(r *custodydb.AccessGrant) { r.CaptureID = r.ID },
		"pod substitution":         func(r *custodydb.AccessGrant) { r.PodUid = grantText("pod") },
		"workload mismatch":        func(r *custodydb.AccessGrant) { r.WorkloadUid = "other" },
		"policy mismatch":          func(r *custodydb.AccessGrant) { r.PolicyUid = grantText("other") },
		"missing acceptance":       func(r *custodydb.AccessGrant) { r.PolicyAcceptanceID = pgtype.UUID{} },
		"other operation":          func(r *custodydb.AccessGrant) { r.RequestOperation = "requestGrant" },
		"wrong maximum":            func(r *custodydb.AccessGrant) { r.PolicyMaxBytes.Int64++ },
		"missing maximum":          func(r *custodydb.AccessGrant) { r.PolicyMaxBytes.Valid = false },
		"spend before approval":    func(r *custodydb.AccessGrant) { r.PolicyExecutionsSpent++ },
		"original expiry extended": func(r *custodydb.AccessGrant) { r.PolicyNotAfter = ts(r.RequestedAt.Time.Add(8 * 24 * time.Hour)) },
	} {
		t.Run(name, func(t *testing.T) {
			x := policyGrantTestRow(t)
			change(&x)
			if _, err := grantFromRow(x); err == nil {
				t.Fatal("invalid policy record accepted")
			}
		})
	}
}

func TestPolicyGrantRequestIndexNeverAliasesAnotherFullActorOrInput(t *testing.T) {
	r := policyGrantTestRow(t)
	a := identity.Principal{Issuer: r.RequesterIssuer, Subject: r.RequesterSubject, ClientID: r.RequesterClient, Kind: identity.Kind(r.RequesterKind)}
	d := artifact.Digest{5}
	r.RequestDigest = d[:]
	if !policyGrantRequestMatches(r, a, r.PolicyUid.String, d) {
		t.Fatal("exact original request refused")
	}
	for _, change := range []func(*custodydb.AccessGrant){
		func(r *custodydb.AccessGrant) { r.RequesterClient += "-other" },
		func(r *custodydb.AccessGrant) { r.RequesterIssuer += "/other" },
		func(r *custodydb.AccessGrant) { r.RequesterSubject += "-other" },
		func(r *custodydb.AccessGrant) { r.RequesterKind = string(identity.Workload) },
		func(r *custodydb.AccessGrant) { r.PolicyUid = grantText("other") },
		func(r *custodydb.AccessGrant) { r.RequestOperation = "other" },
		func(r *custodydb.AccessGrant) { r.RequestDigest = make([]byte, 32) },
	} {
		x := r
		change(&x)
		if policyGrantRequestMatches(x, a, r.PolicyUid.String, d) {
			t.Fatal("indexed collision aliased another request")
		}
	}
}
