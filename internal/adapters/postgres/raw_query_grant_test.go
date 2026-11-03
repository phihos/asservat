package postgres

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"github.com/jackc/pgx/v5/pgtype"
)

func rawQueryTestRow(t *testing.T) custodydb.AccessGrant {
	t.Helper()
	p := previewTestValue(t)
	now := p.CreatedAt
	output := value.VerifiedOutput{CaptureID: p.ID, ActionID: "a1", ArtifactID: p.CaseID, ExecutionDigest: p.ScopeDigest, ArtifactDigest: artifact.Digest{9}, Target: value.Target{ClusterID: p.Target.ClusterID, NamespaceUID: p.Target.Namespace.UID, WorkloadUID: p.Target.Workload.UID, PodUID: p.Target.PodUID}}
	scope := value.RawQueryScope{CaseID: p.CaseID, Artifacts: []value.RawQueryArtifact{{Output: output, NativeBytes: 353, ExpiresAt: now.Add(time.Hour)}}, Operations: []string{value.GrantDownloadOperation}, Reason: "Inspect saved synthetic evidence", MaxBytes: artifact.MaxNativeBytes, MaxOperations: 10000, NotAfter: now.Add(time.Hour)}
	raw, err := json.Marshal(scope)
	if err != nil {
		t.Fatal(err)
	}
	canonical, d := app.RawQueryScopeBytes(scope)
	return custodydb.AccessGrant{ID: id(p.ID), RootID: id(p.RootID), Kind: value.GrantRawQuery, ExecutionDigest: d[:], ReviewDigest: append([]byte{4}, make([]byte, 31)...), DataClass: "raw", Reasons: []byte(`[{"actionID":"download_artifact","code":"rawDisclosure"}]`), Scope: canonical, Review: []byte(`{}`), RequesterIssuer: p.Actor.Issuer, RequesterSubject: p.Actor.Subject, RequesterClient: p.Actor.ClientID, RequesterKind: string(p.Actor.Kind), RequesterKey: policyGrantActorKey(p.Actor), RequestOperation: "requestRawAccess", LifetimeSeconds: 3600, RequestedAt: ts(now), ReviewUntil: ts(now.Add(time.Hour)), NotAfter: ts(scope.NotAfter), MaxArtifacts: 1, MaxBytes: scope.MaxBytes, MaxOperations: scope.MaxOperations, RawQuery: raw, Revision: 1}
}
func TestRawQueryGrantRowPreservesExactOriginalMember(t *testing.T) {
	row := rawQueryTestRow(t)
	g, err := grantFromRow(row)
	if err != nil || g.Target != (value.Target{}) || g.CaptureID != "" || !app.RawQueryScopeMatches(g) || g.RawQuery.MaxBytes != artifact.MaxNativeBytes {
		t.Fatal(g, err)
	}
	output := g.RawQuery.Artifacts[0].Output
	childRow := custodydb.AccessGrantChild{ID: id(g.RawQuery.CaseID), RootID: row.RootID, ParentID: row.ID, CaptureID: id(output.CaptureID), ActionID: output.ActionID, ArtifactID: id(output.ArtifactID), ArtifactDigest: output.ArtifactDigest[:], ClientID: g.Requester.ClientID, CreatedAt: row.RequestedAt}
	child, err := childFromRow(childRow, g)
	if err != nil || child.Output != output || child.Output.ExecutionDigest == g.ExecutionDigest {
		t.Fatal("child used raw parent query digest/empty target", child, err)
	}
	for _, alter := range []func(*custodydb.AccessGrantChild){func(r *custodydb.AccessGrantChild) { r.ClientID += "other" }, func(r *custodydb.AccessGrantChild) { r.CaptureID = id("00000000-0000-4000-8000-000000000099") }, func(r *custodydb.AccessGrantChild) { r.ActionID = "other" }, func(r *custodydb.AccessGrantChild) { r.ArtifactDigest = make([]byte, 32) }} {
		bad := childRow
		alter(&bad)
		if _, err := childFromRow(bad, g); err == nil {
			t.Fatal("unreviewed child accepted")
		}
	}
	for name, alter := range map[string]func(*custodydb.AccessGrant){
		"fake parent": func(r *custodydb.AccessGrant) { r.ClusterID = id(output.Target.ClusterID) },
		"scope mismatch": func(r *custodydb.AccessGrant) {
			r.Scope = bytes.Replace(r.Scope, []byte("Inspect"), []byte("Change"), 1)
		},
		"query mismatch": func(r *custodydb.AccessGrant) {
			r.RawQuery = bytes.Replace(r.RawQuery, []byte("Inspect"), []byte("Change"), 1)
		},
		"pool mismatch":     func(r *custodydb.AccessGrant) { r.MaxBytes-- },
		"deadline mismatch": func(r *custodydb.AccessGrant) { r.NotAfter = ts(r.NotAfter.Time.Add(time.Second)) },
		"client mismatch":   func(r *custodydb.AccessGrant) { r.RequesterClient += "other" },
		"capture scope":     func(r *custodydb.AccessGrant) { r.CaptureID = r.ID },
		"result access":     func(r *custodydb.AccessGrant) { r.ResultAccess = []byte(`{}`) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := rawQueryTestRow(t)
			alter(&bad)
			if _, err := grantFromRow(bad); err == nil {
				t.Fatal("changed scope accepted")
			}
		})
	}
}
func TestLegacyGrantRowRetainsNonNullableTarget(t *testing.T) {
	row := policyGrantTestRow(t)
	row.NamespaceUid = pgtype.Text{}
	if _, err := grantFromRow(row); err == nil {
		t.Fatal("policy lost original namespace")
	}
}
