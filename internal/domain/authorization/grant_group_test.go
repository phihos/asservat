package authorization

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestGrantGroupKeepsActualChildAndOriginalPool(t *testing.T) {
	now := time.Now().UTC()
	g := grantFixture(now)
	g.DataClass = "raw"
	g.ResultAccess = &ResultAccess{ActionIDs: []string{"a1"}, Operations: []string{GrantDownloadOperation, GrantLogQueryOperation}, ClientIDs: []string{"console"}, MaxArtifacts: 1, MaxBytes: 49152, MaxOperations: 2, NotAfter: now.Add(30 * time.Minute)}
	g.ResultAccessDigest = artifact.Digest{3}
	g.Decision = &GrantDecision{Approved: true, Approver: identity.Principal{Issuer: g.Requester.Issuer, Subject: "lead", ClientID: "console", Kind: identity.Human}, Reason: "ok", ACR: "mfa", AuthenticatedAt: now, DecidedAt: now}
	g.ExpiresAt, g.Revision = now.Add(30*time.Minute), 2
	out := VerifiedOutput{CaptureID: "00000000-0000-4000-8000-000000000010", ActionID: "a1", ArtifactID: "00000000-0000-4000-8000-000000000011", ExecutionDigest: artifact.Digest{9}, ArtifactDigest: artifact.Digest{10}, Target: g.Target}
	group := GrantOutputGroup{RootID: g.RootID, ParentCaptureID: g.CaptureID, ParentExecutionDigest: g.ExecutionDigest, CaptureID: out.CaptureID, ExecutionDigest: out.ExecutionDigest, ArtifactID: out.ArtifactID, ArtifactDigest: out.ArtifactDigest, ActionID: out.ActionID, ChildIndex: 1, ChildCount: 2}
	if err := CheckMaterialize(g, out, "console", false, now); !errors.Is(err, ErrGrantScope) {
		t.Fatal("unassociated child admitted", err)
	}
	if err := CheckMaterialize(g, out, "console", false, now, &group); err != nil {
		t.Fatal("exact group child refused", err)
	}
	child := GrantChild{ID: "00000000-0000-4000-8000-000000000012", ParentID: g.ID, ClientID: "console", Output: out, Group: &group, CreatedAt: now}
	caller := reviewer(now, "dev", "console", false)
	if err := CheckResultUse(g, child, caller, GrantLogQueryOperation, now); err != nil {
		t.Fatal(err)
	}
	if child.Output.CaptureID == g.CaptureID || child.Output.ExecutionDigest == g.ExecutionDigest {
		t.Fatal("parent relabeled as native child")
	}
	for name, change := range map[string]func(*GrantOutputGroup){"root": func(a *GrantOutputGroup) { a.RootID = out.ArtifactID }, "parent": func(a *GrantOutputGroup) { a.ParentCaptureID = out.ArtifactID }, "parent-scope": func(a *GrantOutputGroup) { a.ParentExecutionDigest[0]++ }, "child": func(a *GrantOutputGroup) { a.CaptureID = g.CaptureID }, "child-scope": func(a *GrantOutputGroup) { a.ExecutionDigest[0]++ }, "version": func(a *GrantOutputGroup) { a.ArtifactDigest[0]++ }, "action": func(a *GrantOutputGroup) { a.ActionID = "a2" }, "index": func(a *GrantOutputGroup) { a.ChildIndex = a.ChildCount }} {
		bad := group
		change(&bad)
		if CheckMaterialize(g, out, "console", true, now, &bad) == nil {
			t.Fatal("wrong association admitted", name)
		}
	}
	body, _ := json.Marshal(child)
	var decoded GrantChild
	if json.Unmarshal(body, &decoded) != nil || decoded.Group != nil || CheckResultUse(g, decoded, caller, GrantLogQueryOperation, now) == nil {
		t.Fatal("ephemeral association round-tripped over wire")
	}
	g.Spent.Bytes, g.Spent.Operations = 49152, 2
	if PoolCovers(g, GrantUse{Operation: GrantLogQueryOperation, Bytes: 1, Operations: 1}) {
		t.Fatal("group association refilled shared pool")
	}
	g.RevokedAt = now
	g.Revoker = g.Decision.Approver
	g.Revision++
	if CheckResultUse(g, child, caller, GrantLogQueryOperation, now) == nil {
		t.Fatal("revocation ignored")
	}
}
