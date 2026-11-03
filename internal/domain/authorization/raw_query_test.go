package authorization

import (
	"errors"
	"math"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

func TestExistingArtifactRawGrantIsDistinctFromCollection(t *testing.T) {
	g := grantFixture(time.Now().UTC())
	g.Kind = "rawQuery"
	if g.Valid() {
		t.Fatal("raw review accepted a fabricated capture scope")
	}
}

func rawQueryFixture(now time.Time) (Grant, VerifiedOutput) {
	g := grantFixture(now)
	output := VerifiedOutput{CaptureID: g.CaptureID, ActionID: "a1", ArtifactID: "00000000-0000-4000-8000-000000000011", ExecutionDigest: g.ExecutionDigest, ArtifactDigest: artifact.Digest{7}, Target: g.Target}
	g.Kind, g.DataClass = GrantRawQuery, "raw"
	g.PreviewID, g.CaptureID, g.Target = "", "", Target{}
	g.RawQuery = &RawQueryScope{CaseID: "00000000-0000-4000-8000-000000000012", Artifacts: []RawQueryArtifact{{Output: output, NativeBytes: 800, ExpiresAt: now.Add(20 * time.Minute)}}, Operations: []string{GrantDownloadOperation}, Reason: "Inspect the saved argument trace", MaxBytes: 1600, MaxOperations: 10, NotAfter: now.Add(30 * time.Minute)}
	return g, output
}

func TestRawQueryExactPublishedMembershipAndClient(t *testing.T) {
	now := time.Now().UTC()
	g, output := rawQueryFixture(now)
	if !g.Valid() {
		t.Fatal("existing-artifact request invalid")
	}
	lead := reviewer(now, "lead", "console", true)
	if err := CheckDecision(g, lead, eligibleFor(lead, now), true, now); err != nil {
		t.Fatal(err)
	}
	self := reviewer(now, "dev", "other-client", true)
	if err := CheckDecision(g, self, eligibleFor(self, now), true, now); !errors.Is(err, ErrSelfApproval) {
		t.Fatal("cross-client self approval", err)
	}
	g.Decision = &GrantDecision{Approved: true, Approver: lead.Principal, Reason: "reviewed exact files", ACR: "mfa", AuthenticatedAt: now.Add(-time.Minute), DecidedAt: now}
	g.ExpiresAt = g.expiryAt(now)
	g.Revision = 2
	if !g.Valid() || !g.ExpiresAt.Equal(g.RawQuery.NotAfter) {
		t.Fatal("original request end lost")
	}
	if err := CheckMaterialize(g, output, "console", false, now); err != nil {
		t.Fatal(err)
	}
	for name, alter := range map[string]func(*VerifiedOutput){
		"version":   func(o *VerifiedOutput) { o.ArtifactDigest[0]++ },
		"capture":   func(o *VerifiedOutput) { o.CaptureID = "00000000-0000-4000-8000-000000000013" },
		"action":    func(o *VerifiedOutput) { o.ActionID = "other" },
		"execution": func(o *VerifiedOutput) { o.ExecutionDigest[0]++ },
		"target":    func(o *VerifiedOutput) { o.Target.PodUID = "replacement" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := output
			alter(&changed)
			if err := CheckMaterialize(g, changed, "console", false, now); !errors.Is(err, ErrGrantScope) {
				t.Fatal("unreviewed output admitted", err)
			}
		})
	}
	if err := CheckMaterialize(g, output, "other-client", false, now); !errors.Is(err, ErrGrantScope) {
		t.Fatal("client expanded", err)
	}
	child := GrantChild{ID: "00000000-0000-4000-8000-000000000014", ParentID: g.ID, ClientID: "console", Output: output, CreatedAt: now}
	caller := reviewer(now, "dev", "console", false)
	if err := CheckResultUse(g, child, caller, GrantDownloadOperation, now); err != nil {
		t.Fatal(err)
	}
	if err := CheckCaptureUse(g, caller, output.CaptureID, output.ExecutionDigest, g.ReviewDigest, now); !errors.Is(err, ErrGrantScope) {
		t.Fatal("disclosure granted collection", err)
	}
	if err := CheckResultUse(g, child, caller, "syscall_query", now); !errors.Is(err, ErrGrantScope) {
		t.Fatal("unimplemented raw operation admitted", err)
	}
	if err := CheckMaterialize(g, output, "console", true, now.Add(20*time.Minute)); !errors.Is(err, ErrGrantScope) {
		t.Fatal("expired output revived", err)
	}
	g.RevokedAt = now
	g.Revoker = lead.Principal
	g.Revision = 3
	if err := CheckResultUse(g, child, caller, GrantDownloadOperation, now); !errors.Is(err, ErrGrantRevoked) {
		t.Fatal("revocation ignored", err)
	}
}

func TestRawQueryScopeAndDisclosurePoolCannotExpand(t *testing.T) {
	now := time.Now().UTC()
	g, output := rawQueryFixture(now)
	for name, alter := range map[string]func(*Grant){
		"fabricated capture":    func(g *Grant) { g.CaptureID = output.CaptureID },
		"representative target": func(g *Grant) { g.Target = output.Target },
		"future result access":  func(g *Grant) { g.ResultAccess = &ResultAccess{} },
		"policy authority":      func(g *Grant) { g.Policy = &PolicyGrantScope{} },
		"unknown size":          func(g *Grant) { g.RawQuery.Artifacts[0].NativeBytes = -1 },
		"too few bytes":         func(g *Grant) { g.RawQuery.MaxBytes = 799 },
		"duplicate artifact":    func(g *Grant) { g.RawQuery.Artifacts = append(g.RawQuery.Artifacts, g.RawQuery.Artifacts[0]) },
		"late expiry":           func(g *Grant) { g.RawQuery.NotAfter = now.Add(GrantMaxLifetime + time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := g
			scope := g.RawQuery.Clone()
			changed.RawQuery = &scope
			alter(&changed)
			if changed.Valid() {
				t.Fatal("expanded or ambiguous raw grant accepted")
			}
		})
	}
	g.Spent.Bytes = 800
	g.Spent.Operations = 1
	if !PoolCovers(g, GrantUse{Bytes: 800, Operations: 1}) || PoolCovers(g, GrantUse{Bytes: 801, Operations: 1}) || PoolCovers(g, GrantUse{Bytes: math.MaxInt64, Operations: 1}) {
		t.Fatal("raw pool overflow or wrong remaining budget")
	}
	if !CanRevoke(g, reviewer(now, "dev", "other-client", false), Result{}, now) {
		t.Fatal("requester cannot revoke through another client")
	}
	copied := g.RawQuery.Clone()
	copied.Artifacts[0].Output.ArtifactDigest[0]++
	copied.Operations[0] = "read_memory"
	if g.RawQuery.Artifacts[0].Output != output || g.RawQuery.Operations[0] != GrantDownloadOperation {
		t.Fatal("clone shared mutable scope")
	}
}

func TestRawQueryPendingExpiresAtOriginalDeadline(t *testing.T) {
	now := time.Now().UTC()
	g, _ := rawQueryFixture(now)
	g.RawQuery.NotAfter = now.Add(time.Second)
	if !g.Valid() {
		t.Fatal("invalid pending fixture")
	}
	if g.Phase(now) != GrantPending {
		t.Fatal("request not pending")
	}
	if got := g.Phase(now.Add(time.Second)); got != GrantExpired {
		t.Fatalf("original deadline: %s", got)
	}
}
