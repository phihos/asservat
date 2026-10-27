package authorization

import (
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

func grantFixture(now time.Time) Grant {
	requester := identity.Principal{Issuer: "https://id.example.invalid", Subject: "dev", ClientID: "console", Kind: identity.Human}
	return Grant{ID: "00000000-0000-4000-8000-000000000001", RootID: "00000000-0000-4000-8000-000000000002", Kind: GrantAdHocCapture,
		PreviewID: "00000000-0000-4000-8000-000000000003", CaptureID: "00000000-0000-4000-8000-000000000004",
		Target:          Target{ClusterID: "00000000-0000-4000-8000-000000000005", NamespaceUID: "ns", WorkloadUID: "w", PodUID: "p"},
		ExecutionDigest: artifact.Digest{1}, ReviewDigest: artifact.Digest{2}, DataClass: "extract", Reasons: []SensitiveReason{{"a1", "rawBytePredicate"}},
		Scope: []byte("{}"), Review: []byte("{}"), Requester: requester, RequestedAt: now, ReviewUntil: now.Add(GrantReviewWindow), Lifetime: GrantDefaultLifetime, Revision: 1}
}

func reviewer(now time.Time, subject, client string, stepped bool) identity.Identity {
	i := identity.Identity{Principal: identity.Principal{Issuer: "https://id.example.invalid", Subject: subject, ClientID: client, Kind: identity.Human}, Scopes: []string{"evidence:read"}, Policy: identity.Revision{UID: "p", Generation: 1, Digest: [32]byte{1}}, VerifiedAt: now, ValidUntil: now.Add(30 * time.Second)}
	if stepped {
		i.Assurance = identity.Assurance{ACR: "mfa", AuthenticatedAt: now.Add(-time.Minute), StepUpUntil: now.Add(time.Minute)}
	}
	return i
}

func eligibleFor(i identity.Identity, now time.Time) Result {
	return Result{Eligible: true, Principal: i.Principal, ValidUntil: now.Add(10 * time.Second)}
}

// The ADR-249 evaluator matrix on the pure rules.
func TestGrantEvaluatorMatrix(t *testing.T) {
	now := time.Now().UTC()
	g := grantFixture(now)
	if !g.Valid() || g.Phase(now) != GrantPending {
		t.Fatal("fixture")
	}
	lead := reviewer(now, "lead", "console", true)
	for name, tc := range map[string]struct {
		g        Grant
		who      identity.Identity
		eligible Result
		approve  bool
		want     error
	}{
		"self through another client": {g, reviewer(now, "dev", "agent", true), eligibleFor(reviewer(now, "dev", "agent", true), now), true, ErrSelfApproval},
		"self deny":                   {g, reviewer(now, "dev", "console", false), eligibleFor(reviewer(now, "dev", "console", false), now), false, ErrSelfApproval},
		"no approver role":            {g, lead, Result{}, true, ErrNotApprover},
		"stale role":                  {g, lead, Result{Eligible: true, Principal: lead.Principal, ValidUntil: now}, true, ErrNotApprover},
		"no step-up":                  {g, reviewer(now, "lead", "console", false), eligibleFor(lead, now), true, ErrStepUpRequired},
		"deny without step-up":        {g, reviewer(now, "lead", "console", false), eligibleFor(lead, now), false, nil},
		"approve":                     {g, lead, eligibleFor(lead, now), true, nil},
		"review window over":          {func() Grant { x := g; x.RequestedAt, x.ReviewUntil = now.Add(-GrantReviewWindow), now; return x }(), lead, eligibleFor(lead, now), true, ErrGrantNotPending},
		"revoked request":             {func() Grant { x := g; x.RevokedAt, x.Revoker, x.Revision = now, g.Requester, 2; return x }(), lead, eligibleFor(lead, now), true, ErrGrantNotPending},
		"workload identity":           {g, func() identity.Identity { x := lead; x.Principal.Kind = identity.Workload; return x }(), eligibleFor(lead, now), true, ErrNotApprover},
	} {
		t.Run(name, func(t *testing.T) {
			if err := CheckDecision(tc.g, tc.who, tc.eligible, tc.approve, now); !errors.Is(err, tc.want) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
		})
	}
	approved := g
	approved.Decision = &GrantDecision{Approved: true, Approver: lead.Principal, Reason: "ok", ACR: "mfa", AuthenticatedAt: now.Add(-time.Minute), DecidedAt: now}
	approved.ExpiresAt, approved.Revision = now.Add(GrantDefaultLifetime), 2
	if !approved.Valid() || approved.Phase(now) != GrantApproved {
		t.Fatal("approved fixture")
	}
	self := approved
	self.Decision = &GrantDecision{Approved: true, Approver: identity.Principal{Issuer: g.Requester.Issuer, Subject: g.Requester.Subject, ClientID: "agent", Kind: identity.Human}, Reason: "ok", ACR: "mfa", AuthenticatedAt: now, DecidedAt: now}
	if self.Valid() {
		t.Fatal("a self-approved row is valid")
	}
	dev := reviewer(now, "dev", "console", false)
	for name, tc := range map[string]struct {
		g         Grant
		who       identity.Identity
		capture   string
		execution artifact.Digest
		at        time.Time
		want      error
	}{
		"covers":  {approved, dev, g.CaptureID, g.ExecutionDigest, now, nil},
		"pending": {g, dev, g.CaptureID, g.ExecutionDigest, now, ErrApprovalRequired},
		"expired": {approved, reviewer(approved.ExpiresAt, "dev", "console", false), g.CaptureID, g.ExecutionDigest, approved.ExpiresAt, ErrGrantExpired},
		"revoked": {func() Grant { x := approved; x.RevokedAt, x.Revoker, x.Revision = now, lead.Principal, 3; return x }(), dev, g.CaptureID, g.ExecutionDigest, now, ErrGrantRevoked},
		"denied": {func() Grant {
			x := approved
			d := *x.Decision
			d.Approved = false
			x.Decision, x.ExpiresAt = &d, time.Time{}
			return x
		}(), dev, g.CaptureID, g.ExecutionDigest, now, ErrGrantDenied},
		"digest mismatch":    {approved, dev, g.CaptureID, artifact.Digest{9}, now, ErrGrantScope},
		"another capture":    {approved, dev, "00000000-0000-4000-8000-000000000099", g.ExecutionDigest, now, ErrGrantScope},
		"another client":     {approved, reviewer(now, "dev", "agent", false), g.CaptureID, g.ExecutionDigest, now, ErrGrantPrincipal},
		"another requester":  {approved, lead, g.CaptureID, g.ExecutionDigest, now, ErrGrantPrincipal},
		"invalid stored row": {func() Grant { x := approved; x.Lifetime = 9 * time.Hour; return x }(), dev, g.CaptureID, g.ExecutionDigest, now, ErrGrantInvalid},
	} {
		t.Run(name, func(t *testing.T) {
			if err := CheckCaptureUse(tc.g, tc.who, tc.capture, tc.execution, g.ReviewDigest, tc.at); !errors.Is(err, tc.want) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
		})
	}
}

func TestGrantPoolAndChildRules(t *testing.T) {
	now := time.Now().UTC()
	g := grantFixture(now)
	g.ResultAccess = &ResultAccess{ActionIDs: []string{"a1"}, Operations: []string{GrantDownloadOperation}, ClientIDs: []string{"agent", "console"}, MaxArtifacts: 1, MaxBytes: 10, MaxOperations: 2, NotAfter: now.Add(30 * time.Minute)}
	g.ResultAccessDigest = artifact.Digest{3}
	g.Decision = &GrantDecision{Approved: true, Approver: identity.Principal{Issuer: g.Requester.Issuer, Subject: "lead", ClientID: "console", Kind: identity.Human}, Reason: "ok", ACR: "mfa", AuthenticatedAt: now, DecidedAt: now}
	g.ExpiresAt, g.Revision = now.Add(30*time.Minute), 2
	if !g.Valid() {
		t.Fatal("NotAfter must cap the approved expiry")
	}
	out := VerifiedOutput{CaptureID: g.CaptureID, ActionID: "a1", ArtifactID: "00000000-0000-4000-8000-000000000010", ExecutionDigest: g.ExecutionDigest, ArtifactDigest: artifact.Digest{4}, Target: g.Target}
	if err := CheckMaterialize(g, out, "console", false, now); err != nil {
		t.Fatal(err)
	}
	g.Spent.Artifacts = 1
	if err := CheckMaterialize(g, out, "agent", true, now); err != nil {
		t.Fatal("registered artifact for a second client", err)
	}
	if err := CheckMaterialize(g, out, "agent", false, now); !errors.Is(err, ErrGrantPoolExhausted) {
		t.Fatal("max artifacts", err)
	}
	if err := CheckMaterialize(g, out, "cli", true, now); !errors.Is(err, ErrGrantScope) {
		t.Fatal("unlisted client", err)
	}
	child := GrantChild{ID: "00000000-0000-4000-8000-000000000011", ParentID: g.ID, ClientID: "agent", Output: out, CreatedAt: now}
	agent := reviewer(now, "dev", "agent", false)
	if err := CheckResultUse(g, child, agent, GrantDownloadOperation, now); err != nil {
		t.Fatal(err)
	}
	if err := CheckResultUse(g, child, reviewer(now, "dev", "console", false), GrantDownloadOperation, now); !errors.Is(err, ErrGrantPrincipal) {
		t.Fatal("another client of the same human used the child", err)
	}
	if err := CheckResultUse(g, child, agent, "read_memory", now); !errors.Is(err, ErrGrantScope) {
		t.Fatal("broadened operation", err)
	}
	if !PoolCovers(g, GrantUse{Operation: GrantDownloadOperation, Bytes: 10, Operations: 2}) || PoolCovers(g, GrantUse{Operation: GrantDownloadOperation, Bytes: 11, Operations: 1}) || PoolCovers(g, GrantUse{Operation: GrantDownloadOperation}) {
		t.Fatal("pool arithmetic")
	}
	g.Spent.Bytes = 10
	if PoolCovers(g, GrantUse{Operation: GrantDownloadOperation, Bytes: 1}) {
		t.Fatal("exhausted pool covers")
	}
	if err := CheckResultUse(g, child, agent, GrantDownloadOperation, g.ExpiresAt); !errors.Is(err, ErrGrantExpired) {
		t.Fatal("expired parent", err)
	}
}
