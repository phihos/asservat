package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

func (m *memoryGrants) RawQueryRequest(_ context.Context, p identity.Principal, key string) (StoredGrantRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := p.Issuer + "\n" + p.Subject + "\n" + key
	id, ok := m.keys[k]
	if !ok {
		return StoredGrantRequest{}, ErrGrantNotFound
	}
	return StoredGrantRequest{Grant: m.rows[id], IdempotencyKey: key, RequestDigest: m.policyInputs[k]}, nil
}
func (m *memoryGrants) RawQueryCandidates(_ context.Context, scope artifact.DownloadScope, use value.GrantUse) ([]value.Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []value.Grant
	for _, g := range m.rows {
		if g.Kind != value.GrantRawQuery || g.Requester != scope.Principal || g.Phase(m.now()) != value.GrantApproved || (use.Bytes > 0 || use.Operations > 0) && !value.PoolCovers(g, use) {
			continue
		}
		if _, ok := rawOutputForScope(g, scope, ""); ok {
			out = append(out, g)
		}
	}
	slices.SortFunc(out, func(a, b value.Grant) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	return out, nil
}
func (m *memoryGrants) GrantUseByID(_ context.Context, id string) (GrantUseRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.uses[id]
	if !ok {
		return r, ErrGrantNotFound
	}
	return r, nil
}

type rawSelectionFunc func(context.Context, identities.CurrentIdentity, string, []artifact.Digest) (RawQuerySelection, error)

func (f rawSelectionFunc) ResolveRawQuery(ctx context.Context, i identities.CurrentIdentity, c string, d []artifact.Digest) (RawQuerySelection, error) {
	return f(ctx, i, c, d)
}

func rawQueryFixture(t *testing.T) (*grantFixture, RawQueryRequestInput, *int) {
	f := newGrantFixture(t)
	reads := 0
	f.svc.RawStore = f.store
	f.svc.RawSelections = rawSelectionFunc(func(_ context.Context, _ identities.CurrentIdentity, _ string, digests []artifact.Digest) (RawQuerySelection, error) {
		reads++
		selection := RawQuerySelection{ValidUntil: f.now.Add(5 * time.Second)}
		for _, digest := range digests {
			target := f.target
			target.PodUID = "pod-" + strconv.Itoa(int(digest[0]))
			o := value.VerifiedOutput{CaptureID: grantID(10 + int(digest[0])), ActionID: "arguments", ArtifactID: grantID(20 + int(digest[0])), ExecutionDigest: artifact.Digest{7}, ArtifactDigest: digest, Target: target}
			a := value.RawQueryArtifact{Output: o, NativeBytes: 10, ExpiresAt: f.now.Add(time.Hour)}
			selection.Artifacts = append(selection.Artifacts, a)
			selection.Review = append(selection.Review, RawQueryReviewArtifact{Output: o, NativeBytes: 10, ExpiresAt: a.ExpiresAt, Namespace: "payments", WorkloadKind: "Deployment", WorkloadName: "api", NativeType: artifact.SyscallArgumentsArtifact})
			f.store.locator[o.ArtifactID] = o.CaptureID
		}
		return selection, nil
	})
	in := RawQueryRequestInput{CaseID: grantID(99), ArtifactDigests: []artifact.Digest{{1}, {2}}, Operations: []string{value.GrantDownloadOperation}, Reason: "Inspect saved syscall arguments", MaxBytes: 40, Lifetime: time.Hour, IdempotencyKey: "raw-1"}
	return f, in, &reads
}
func requestRawFixture(t *testing.T, f *grantFixture, in RawQueryRequestInput) value.Grant {
	t.Helper()
	g, replay, err := f.svc.RequestRaw(t.Context(), grantIdentity{f.requester, &f.now}, in)
	if err != nil || replay {
		t.Fatalf("request raw: replay=%v err=%v", replay, err)
	}
	return g
}

func TestRawQueryRequestReplayPreservesOriginalSelectionAndDeadline(t *testing.T) {
	f, in, reads := rawQueryFixture(t)
	g := requestRawFixture(t, f, in)
	if g.CaptureID != "" || g.Target != (value.Target{}) || !RawQueryScopeMatches(g) {
		t.Fatal("invented collection identity")
	}
	var review GrantReview
	if json.Unmarshal(g.Review, &review) != nil || review.RawQuery == nil || review.RawQuery.MaxOperations != value.GrantMaxResultOperations || review.RawQuery.Artifacts[0].WorkloadName != "api" {
		t.Fatal("missing readable, bound review")
	}
	f.now = f.now.Add(time.Minute)
	got, replay, err := f.svc.RequestRaw(t.Context(), grantIdentity{f.requester, &f.now}, in)
	if err != nil || !replay || got.ID != g.ID || !got.RawQuery.NotAfter.Equal(g.RawQuery.NotAfter) || *reads != 1 {
		t.Fatal("replay renewed or reselected", replay, err, *reads)
	}
	changed := in
	changed.MaxBytes++
	if _, _, err = f.svc.RequestRaw(t.Context(), grantIdentity{f.requester, &f.now}, changed); !errors.Is(err, ErrGrantConflict) {
		t.Fatal("changed replay", err)
	}
	other := f.requester
	other.Principal.ClientID = "agent"
	if _, _, err = f.svc.RequestRaw(t.Context(), grantIdentity{other, &f.now}, in); !errors.Is(err, ErrGrantConflict) {
		t.Fatal("client substitution", err)
	}
}

func TestRawQueryReviewRequiresEveryTargetAndDoesNotAliasInbox(t *testing.T) {
	f, in, _ := rawQueryFixture(t)
	g := requestRawFixture(t, f, in)
	original := f.projection
	second := g.RawQuery.Artifacts[1].Output.Target
	f.projection = func(target value.Target) value.Projection {
		p := original(target)
		if target == second {
			p.Allows = p.Allows[:1]
		}
		return p
	}
	if _, _, err := f.svc.Decide(t.Context(), grantIdentity{f.approver, &f.now}, g.ID, true, "approve", "decision"); !errors.Is(err, value.ErrNotApprover) {
		t.Fatal("first target's approval admitted second", err)
	}
	single := in
	single.ArtifactDigests = single.ArtifactDigests[:1]
	single.IdempotencyKey = "one-target"
	only := requestRawFixture(t, f, single)
	rows, _, err := f.svc.List(t.Context(), grantIdentity{f.approver, &f.now}, "pending", 100)
	if err != nil || len(rows) != 1 || rows[0].Grant.ID != only.ID {
		t.Fatal("zero-target cache conflated reviews", rows, err)
	}
	if _, _, err = f.svc.Decide(t.Context(), grantIdentity{f.requester, &f.now}, g.ID, true, "self", "self"); !errors.Is(err, value.ErrSelfApproval) {
		t.Fatal("self approval", err)
	}
	f.projection = original
	approved := f.approve(t, g)
	if !approved.ExpiresAt.Equal(g.RawQuery.NotAfter) {
		t.Fatal("approval renewed original request deadline")
	}
}

func TestRawQueryExactChildAndUseReplayNeverMovesParent(t *testing.T) {
	f, in, _ := rawQueryFixture(t)
	g := f.approve(t, requestRawFixture(t, f, in))
	dev := grantIdentity{f.requester, &f.now}
	o := g.RawQuery.Artifacts[0].Output
	scope := rawDownloadScope(grantRoot, f.requester.Principal, o)
	if _, err := f.svc.CurrentResultAccess(t.Context(), dev, scope, o.ActionID); err != nil {
		t.Fatal(err)
	}
	child, err := f.store.GrantChildFor(t.Context(), g.ID, o.ArtifactID, f.requester.Principal.ClientID)
	if err != nil || child.Output != o || child.Output.ExecutionDigest == g.ExecutionDigest {
		t.Fatal("child used raw parent scope digest", child, err)
	}
	use := value.GrantUse{Operation: value.GrantDownloadOperation, Bytes: 40, Operations: 1}
	useID := grantID(600)
	if err = f.svc.ReserveRawResult(t.Context(), dev, scope, useID, use); err != nil {
		t.Fatal("use selected output target", err)
	}
	in.IdempotencyKey = "second"
	in.MaxBytes = 80
	g2 := f.approve(t, requestRawFixture(t, f, in))
	if err = f.svc.ReserveRawResult(t.Context(), dev, scope, useID, use); err != nil || f.store.rows[g2.ID].Spent.Bytes != 0 || f.store.rows[g.ID].Spent.Bytes != 40 {
		t.Fatal("uncertain spend moved or repeated", err)
	}
	original := f.store.rows[g.ID]
	if _, _, err = f.svc.Revoke(t.Context(), dev, g.ID, original.Revision, "stop"); err != nil {
		t.Fatal(err)
	}
	if err = f.svc.ReserveRawResult(t.Context(), dev, scope, useID, use); !errors.Is(err, value.ErrGrantRevoked) {
		t.Fatal("revoked use moved to newer approval", err)
	}
	if err = f.svc.ReserveRawResult(t.Context(), dev, scope, grantID(601), use); err != nil || f.store.rows[g2.ID].Spent.Bytes != 40 {
		t.Fatal("new use could not select current approval", err)
	}
	wrong := scope
	wrong.Version[0]++
	if err = f.svc.ReserveRawResult(t.Context(), dev, wrong, useID, use); !errors.Is(err, value.ErrGrantScope) {
		t.Fatal("version substituted on replay", err)
	}
}

func TestRawQueryReusesCoveringGrantAndRejectsUnsupportedOperations(t *testing.T) {
	f, in, reads := rawQueryFixture(t)
	g := f.approve(t, requestRawFixture(t, f, in))
	in.IdempotencyKey = "covering"
	got, replay, err := f.svc.RequestRaw(t.Context(), grantIdentity{f.requester, &f.now}, in)
	if err != nil || !replay || got.ID != g.ID || len(f.store.rows) != 1 || *reads != 2 {
		t.Fatal("covering grant not reused", replay, err)
	}
	in.Operations = []string{"read_memory"}
	if _, _, err = f.svc.RequestRaw(t.Context(), grantIdentity{f.requester, &f.now}, in); !errors.Is(err, ErrRawQueryOperationUnsupported) {
		t.Fatal("unimplemented operation", err)
	}
}

func TestRawQuerySixtyFourSelectedArtifactsFitReviewedRequest(t *testing.T) {
	f, in, _ := rawQueryFixture(t)
	in.ArtifactDigests = nil
	in.MaxBytes = 640
	for n := 1; n <= 64; n++ {
		in.ArtifactDigests = append(in.ArtifactDigests, artifact.Digest{byte(n)})
	}
	selected, _ := f.svc.RawSelections.ResolveRawQuery(t.Context(), grantIdentity{f.requester, &f.now}, in.CaseID, in.ArtifactDigests)
	scope := value.RawQueryScope{CaseID: in.CaseID, Artifacts: selected.Artifacts, Operations: in.Operations, Reason: in.Reason, MaxBytes: in.MaxBytes, MaxOperations: value.GrantMaxResultOperations, NotAfter: f.now.Add(in.Lifetime)}
	b, _ := RawQueryScopeBytes(scope)
	review, _ := json.Marshal(GrantReview{RawQuery: &RawQueryReview{CaseID: in.CaseID, Artifacts: selected.Review, Operations: in.Operations, Reason: in.Reason, MaxBytes: in.MaxBytes, MaxOperations: value.GrantMaxResultOperations, NotAfter: scope.NotAfter}, Deadline: scope.NotAfter})
	t.Logf("64 exact artifact scope=%d bytes review=%d bytes", len(b), len(review))
	requestRawFixture(t, f, in)
}

func TestRawQueryPriorUseStillBindsScopePrincipal(t *testing.T) {
	f, in, _ := rawQueryFixture(t)
	g := f.approve(t, requestRawFixture(t, f, in))
	o := g.RawQuery.Artifacts[0].Output
	scope := rawDownloadScope(grantRoot, f.requester.Principal, o)
	dev := grantIdentity{f.requester, &f.now}
	if _, err := f.svc.CurrentResultAccess(t.Context(), dev, scope, o.ActionID); err != nil {
		t.Fatal(err)
	}
	use := value.GrantUse{Operation: value.GrantDownloadOperation, Bytes: 1, Operations: 1}
	if err := f.svc.ReserveRawResult(t.Context(), dev, scope, grantID(700), use); err != nil {
		t.Fatal(err)
	}
	scope.Principal.Subject = "someone-else"
	if err := f.svc.ReserveRawResult(t.Context(), dev, scope, grantID(700), use); !errors.Is(err, value.ErrGrantPrincipal) {
		t.Fatal("prior use ignored scope principal", err)
	}
}

func TestRawQueryConcurrentUsesNeverRefillSharedPool(t *testing.T) {
	f, in, _ := rawQueryFixture(t)
	g := f.approve(t, requestRawFixture(t, f, in))
	o := g.RawQuery.Artifacts[0].Output
	scope := rawDownloadScope(grantRoot, f.requester.Principal, o)
	dev := grantIdentity{f.requester, &f.now}
	if _, err := f.svc.CurrentResultAccess(t.Context(), dev, scope, o.ActionID); err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 8)
	for n := 0; n < 8; n++ {
		go func(n int) {
			results <- f.svc.ReserveRawResult(t.Context(), dev, scope, grantID(800+n), value.GrantUse{Operation: value.GrantDownloadOperation, Bytes: 10, Operations: 1})
		}(n)
	}
	passed := 0
	for n := 0; n < 8; n++ {
		if err := <-results; err == nil {
			passed++
		}
	}
	if passed != 4 || f.store.rows[g.ID].Spent.Bytes != 40 || f.store.rows[g.ID].Spent.Operations != 4 {
		t.Fatal("concurrent shared pool overspent", passed, f.store.rows[g.ID].Spent)
	}
}

func TestRawQuerySixtyFourMaximumNamesAndEscapedUIDsFit(t *testing.T) {
	f, in, _ := rawQueryFixture(t)
	in.ArtifactDigests = nil
	in.MaxBytes = 640
	for n := 1; n <= 64; n++ {
		d := artifact.Digest{}
		for j := range d {
			d[j] = 255
		}
		d[0] = byte(n)
		in.ArtifactDigests = append(in.ArtifactDigests, d)
	}
	original := f.svc.RawSelections
	f.svc.RawSelections = rawSelectionFunc(func(ctx context.Context, current identities.CurrentIdentity, caseID string, digests []artifact.Digest) (RawQuerySelection, error) {
		out, err := original.ResolveRawQuery(ctx, current, caseID, digests)
		if err != nil {
			return out, err
		}
		for n := range out.Artifacts {
			o := &out.Artifacts[n].Output
			o.Target.NamespaceUID = strings.Repeat("\\", 64)
			o.Target.WorkloadUID = strings.Repeat("\"", 64)
			o.Target.PodUID = strings.Repeat("\\", 64)
			for j := range o.ExecutionDigest {
				o.ExecutionDigest[j] = 255
			}
			r := &out.Review[n]
			r.Output = *o
			r.Namespace = strings.Repeat("n", 253)
			r.WorkloadKind = strings.Repeat("K", 64)
			r.WorkloadName = strings.Repeat("w", 253)
			r.PodName = strings.Repeat("p", 253)
		}
		return out, nil
	})
	g := requestRawFixture(t, f, in)
	t.Logf("64 maximum display names and escaped UIDs: scope=%d review=%d", len(g.Scope), len(g.Review))
	if len(g.Scope) > value.GrantMaxScopeBytes || len(g.Review) > value.GrantReviewBytesLimit(g.Kind) {
		t.Fatal("review exceeded bounded serialization")
	}
}
