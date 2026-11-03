package authorization

import (
	"context"
	"slices"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
)

func TestRawQueryReuseRequiresOneOperationPerSelectedFile(t *testing.T) {
	for _, count := range []int{2, 64} {
		for _, enough := range []bool{false, true} {
			f, in, _ := rawQueryFixture(t)
			in.ArtifactDigests = nil
			in.MaxBytes = int64(count) * 10
			for n := 1; n <= count; n++ {
				in.ArtifactDigests = append(in.ArtifactDigests, artifact.Digest{byte(n)})
			}
			g := f.approve(t, requestRawFixture(t, f, in))
			remaining := int64(count)
			if !enough {
				remaining--
			}
			g.Spent.Operations = g.RawQuery.MaxOperations - remaining
			f.store.rows[g.ID] = g
			in.IdempotencyKey = "reuse"
			got, reused, err := f.svc.RequestRaw(t.Context(), grantIdentity{f.requester, &f.now}, in)
			if err != nil || reused != enough || (got.ID == g.ID) != enough {
				t.Errorf("files=%d remaining operations=%d: reused=%v same=%v err=%v", count, remaining, reused, got.ID == g.ID, err)
			}
		}
	}
}

func TestRawQueryReusePreservesRequestedBytePool(t *testing.T) {
	f, in, _ := rawQueryFixture(t)
	g := f.approve(t, requestRawFixture(t, f, in))
	// Twenty bytes cover the two files once, but do not cover the forty-byte
	// pool the human selected. Reuse must not silently reduce that pool.
	g.Spent.Bytes = 20
	f.store.rows[g.ID] = g
	in.IdempotencyKey = "reuse-bytes"
	got, reused, err := f.svc.RequestRaw(t.Context(), grantIdentity{f.requester, &f.now}, in)
	if err != nil || reused || got.ID == g.ID {
		t.Fatal("reused insufficient requested byte pool", reused, err)
	}
}

func TestRawQueryLegacyReuseRequiresSelectedArtifactCapacity(t *testing.T) {
	f := newGrantFixture(t)
	f.svc.RawStore = f.store
	in := f.input(10, f.access())
	in.DataClass = "raw"
	g, _, err := f.svc.Request(t.Context(), grantIdentity{f.requester, &f.now}, in)
	if err != nil {
		t.Fatal(err)
	}
	g = f.approve(t, g)
	selection := value.RawQueryScope{CaseID: grantID(99), Operations: []string{value.GrantDownloadOperation}, Reason: "Inspect both saved files", MaxBytes: 20, MaxOperations: value.GrantMaxResultOperations, NotAfter: f.now.Add(time.Hour)}
	for n := 1; n <= 2; n++ {
		selection.Artifacts = append(selection.Artifacts, value.RawQueryArtifact{Output: value.VerifiedOutput{CaptureID: g.CaptureID, ActionID: "a1", ArtifactID: grantID(20 + n), ExecutionDigest: g.ExecutionDigest, ArtifactDigest: artifact.Digest{byte(n)}, Target: g.Target}, NativeBytes: 10, ExpiresAt: f.now.Add(time.Hour)})
	}
	if !selection.Valid(f.now) {
		t.Fatal("invalid selection fixture")
	}
	if _, covered, err := f.svc.coveringRawSelection(t.Context(), f.requester, selection); err != nil || covered {
		t.Fatal("one-artifact collection grant covered two different files", covered, err)
	}
}

func TestRawQueryLegacyReuseCountsOnlySelectedRegisteredArtifacts(t *testing.T) {
	for _, tc := range []struct {
		name       string
		max, spent int
		children   []int
		clients    []string
		covered    bool
	}{
		{"free capacity", 2, 0, nil, nil, true},
		{"one existing selected", 3, 2, []int{1, 3}, []string{"agent", "console"}, true},
		{"both existing across clients", 2, 2, []int{1, 2}, []string{"agent", "console"}, true},
		{"only hidden files", 2, 2, []int{3, 4}, []string{"console", "agent"}, false},
		{"one hidden file", 2, 2, []int{1, 3}, []string{"console", "agent"}, false},
		{"same file two clients", 2, 2, []int{1, 1}, []string{"console", "agent"}, false},
		{"unreviewed client", 2, 2, []int{1, 2}, []string{"console", "unreviewed"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newGrantFixture(t)
			counted := &countingRawRegistrations{RawQueryGrantStore: f.store}
			f.svc.RawStore = counted
			access := f.access()
			access.MaxArtifacts = tc.max
			in := f.input(10, access)
			in.DataClass = "raw"
			g, _, err := f.svc.Request(t.Context(), grantIdentity{f.requester, &f.now}, in)
			if err != nil {
				t.Fatal(err)
			}
			g = f.approve(t, g)
			g.Spent.Artifacts = tc.spent
			f.store.rows[g.ID] = g
			output := func(n int) value.VerifiedOutput {
				return value.VerifiedOutput{CaptureID: g.CaptureID, ActionID: "a1", ArtifactID: grantID(20 + n), ExecutionDigest: g.ExecutionDigest, ArtifactDigest: artifact.Digest{byte(n)}, Target: g.Target}
			}
			for n, id := range tc.children {
				child := value.GrantChild{ID: grantID(500 + n), ParentID: g.ID, ClientID: tc.clients[n], Output: output(id), CreatedAt: f.now}
				f.store.children[child.ID] = child
			}
			selection := value.RawQueryScope{CaseID: grantID(99), Operations: []string{value.GrantDownloadOperation}, Reason: "Inspect two files", MaxBytes: 20, MaxOperations: value.GrantMaxResultOperations, NotAfter: f.now.Add(time.Hour)}
			for n := 1; n <= 2; n++ {
				selection.Artifacts = append(selection.Artifacts, value.RawQueryArtifact{Output: output(n), NativeBytes: 10, ExpiresAt: f.now.Add(time.Hour)})
			}
			if _, covered, err := f.svc.coveringRawSelection(t.Context(), f.requester, selection); err != nil || covered != tc.covered {
				t.Fatal("selected registered capacity", covered, err)
			}
			wantReads := 1
			if tc.max-tc.spent >= len(selection.Artifacts) {
				wantReads = 0
			}
			if counted.calls != wantReads {
				t.Fatalf("registration reads=%d, want %d", counted.calls, wantReads)
			}
		})
	}
}

func (m *memoryGrants) CountRegisteredGrantArtifacts(_ context.Context, parent string, ids []string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g := m.rows[parent]
	registered := map[string]bool{}
	if g.Kind != value.GrantAdHocCapture || g.ResultAccess == nil {
		return 0, nil
	}
	for _, c := range m.children {
		if c.ParentID == parent && slices.Contains(ids, c.Output.ArtifactID) && slices.Contains(g.ResultAccess.ClientIDs, c.ClientID) {
			registered[c.Output.ArtifactID] = true
		}
	}
	return len(registered), nil
}

type countingRawRegistrations struct {
	RawQueryGrantStore
	calls int
}

func (c *countingRawRegistrations) CountRegisteredGrantArtifacts(ctx context.Context, parent string, ids []string) (int, error) {
	c.calls++
	return c.RawQueryGrantStore.CountRegisteredGrantArtifacts(ctx, parent, ids)
}
