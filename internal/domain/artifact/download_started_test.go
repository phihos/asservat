package artifact

import (
	"testing"
	"time"
)

// ADR-312: a started response continues its original decision as short
// leases, up to its original bounds; it cannot start another response.
func TestStartedDownloadContinuesToOriginalBounds(t *testing.T) {
	s, a, r, n := responseFixture(t, 2*DownloadWindowBytes)
	later := n.Add(10 * time.Minute)
	c, ok := a.Continue(later, r.Until)
	if !ok || !c.Started() || !c.StartedAt.Equal(a.CheckedAt) || !c.CheckedAt.Equal(later) || !c.ValidUntil.Equal(later.Add(DownloadLease)) || c.DecisionDigest != a.DecisionDigest || c.PermissionSequence != a.PermissionSequence {
		t.Fatal("continuation did not restate the original decision", c, ok)
	}
	again, ok := c.Continue(later.Add(time.Minute), r.Until)
	if !ok || !again.StartedAt.Equal(a.CheckedAt) {
		t.Fatal("second continuation lost the original start", again)
	}
	if _, _, w, e := r.BeginWindow(s, c, "10000000-0000-4000-8000-000000000099", s.ID, r.Until.Add(time.Minute), later); e != nil || !w.Authority.Started() {
		t.Fatal("window refused a continuation", e)
	}
	if _, _, e := s.BeginResponse(c, r, later); e == nil {
		t.Fatal("continuation started a new response")
	}
	near := a.AccessUntil.Add(-time.Second)
	if c, ok = a.Continue(near, a.AccessUntil.Add(time.Hour)); !ok || !c.ValidUntil.Equal(a.AccessUntil) {
		t.Fatal("continuation lease passed AccessUntil", c.ValidUntil)
	}
	for name, at := range map[string]time.Time{"access": a.AccessUntil, "response": r.Until, "before-start": n.Add(-time.Second)} {
		until := r.Until
		if name == "access" {
			until = a.AccessUntil.Add(time.Hour)
		}
		if _, ok := a.Continue(at, until); ok {
			t.Fatal("continuation outlived its original bound", name)
		}
	}
	// Only response windows/leases accept a continuation; a batch start never.
	prep, a2, n2 := downloadFixture()
	cont, _ := a2.Continue(n2.Add(time.Second), prep.Deadline)
	if _, err := prep.Start(cont, DownloadBatch{ID: prep.ID, Purpose: DownloadMetadata, ReadBytes: 2 << 20}, n2.Add(time.Second)); err == nil {
		t.Fatal("continuation started a batch")
	}
	if _, err := prep.Start(a2, DownloadBatch{ID: prep.ID, Purpose: DownloadMetadata, ReadBytes: 2 << 20}, n2.Add(time.Second)); err != nil {
		t.Fatal("complete check refused a batch", err)
	}
	// A forged continuation that claims a later start than its check is invalid.
	c.StartedAt = c.CheckedAt.Add(time.Second)
	if c.Valid(c.CheckedAt) {
		t.Fatal("continuation started after its own check")
	}
}
