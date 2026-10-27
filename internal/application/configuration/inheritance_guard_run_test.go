package configuration

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/configuration"
)

type guardFixture struct {
	proof value.NamespaceGuardProof
	err   error
	calls int
}

func (g *guardFixture) NamespaceGuard(context.Context, string) (value.NamespaceGuardProof, error) {
	g.calls++
	return g.proof, g.err
}

// The reconciler fetches guard proofs before acceptance and treats a lost
// proof as an unavailable source (kept, granting nothing).
func TestReconcilerRefreshesGuardEvidence(t *testing.T) {
	f, _, s, ctx := inheritanceRun(t)
	if err := s.namespaceItem(ctx, nextNamespaceItem(t, s)); err != nil {
		t.Fatal(err)
	}
	guarded := inheritanceSource()
	guarded.Protection = value.Protection{Mode: "admissionEnforced", ReviewRef: "platform-review", GuardRef: "namespace-guard"}
	now := s.r.Now()
	g := &guardFixture{proof: value.NamespaceGuardProof{ClusterID: inheritanceCluster, Name: "namespace-guard", LabelKeys: []string{"managed"}, AnnotationKeys: []string{"owner"}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}}
	s.r.Guards, s.sources = g, []value.Source{guarded}
	s.refreshEvidence(ctx)
	if err := s.accept(ctx, false); err != nil {
		t.Fatal(err)
	}
	if owners, _ := inheritedOwners(f.accepted[len(f.accepted)-1]); len(owners) != 2 || g.calls != 1 {
		t.Fatalf("guarded source not granted with a current proof: %v calls=%d", owners, g.calls)
	}
	g.err, s.guards = errors.New("guard lost"), nil
	s.refreshEvidence(ctx)
	if err := s.accept(ctx, false); err != nil {
		t.Fatal(err)
	}
	if b := f.accepted[len(f.accepted)-1]; func() bool { o, _ := inheritedOwners(b); return len(o) != 0 }() || !slices.Equal(b.UnavailableSources, []string{"source"}) {
		t.Fatalf("lost guard still granted: %+v", b)
	}
}
