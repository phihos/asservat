package integration

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
	"github.com/jackc/pgx/v5/pgxpool"
)

func qualifyProcessingDiscovery(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, s captureAdmissionScenario, f *processingTestFixture, first, second artifact.ContextExpectation, publishSecond func()) {
	t.Helper()
	const password = "synthetic-processing-discovery"
	role := narrowRole(t, ctx, admin, "processing_discovery_", password, func(name string) []string {
		grants, ok := postgres.PublicRuntimeRoleGrantSQL("hub-runtime", name)
		if !ok {
			t.Fatal("compiled hub discovery grants")
		}
		return grants
	})
	pool := poolFor(role, password)
	defer pool.Close()
	reader, err := postgres.NewProcessingInventory(ctx, pool, s.a.RootID, s.recovery.guard)
	if err != nil {
		t.Fatal("compiled discovery constructor", err)
	}
	authority := func() value.ProcessingAuthority {
		t.Helper()
		started := time.Now().UTC().Truncate(time.Microsecond)
		i, err := f.actor.ResolveIdentity(ctx)
		if err != nil {
			t.Fatal("discovery fixture identity", err)
		}
		p, err := f.policy.DownloadPolicy(ctx)
		if err != nil {
			t.Fatal("discovery fixture policy", err)
		}
		r, err := s.recovery.reader.RecoveryState(ctx)
		if err != nil {
			t.Fatal("discovery fixture recovery", err)
		}
		return value.ProcessingAuthority{Identity: i, Policy: p, Recovery: r, ObservedAt: started, ValidUntil: identity.Earlier(started.Add(5*time.Second), identity.Earlier(i.ValidUntil, identity.Earlier(p.FreshUntil, r.FreshUntil)))}
	}
	read := func(q value.ProcessingDiscoveryQuery) value.ProcessingDiscoveryPage {
		t.Helper()
		out, err := reader.ReadProcessingDiscovery(ctx, authority(), q)
		if err != nil || out.RootID != s.a.RootID || !out.Valid(q, time.Now()) {
			t.Fatal("compiled-role evidence discovery", out, err)
		}
		return out
	}
	q := value.ProcessingDiscoveryQuery{CaseID: first.CaseID, Limit: 1}
	page := read(q)
	if len(page.Candidates) != 1 || page.Next.ArtifactID != "" {
		t.Fatal("unpublished evidence entered discovery", page)
	}
	r := page.Candidates[0]
	if r.ArtifactID != first.Registration.Location.ArtifactID || r.CaptureID != first.CaptureUID || r.CaseID != first.CaseID || r.PurposeRef != first.PurposeRef || r.CustodyState != artifact.StoredUnpublished ||
		r.Origin != "capture" || r.Parents == nil || len(r.Parents) != 0 || r.NativeType != "podStatus" || r.DataClass != "metadata" ||
		!r.AnchorAt.Equal(first.Registration.AnchorAt) || !r.ExpiresAt.Equal(first.Registration.ExpiresAt) || !r.DeleteBy.Equal(first.Registration.DeleteBy) {
		t.Fatal("discovery lost verified identity, lineage or custody dates", r)
	}
	publishSecond()
	if !first.Registration.AnchorAt.Equal(second.Registration.AnchorAt) || first.CaseID != second.CaseID {
		t.Fatal("discovery fixtures do not share case and acquisition anchor")
	}
	low, high := first.Registration.Location.ArtifactID, second.Registration.Location.ArtifactID
	if low > high {
		low, high = high, low
	}
	page = read(q)
	if len(page.Candidates) != 1 || page.Candidates[0].ArtifactID != low || page.Next != (value.ProcessingDiscoveryCursor{ArtifactID: low}) {
		t.Fatal("case discovery cursor", page)
	}
	q.After = page.Next
	page = read(q)
	if len(page.Candidates) != 1 || page.Candidates[0].ArtifactID != high || page.Next.ArtifactID != "" {
		t.Fatal("case discovery continuation", page)
	}
	q = value.ProcessingDiscoveryQuery{ClusterID: first.Registration.Location.ClusterID, NamespaceUID: first.NamespaceUID, WorkloadUID: first.WorkloadUID,
		AcquiredFrom: first.Registration.AnchorAt, AcquiredUntil: first.Registration.AnchorAt.Add(time.Microsecond), PurposeRef: first.PurposeRef, Limit: 1}
	page = read(q)
	if len(page.Candidates) != 1 || page.Candidates[0].ArtifactID != low || page.Next.ArtifactID != low || !page.Next.AnchorAt.Equal(q.AcquiredFrom) {
		t.Fatal("workload discovery tie at inclusive lower time bound", page)
	}
	q.After = page.Next
	page = read(q)
	if len(page.Candidates) != 1 || page.Candidates[0].ArtifactID != high || page.Next.ArtifactID != "" {
		t.Fatal("workload discovery cursor skipped equal-anchor artifact", page)
	}
	q.After = value.ProcessingDiscoveryCursor{}
	q.PurposeRef = first.PurposeRef + "-missing"
	page = read(q)
	if len(page.Candidates) != 0 || page.Next.ArtifactID != low {
		t.Fatal("sparse purpose ended discovery at empty page", page)
	}
	q.After = page.Next
	page = read(q)
	if len(page.Candidates) != 0 || page.Next.ArtifactID != "" {
		t.Fatal("sparse purpose continuation did not end", page)
	}
	q.After = value.ProcessingDiscoveryCursor{}
	q.PurposeRef = ""
	q.AcquiredFrom, q.AcquiredUntil = q.AcquiredFrom.Add(-time.Microsecond), q.AcquiredFrom
	if page = read(q); len(page.Candidates) != 0 || page.Next.ArtifactID != "" {
		t.Fatal("discovery included exclusive upper time bound", page)
	}
	q = value.ProcessingDiscoveryQuery{CaseID: first.CaseID, Limit: 1}
	for _, mode := range []string{"source", "recovery"} {
		a := authority()
		if mode == "source" {
			a.Policy.Revision.UID = custodyID()
		} else {
			a.Recovery.Revision.Digest[0]++
		}
		if page, err = reader.ReadProcessingDiscovery(ctx, a, q); err == nil || len(page.Candidates) != 0 {
			t.Fatal("discovery bypassed SQL authority fence", mode, page, err)
		}
	}
}
