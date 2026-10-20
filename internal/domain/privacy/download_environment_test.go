package privacy

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"fmt"
	"testing"
	"time"
)

func processingID(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }
func downloadPolicyFixture() (DownloadPolicy, identity.Principal, time.Time) {
	n := time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC)
	rev := identity.Revision{UID: processingID(2), Generation: 1, Digest: artifact.Digest{1}}
	path := DownloadPath{ID: processingID(3), TargetClusterID: processingID(4), StoreID: processingID(5), StorageRegion: "storage", AcquisitionClusterID: processingID(6), AcquisitionRegion: "acquisition", ConnectorClusterID: processingID(6), ConnectorRegion: "connector", HubClusterID: processingID(7), HubRegion: "hub", WorkerConfiguration: rev, HubConfiguration: rev}
	a := identity.Principal{Issuer: "https://id.example.test", Subject: "developer", ClientID: "browser", Kind: identity.Human}
	p := DownloadPolicy{RootID: processingID(1), InstallationID: processingID(1), RecoveryEpoch: processingID(8), Revision: rev, ProtectionDigest: artifact.Digest{2}, PermittedRegions: []string{"storage", "acquisition", "connector", "hub"}, Paths: []DownloadPath{path}, Clients: []DownloadClient{{Issuer: a.Issuer, ID: a.ClientID, Kind: a.Kind, DataClasses: []string{"metadata"}, PrivacyClasses: []string{"potentialPersonalData"}, EvidenceTypes: []string{"context"}, Purposes: []string{"diagnostics"}, PathIDs: []string{path.ID}}}, Operators: []ProcessingOperator{{Issuer: a.Issuer, ClientID: a.ClientID, Kind: "Group", ID: "privacy-operators"}}, ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}
	return p, a, n
}

func TestDownloadPolicyRequiresEveryActualProcessorAndExplicitClient(t *testing.T) {
	p, a, n := downloadPolicyFixture()
	selectPath := func(p DownloadPolicy, a identity.Principal) bool {
		_, ok := p.Select(a, p.Paths[0].TargetClusterID, p.Paths[0].StoreID, "diagnostics", "metadata", "potentialPersonalData", "context", n)
		return ok
	}
	if !selectPath(p, a) {
		t.Fatal("explicit complete path denied")
	}
	for _, excluded := range p.PermittedRegions {
		q := p
		q.PermittedRegions = nil
		for _, r := range p.PermittedRegions {
			if r != excluded {
				q.PermittedRegions = append(q.PermittedRegions, r)
			}
		}
		if selectPath(q, a) {
			t.Fatalf("unapproved %s processor granted", excluded)
		}
	}
	for _, modify := range []func(*identity.Principal){func(x *identity.Principal) { x.ClientID = "mcp" }, func(x *identity.Principal) { x.Issuer = "https://other.example.test" }, func(x *identity.Principal) { x.Kind = identity.Workload }} {
		b := a
		modify(&b)
		if selectPath(p, b) {
			t.Fatal("authentication alone became client disclosure approval")
		}
	}
	q := p
	q.Clients = []DownloadClient{}
	if selectPath(q, a) {
		t.Fatal("empty client list allowed")
	}
	q = p
	q.Clients = nil
	if q.Valid(n) {
		t.Fatal("missing client decision became empty explicit policy")
	}
	q = p
	q.Suspended = true
	if selectPath(q, a) {
		t.Fatal("suspended policy allowed")
	}
	if _, ok := p.Select(a, p.Paths[0].TargetClusterID, p.Paths[0].StoreID, "diagnostics", "metadata", "potentialPersonalData", "context", p.FreshUntil); ok {
		t.Fatal("expired source allowed")
	}
}

func TestDownloadPolicyDoesNotChooseAmbiguousOrDifferentDataPaths(t *testing.T) {
	p, a, n := downloadPolicyFixture()
	x := p.Paths[0]
	x.ID = processingID(50)
	p.Paths = append(p.Paths, x)
	p.Clients[0].PathIDs = append(p.Clients[0].PathIDs, x.ID)
	if _, ok := p.Select(a, x.TargetClusterID, x.StoreID, "diagnostics", "metadata", "potentialPersonalData", "context", n); ok {
		t.Fatal("ambiguous path selected")
	}
	p, a, n = downloadPolicyFixture()
	for _, data := range []string{"raw", "approvedExtract", "anonymous"} {
		if _, ok := p.Select(a, p.Paths[0].TargetClusterID, p.Paths[0].StoreID, "diagnostics", data, "potentialPersonalData", "context", n); ok {
			t.Fatal("unapproved class allowed")
		}
	}
	i := identity.Identity{Principal: a, Policy: p.Revision, Groups: []string{"evidence-owner"}, Scopes: []string{}, VerifiedAt: n, ValidUntil: n.Add(5 * time.Second)}
	if p.Operator(i, n) {
		t.Fatal("ordinary ownership became privacy administration")
	}
	i.Groups = []string{"privacy-operators"}
	if !p.Operator(i, n) {
		t.Fatal("current exact operator group denied")
	}
	i.Principal.Kind = identity.Workload
	if p.Operator(i, n) {
		t.Fatal("workload gained human release authority")
	}
}

func TestDownloadPolicyObservationIsDownloadOnlyAndNeverSliding(t *testing.T) {
	p, actor, start := downloadPolicyFixture()
	p.FreshUntil = start.Add(DownloadPolicyObservationInterval)
	selectPath := func(now time.Time) bool {
		_, ok := p.SelectDownload(actor, p.Paths[0].TargetClusterID, p.Paths[0].StoreID, "diagnostics", "metadata", "potentialPersonalData", "context", now)
		return ok
	}
	for _, at := range []time.Time{start, start.Add(59 * time.Second)} {
		if !p.DownloadValid(at) || !selectPath(at) {
			t.Fatal("download observation refused", at)
		}
	}
	i := identity.Identity{Principal: actor, Policy: p.Revision, Groups: []string{"privacy-operators"}, Scopes: []string{}, VerifiedAt: start, ValidUntil: start.Add(5 * time.Second)}
	if p.Valid(start) || p.Operator(i, start) {
		t.Fatal("download observation became administrative authority")
	}
	if _, ok := p.Select(actor, p.Paths[0].TargetClusterID, p.Paths[0].StoreID, "diagnostics", "metadata", "potentialPersonalData", "context", start); ok {
		t.Fatal("strict selection accepted download observation")
	}
	for _, at := range []time.Time{start.Add(-time.Nanosecond), p.FreshUntil, p.FreshUntil.Add(time.Second)} {
		if p.DownloadValid(at) || selectPath(at) {
			t.Fatal("out-of-interval policy accepted", at)
		}
	}
	p.FreshUntil = p.FreshUntil.Add(time.Nanosecond)
	if p.DownloadValid(start) {
		t.Fatal("observation exceeds fixed interval")
	}
}
