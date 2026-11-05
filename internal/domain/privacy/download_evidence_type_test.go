package privacy

import "testing"

// ADR-248: a client may be approved for packet captures (PCAPNG) besides
// context; each evidence type still needs its own explicit client listing,
// and types without a download path (core dumps) stay invalid. Syscall
// metadata has one since ADR-273.
func TestDownloadPolicyPacketCaptureNeedsExplicitClientType(t *testing.T) {
	p, a, n := downloadPolicyFixture()
	sel := func(p DownloadPolicy, evidenceType string) bool {
		_, ok := p.Select(a, p.Paths[0].TargetClusterID, p.Paths[0].StoreID, "diagnostics", "metadata", "potentialPersonalData", evidenceType, n)
		return ok
	}
	if sel(p, "packetCapture") {
		t.Fatal("context-only client disclosed a packet capture")
	}
	q := p
	q.Clients = []DownloadClient{p.Clients[0]}
	q.Clients[0].EvidenceTypes = []string{"context", "packetCapture"}
	if !q.Valid(n) || !sel(q, "packetCapture") || !sel(q, "context") {
		t.Fatal("explicitly approved packet capture client refused")
	}
	q.Clients[0].EvidenceTypes = []string{"packetCapture"}
	if sel(q, "context") {
		t.Fatal("packet capture approval disclosed context")
	}
	q.Clients[0].EvidenceTypes = []string{"syscallTrace"}
	if !q.Valid(n) || !sel(q, "syscallTrace") {
		t.Fatal("explicitly approved syscall metadata client refused")
	}
	q.Clients[0].EvidenceTypes = []string{"coreDump"}
	if q.Valid(n) {
		t.Fatal("evidence type without a download path accepted")
	}
}

func TestDownloadPolicyAllSupportedTypesIncludesLogsWithoutImplicitExpansion(t *testing.T) {
	p, who, n := downloadPolicyFixture()
	path := p.Paths[0]
	selectLogs := func(p DownloadPolicy) bool {
		_, ok := p.Select(who, path.TargetClusterID, path.StoreID, "diagnostics", "metadata", "potentialPersonalData", "logs", n)
		return ok
	}
	if selectLogs(p) {
		t.Fatal("old context-only policy implicitly gained logs")
	}
	p.Clients[0].EvidenceTypes = []string{"context", "packetCapture", "syscallTrace", "profile", "logs"}
	if !p.Valid(n) || !selectLogs(p) {
		t.Fatal("explicit complete supported policy refused logs")
	}
	for _, types := range [][]string{{"context", "packetCapture", "syscallTrace", "profile", "logs", "coreDump"}, {"context", "packetCapture", "syscallTrace", "profile", "logs", "logs"}} {
		p.Clients[0].EvidenceTypes = types
		if p.Valid(n) {
			t.Fatal("unknown/duplicate extra type accepted")
		}
	}
}
