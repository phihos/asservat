package privacy

import (
	"asservat.local/asservat/internal/domain/authorization"
	"testing"
)

func TestLiveReadRequiresIndependentOptInExactClientPathAndScope(t *testing.T) {
	p, a, now := downloadPolicyFixture()
	target := authorization.Target{ClusterID: p.Paths[0].TargetClusterID, NamespaceUID: processingID(20), WorkloadUID: processingID(21), PodUID: processingID(22)}
	if _, _, ok := p.SelectLive(a, target, "packetMetadata", now); ok {
		t.Fatal("download policy enabled live")
	}
	limits := LiveLimits{600, 16 << 20, 64 << 10, 100, 1 << 20, 30, 5}
	p.LiveRead = &LiveRead{Root: LiveRootLimits{16, 4, 4, 1 << 20, 1 << 20}, Projections: []string{"packetMetadata"}, Clients: []LiveClient{{Issuer: a.Issuer, ID: a.ClientID, Kind: a.Kind, PathIDs: []string{p.Paths[0].ID}}}, Ceilings: []LiveCeiling{{ClusterID: target.ClusterID, Limits: limits}}}
	// A live viewer is not thereby a native-download client.
	p.Clients = []DownloadClient{}
	if _, got, ok := p.SelectLive(a, target, "packetMetadata", now); !ok || got != limits {
		t.Fatal("explicit live client denied", got, ok)
	}
	if _, ok := p.Select(a, target.ClusterID, p.Paths[0].StoreID, "diagnostics", "metadata", "potentialPersonalData", "context", now); ok {
		t.Fatal("live opt-in enabled download")
	}
	p.LiveRead.Ceilings = append(p.LiveRead.Ceilings, LiveCeiling{ClusterID: target.ClusterID, NamespaceUID: target.NamespaceUID, Limits: LiveLimits{60, 1 << 20, 16 << 10, 10, 64 << 10, 10, 2}})
	if _, got, ok := p.SelectLive(a, target, "packetMetadata", now); !ok || got.Duration != 60 || got.Rows != 10 || got.Rate != 16<<10 {
		t.Fatal("scope did not lower cluster ceiling", got, ok)
	}
	for _, mode := range []string{"client", "projection", "region", "scope", "expired", "ambiguous", "invalid-child"} {
		t.Run(mode, func(t *testing.T) {
			q := p
			live := *p.LiveRead
			live.Clients = append([]LiveClient(nil), live.Clients...)
			live.Ceilings = append([]LiveCeiling(nil), live.Ceilings...)
			q.LiveRead = &live
			actor := a
			proj := "packetMetadata"
			at := now
			switch mode {
			case "client":
				actor.ClientID = "other"
			case "projection":
				proj = "httpHeaders"
			case "region":
				q.PermittedRegions = []string{"storage"}
			case "scope":
				q.LiveRead.Ceilings = q.LiveRead.Ceilings[1:]
			case "expired":
				at = p.FreshUntil
			case "ambiguous":
				path := p.Paths[0]
				path.ID = processingID(30)
				q.Paths = append(append([]DownloadPath(nil), p.Paths...), path)
				q.LiveRead.Clients[0].PathIDs = append(append([]string(nil), q.LiveRead.Clients[0].PathIDs...), path.ID)
			case "invalid-child":
				q.LiveRead.Ceilings[1].Limits.Rows = 0
			}
			if _, _, ok := q.SelectLive(actor, target, proj, at); ok {
				t.Fatal("unapproved live path accepted")
			}
		})
	}
}
