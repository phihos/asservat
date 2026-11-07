package privacy

import (
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"slices"
	"time"
)

// LiveRead is an optional administrator capability. It conveys no ordinary
// source entitlement, observation grant or native-download authority.
type LiveRead struct {
	Root        LiveRootLimits
	Projections []string
	Clients     []LiveClient
	Ceilings    []LiveCeiling
}
type LiveRootLimits struct {
	Watches, PrincipalWatches, WorkloadWatches int
	Rate, Burst                                int64
}

func (r LiveRootLimits) Valid() bool {
	return r.Watches >= 1 && r.Watches <= 4096 && r.PrincipalWatches >= 1 && r.PrincipalWatches <= r.Watches && r.WorkloadWatches >= 1 && r.WorkloadWatches <= r.Watches && r.Rate >= 1 && r.Rate <= 256<<20 && r.Burst >= 24<<10 && r.Burst <= 1<<30
}

type LiveClient struct {
	Issuer, ID string
	Kind       identity.Kind
	PathIDs    []string
}
type LiveLimits struct {
	Duration                     int
	Output, Rate                 int64
	Rows, Buffer, RowAge, Replay int
}
type LiveCeiling struct {
	ClusterID, NamespaceUID, WorkloadUID string
	Limits                               LiveLimits
}

func (l LiveLimits) Valid() bool {
	return l.Duration > 0 && l.Duration <= 3600 && l.Output > 0 && l.Output <= 64<<20 && l.Rate > 0 && l.Rate <= 256<<10 && l.Rows > 0 && l.Rows <= 100 && l.Buffer > 0 && l.Buffer <= 1<<20 && l.RowAge > 0 && l.RowAge <= 30 && l.Replay >= 0 && l.Replay <= 5
}
func (l LiveLimits) tighten(o LiveLimits) LiveLimits {
	return LiveLimits{min(l.Duration, o.Duration), min(l.Output, o.Output), min(l.Rate, o.Rate), min(l.Rows, o.Rows), min(l.Buffer, o.Buffer), min(l.RowAge, o.RowAge), min(l.Replay, o.Replay)}
}
func liveProjection(p string) bool {
	return p == "packetMetadata" || p == "syscallMetadata" || p == "httpHeaders"
}
func (l LiveRead) valid(paths map[string]bool) bool {
	if !l.Root.Valid() || l.Projections == nil || len(l.Projections) > 3 || l.Clients == nil || len(l.Clients) > 64 || l.Ceilings == nil || len(l.Ceilings) > 128 {
		return false
	}
	for n, p := range l.Projections {
		if !liveProjection(p) || slices.Contains(l.Projections[:n], p) {
			return false
		}
	}
	clients := map[[2]string]bool{}
	for _, c := range l.Clients {
		k := [2]string{c.Issuer, c.ID}
		if clients[k] || !identity.Text(c.Issuer, 2048) || c.Issuer == "" || !identity.Text(c.ID, 256) || c.ID == "" || !identity.ValidKind(c.Kind) || c.PathIDs == nil || len(c.PathIDs) > 32 {
			return false
		}
		clients[k] = true
		for n, id := range c.PathIDs {
			if !paths[id] || slices.Contains(c.PathIDs[:n], id) {
				return false
			}
		}
	}
	scopes := map[[3]string]bool{}
	for _, c := range l.Ceilings {
		k := [3]string{c.ClusterID, c.NamespaceUID, c.WorkloadUID}
		if scopes[k] || !authorization.UUID(c.ClusterID) || c.NamespaceUID != "" && !authorization.UUID(c.NamespaceUID) || c.WorkloadUID != "" && (!authorization.UUID(c.WorkloadUID) || c.NamespaceUID == "") || !c.Limits.Valid() {
			return false
		}
		scopes[k] = true
	}
	return true
}

// SelectLive uses current protected policy and one exact installed regional
// path. A source has no store yet; ambiguous paths deny rather than selecting a
// store on the viewer's behalf. Scope entries only lower the cluster ceiling.
func (p DownloadPolicy) SelectLive(actor identity.Principal, target authorization.Target, projection string, now time.Time) (DownloadPath, LiveLimits, bool) {
	path, limits, reason := p.SelectLiveReason(actor, target, projection, now)
	return path, limits, reason == ""
}

// SelectLiveReason is SelectLive with a fixed refusal reason for diagnostics;
// the empty reason means selected.
func (p DownloadPolicy) SelectLiveReason(actor identity.Principal, target authorization.Target, projection string, now time.Time) (DownloadPath, LiveLimits, string) {
	var path DownloadPath
	var limits LiveLimits
	if !p.DownloadValid(now) || p.Suspended || p.LiveRead == nil || !actor.Valid() || !target.Valid() || projection != "" && !liveProjection(projection) {
		return path, limits, "policy"
	}
	l := p.LiveRead
	if projection != "" && !slices.Contains(l.Projections, projection) || len(l.Projections) == 0 {
		return path, limits, "projection"
	}
	var client *LiveClient
	for n := range l.Clients {
		c := &l.Clients[n]
		if c.Issuer == actor.Issuer && c.ID == actor.ClientID && c.Kind == actor.Kind {
			client = c
			break
		}
	}
	if client == nil {
		return path, limits, "client"
	}
	found := false
	for _, x := range p.Paths {
		if x.TargetClusterID != target.ClusterID || !slices.Contains(client.PathIDs, x.ID) {
			continue
		}
		if !slices.Contains(p.PermittedRegions, x.AcquisitionRegion) || !slices.Contains(p.PermittedRegions, x.ConnectorRegion) || !slices.Contains(p.PermittedRegions, x.HubRegion) {
			continue
		}
		if found {
			return DownloadPath{}, LiveLimits{}, "ambiguous-path"
		}
		path = x
		found = true
	}
	cluster := false
	for _, c := range l.Ceilings {
		if c.ClusterID != target.ClusterID || c.NamespaceUID != "" && c.NamespaceUID != target.NamespaceUID || c.WorkloadUID != "" && c.WorkloadUID != target.WorkloadUID {
			continue
		}
		if c.NamespaceUID == "" {
			cluster = true
		}
		if limits.Valid() {
			limits = limits.tighten(c.Limits)
		} else {
			limits = c.Limits
		}
	}
	switch {
	case !found:
		return path, limits, "path"
	case !cluster || !limits.Valid():
		return path, limits, "ceiling"
	}
	return path, limits, ""
}
