package bootstrap

import (
	"context"
	"fmt"
	"os"
	"time"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/postgres"
	authapp "asservat.local/asservat/internal/application/authorization"
	executionapp "asservat.local/asservat/internal/application/execution"
	liveapp "asservat.local/asservat/internal/application/live"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/live"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/transport/presentation"
)

var _ liveapp.Sources = authapp.LiveSourceAuthority{}

// newPublicLive uses the existing guarded delivery config as the sole source
// of live ceilings. Missing liveRead is disabled, preserving old deployments.
func (d *OwnerDeployment) newPublicLive(ctx context.Context) (presentation.LiveService, error) {
	pc, dl := d.publicContext, d.publicDownloads
	if pc == nil || dl == nil || dl.environment == nil || d.Runtime == nil {
		return nil, mounts.ErrUnavailable
	}
	policy, e := dl.environment.DownloadPolicy(ctx)
	if e != nil || !policy.Valid(time.Now()) {
		return nil, mounts.ErrUnavailable
	}
	if policy.LiveRead == nil || len(policy.LiveRead.Projections) == 0 || len(policy.LiveRead.Clients) == 0 || len(policy.LiveRead.Ceilings) == 0 {
		return nil, nil
	}
	candidates, ok := pc.investigation.RecordingSources.(liveCandidateReader)
	if !ok {
		return nil, mounts.ErrUnavailable
	}
	policies, ok := pc.recordings.Inventory.Policies.(livePolicyReader)
	if !ok {
		return nil, mounts.ErrUnavailable
	}
	status, ok := pc.investigation.Targets.(liveSourceStatusReader)
	if !ok {
		return nil, mounts.ErrUnavailable
	}
	remote, ok := pc.investigation.Targets.(liveRegionalReader)
	if !ok {
		return nil, mounts.ErrUnavailable
	}
	targets, ok := pc.investigation.Targets.(authapp.LiveWorkloads)
	if !ok {
		return nil, mounts.ErrUnavailable
	}
	grants, ok := pc.grants.Store.(authapp.LiveObservationGrants)
	if !ok {
		return nil, mounts.ErrUnavailable
	}
	registry, ok := d.Runtime.readiness.Registry.(*postgres.OwnerEnrollments)
	if !ok {
		return nil, mounts.ErrUnavailable
	}
	pool, e := d.public.open(ctx, "live-watch")
	if e != nil {
		return nil, e
	}
	numeric, limits := publicLiveLimits(*policy.LiveRead)
	ledger, e := postgres.NewLiveWatches(ctx, pool, policy.RootID, d.Runtime.binding.ProcessEpoch, registry, func(call context.Context) (fleet.OwnerCertificate, error) {
		if call == nil || call.Err() != nil {
			return fleet.OwnerCertificate{}, fmt.Errorf("%w: public_live:71", live.ErrUnavailable)
		}
		return d.Runtime.server.ServingCertificate()
	}, numeric)
	if e != nil {
		return nil, e
	}
	manualWorks, ok := pc.collect.Recordings.(executionapp.LiveManualWorks)
	if !ok {
		return nil, mounts.ErrUnavailable
	}
	manualHolders, ok := pc.investigation.Targets.(liveManualHolders)
	if !ok {
		return nil, mounts.ErrUnavailable
	}
	catalog := liveCatalog{ongoing: liveSourceCatalog{root: policy.RootID, candidates: candidates, policies: policies, status: status, now: time.Now}, manual: liveManualCatalog{root: policy.RootID, works: manualWorks, recovery: pc.recovery, holders: manualHolders, now: time.Now}}
	authority := authapp.LiveSourceAuthority{Diagnose: eventLog(os.Stderr, "live inventory refused"), RootID: policy.RootID, Targets: targets, Workloads: pc.permissions, Permissions: pc.permissions, Catalog: catalog, Accepted: pc.policies, Automation: pc.automation, ObservationGrants: grants, Environment: authapp.CurrentLiveEnvironment{RootID: policy.RootID, InstallationID: policy.InstallationID, AcceptedRoot: policy.LiveRead.Root, Policies: livePolicies(dl), Recovery: pc.recovery, Now: time.Now}, Now: time.Now}
	service, e := liveapp.New(liveapp.Config{RootID: policy.RootID, OwnerID: d.Runtime.binding.ProcessEpoch, Keys: pc.mac, Now: time.Now, NewID: ownerRandomID, Limits: limits, MaxWatches: int(numeric.InstallationSlots), MaxControls: int(numeric.MaxControlRecords)}, authority, liveProjectionReader{remote: remote, now: time.Now}, ledger)
	if e != nil {
		return nil, e
	}
	d.closers = append(d.closers, service.Close)
	routed, e := d.newLiveOwner(ctx, service, ledger, policy.RootID)
	if e != nil {
		return nil, e
	}
	return routed, nil
}

// SQL's metadata-retention caps are fixed internal bounds, not operator tuning
// knobs. Aggregate buckets reuse one root rate/burst; per-source ceilings can
// lower each accepted watch independently without changing accounting debt.
func publicLiveLimits(p privacy.LiveRead) (postgres.LiveWatchLimits, live.Limits) {
	var limits live.Limits
	for _, c := range p.Ceilings {
		l := c.Limits
		limits = live.Limits{Duration: max(limits.Duration, l.Duration), Output: max(limits.Output, l.Output), Rate: max(limits.Rate, l.Rate), Rows: max(limits.Rows, l.Rows), Buffer: max(limits.Buffer, l.Buffer), RowAge: max(limits.RowAge, l.RowAge), Replay: max(limits.Replay, l.Replay)}
	}
	r := p.Root
	numeric := postgres.LiveWatchLimits{InstallationSlots: int64(r.Watches), PrincipalSlots: int64(r.PrincipalWatches), WorkloadSlots: int64(r.WorkloadWatches), MemoryBytes: int64(r.Watches) * live.MaxBufferBytes, InstallationRate: r.Rate, InstallationBurst: r.Burst, PrincipalRate: r.Rate, PrincipalBurst: r.Burst, WorkloadRate: r.Rate, WorkloadBurst: r.Burst, WatchBurst: max(24<<10, limits.Rate), MaxOutputBytes: max(24<<10, limits.Output), MaxRate: limits.Rate, MaxDurationSeconds: int64(limits.Duration), MaxAccounts: 8192, MaxControlRecords: 65536}
	return numeric, limits
}

// livePolicies reuses the downloads' bounded policy observation (accepted
// 60 s interval); each raw read costs several Kubernetes API calls.
func livePolicies(dl *publicDownloads) authapp.DownloadPolicyReader {
	if dl.policies != nil {
		return dl.policies
	}
	return dl.environment
}
