package analysis

import (
	"asservat.local/asservat/internal/domain/authorization"
)

// SharedBudget removes only placement from a resource profile. The installer
// declares the finite work/history budget before worker configuration exists;
// an actual plan binds its accepted placement to the exact charged workload.
func (p ContextQueryResourceProfile) SharedBudget() ContextQueryResourceProfile {
	p.Path = ContextProjectionPath{Purpose: ContextProjectionPurpose}
	return p
}

func (p ContextQueryResourceProfile) SharedBudgetValid() bool {
	return authorization.UUID(p.ID) && p.Source.Valid() && p.Qualification.Valid() &&
		p.Path == (ContextProjectionPath{Purpose: ContextProjectionPurpose}) &&
		p.Lifetime > 0 && p.Lifetime <= ContextMaxQueryTime && p.Worker.Valid() &&
		p.Worker.Runtime >= p.Lifetime && p.Cost.Valid() &&
		p.PollLimit > 0 && p.PollLimit <= 1000000 &&
		p.ControlTransitionLimit > 0 && p.ControlTransitionLimit <= 1000000
}

func (p ContextQueryResourceProfile) WithSharedPath(path ContextProjectionPath) (ContextQueryResourceProfile, error) {
	if !p.SharedBudgetValid() || !path.Valid() {
		return ContextQueryResourceProfile{}, ErrUnavailable
	}
	p.Path = path
	return p, nil
}

// QueryUnits describes fixed read-work accounting only. It neither admits a
// query nor proves that its independent workload allocations are funded.
func (s ContextProjectionScope) QueryUnits() int64 {
	if !s.Valid() {
		return 0
	}
	if s.Comparison != (ProfileComparisonWindow{}) {
		return ProfileComparisonQueryUnits
	}
	switch s.BeginTool() {
	case "get_profile_summary":
		return ProfileSummaryQueryUnits
	case "get_http_headers":
		return HTTPHeaderQueryUnits
	case "get_syscall_summary", "get_syscall_events":
		return SyscallProjectionQueryUnits
	case "get_file_excerpt":
		return 1
	}
	return 0
}

// CommonProfileComparisonReader compares structural placement observations
// only. Each environment still needs its own current authority. Route IDs and
// target clusters intentionally differ across sources and are checked there;
// this predicate cannot union credentials or authorize relocation.
func CommonProfileComparisonReader(baseline, incident ContextProjectionEnvironment) bool {
	if !authorization.UUID(baseline.RootID) || baseline.RootID != incident.RootID || !authorization.UUID(baseline.InstallationID) || baseline.InstallationID != incident.InstallationID || !baseline.Path.Valid() || !incident.Path.Valid() || baseline.StoreID != baseline.Path.StoreID || incident.StoreID != incident.Path.StoreID || baseline.Region != baseline.Path.AcquisitionRegion || incident.Region != incident.Path.AcquisitionRegion {
		return false
	}
	b, i := baseline.Path, incident.Path
	b.ID, i.ID = "", ""
	b.TargetClusterID, i.TargetClusterID = "", ""
	return b == i
}
