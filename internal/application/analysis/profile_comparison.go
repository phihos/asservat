package analysis

import (
	"context"
	"encoding/json"
	"errors"

	identities "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

// ProfileComparisons is an explicit internal facet. Protected composition must
// also supply paired plans; there is no single-source planning fallback.
func (s ContextProjectionService) ProfileComparisons() (ProfileComparisonReads, bool) {
	return ProfileComparisonReads{Service: s, Routes: s.ComparisonRoutes}, s.ComparisonRoutes != nil
}

type ProfileComparisonReads struct {
	Service ContextProjectionService
	Routes  ContextProjectionRouteReader
}

func (s ProfileComparisonReads) Begin(ctx context.Context, current identities.CurrentIdentity, invocation ContextQueryInvocation, request value.ProfileComparisonRequest) (*ContextProjectionDelivery, error) {
	var d *ContextProjectionDelivery
	err := queryStepped("configuration", value.ErrUnavailable)
	if request.Valid() && s.Routes != nil {
		d, err = s.Service.begin(ctx, current, invocation, "compare_profiles", ContextQueryInput{Comparison: request}, func(ctx context.Context, caller identity.Identity, recovery artifact.RecoveryProof) (value.ContextProjectionCandidate, error) {
			var routes [2]value.ContextProjectionCandidate
			for i, selection := range [2][2]string{{request.BaselineCaseID, request.BaselineArtifactID}, {request.CaseID, request.ArtifactID}} {
				c, e := s.Routes.ResolveProjectionRoute(ctx, selection[0], selection[1], caller, recovery)
				if e != nil || !c.RouteValid() || c.RootID != s.Service.Results.RootID || c.Principal != caller.Principal || c.CaseID != selection[0] || c.ArtifactID != selection[1] || !cleanProfileComparisonRoute(c) {
					return value.ContextProjectionCandidate{}, errors.Join(value.ErrUnavailable, e)
				}
				routes[i] = c
			}
			b, c := routes[0], routes[1]
			c.NativeType = artifact.PprofArtifact
			c.Profile = value.ProfileSummarySelection{SampleType: request.Selection.SampleType, TopN: request.Selection.TopN}
			c.Comparison = value.ProfileComparisonWindow{Normalization: request.Selection.Normalization, Baseline: value.ProfileComparisonBaseline{CaseID: b.CaseID, ArtifactID: b.ArtifactID, CaptureID: b.CaptureID, ClusterID: b.ClusterID, NamespaceUID: b.NamespaceUID, WorkloadUID: b.WorkloadUID, PodUID: b.PodUID}}
			return c, nil
		})
	}
	s.Service.Results.refused(ctx, "profile-comparison", err)
	return d, err
}

func cleanProfileComparisonRoute(c value.ContextProjectionCandidate) bool {
	return c.NativeType == "" && c.Selection == (value.LineSelection{}) && c.Headers == (value.HTTPHeaderWindow{}) && c.Profile == (value.ProfileSummarySelection{}) && c.Syscalls == (value.SyscallWindow{}) && c.Comparison == (value.ProfileComparisonWindow{})
}

func (d *ContextProjectionDelivery) ProfileComparison() (value.ProfileComparison, bool) {
	if d == nil || d.owner == nil || d.pending || d.owner.query.Scope.Comparison == (value.ProfileComparisonWindow{}) {
		return value.ProfileComparison{}, false
	}
	d.owner.mu.Lock()
	defer d.owner.mu.Unlock()
	if d.owner.closed || d.refusal != ContextProjectionNoRefusal || d.comparison == nil {
		return value.ProfileComparison{}, false
	}
	return value.CloneProfileComparison(*d.comparison), true
}

// ProfileComparisonSource is immutable display provenance only. It carries no
// private route, authority, placement or retained native-data reference.
type ProfileComparisonSource struct {
	CaseID, ArtifactID string
	Version            artifact.Digest
}

// ProfileComparisonSources returns the ordered baseline and incident pins.
func (d *ContextProjectionDelivery) ProfileComparisonSources() (baseline, incident ProfileComparisonSource, ok bool) {
	if d == nil || d.owner == nil {
		return baseline, incident, false
	}
	d.owner.mu.Lock()
	defer d.owner.mu.Unlock()
	s := d.owner.query.Scope
	if d.owner.closed || s.Comparison == (value.ProfileComparisonWindow{}) {
		return baseline, incident, false
	}
	b := s.Comparison.Baseline
	return ProfileComparisonSource{b.CaseID, b.ArtifactID, b.Version}, ProfileComparisonSource{s.CaseID, s.ArtifactID, s.Version}, true
}

func boundedProfileComparison(result *value.ProfileComparison, selection value.ProfileComparisonSelection) bool {
	if result == nil || !result.Valid(selection) {
		return false
	}
	body, err := json.Marshal(result)
	return err == nil && len(body) <= value.ProfileComparisonBytes
}

func comparisonAssociationSelection(scope value.ContextProjectionScope) value.ProfileComparisonSelection {
	if scope.Comparison == (value.ProfileComparisonWindow{}) {
		return value.ProfileComparisonSelection{}
	}
	return scope.Comparison.Selection(scope.Profile)
}
