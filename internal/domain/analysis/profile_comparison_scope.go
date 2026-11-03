package analysis

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

// ProfileComparisonBaseline is a fixed, comparable second route. Root,
// principal and selected sample/top-N are inherited from the parent. The
// candidate has no version; only independently resolved scope pins populate it.
type ProfileComparisonBaseline struct {
	CaseID, ArtifactID, CaptureID, ClusterID, NamespaceUID, WorkloadUID, PodUID string
	Version                                                                     artifact.Digest `json:",omitzero"`
}

type ProfileComparisonWindow struct {
	Normalization string
	Baseline      ProfileComparisonBaseline
}

func (w ProfileComparisonWindow) Selection(profile ProfileSummarySelection) ProfileComparisonSelection {
	return ProfileComparisonSelection{SampleType: profile.SampleType, Normalization: w.Normalization, TopN: profile.TopN}
}

func (b ProfileComparisonBaseline) candidate(root string, principal identity.Principal, profile ProfileSummarySelection) ContextProjectionCandidate {
	return ContextProjectionCandidate{RootID: root, CaseID: b.CaseID, ArtifactID: b.ArtifactID, CaptureID: b.CaptureID, ClusterID: b.ClusterID, NamespaceUID: b.NamespaceUID, WorkloadUID: b.WorkloadUID, PodUID: b.PodUID, Principal: principal, NativeType: artifact.PprofArtifact, Profile: profile}
}

func (w ProfileComparisonWindow) candidateValid(c ContextProjectionCandidate) bool {
	if w.Baseline.Version != (artifact.Digest{}) || !w.Selection(c.Profile).Valid() || !w.Baseline.candidate(c.RootID, c.Principal, c.Profile).RouteValid() {
		return false
	}
	if w.Baseline.ArtifactID == c.ArtifactID {
		return w.Baseline.candidate(c.RootID, c.Principal, c.Profile) == c.incidentCandidate()
	}
	return true
}

func (s ContextProjectionScope) comparisonResolved() bool {
	if s.Comparison == (ProfileComparisonWindow{}) {
		return true
	}
	w := s.Comparison
	w.Baseline.Version = artifact.Digest{}
	return w.candidateValid(s.Candidate()) && s.Comparison.Baseline.Version != (artifact.Digest{}) && (s.Comparison.Baseline.ArtifactID != s.ArtifactID || s.Comparison.Baseline.Version == s.Version)
}

func (c ContextProjectionCandidate) incidentCandidate() ContextProjectionCandidate {
	c.Comparison = ProfileComparisonWindow{}
	return c
}

// BaselineCandidate and IncidentCandidate produce the existing single-source
// summary selections for independent authorization. No combined read authority
// is produced, and neither helper accepts a caller-selected child principal.
func (c ContextProjectionCandidate) BaselineCandidate() (ContextProjectionCandidate, bool) {
	if c.Comparison == (ProfileComparisonWindow{}) || !c.Valid() {
		return ContextProjectionCandidate{}, false
	}
	b := c.Comparison.Baseline.candidate(c.RootID, c.Principal, c.Profile)
	return b, b.Valid()
}
func (c ContextProjectionCandidate) IncidentCandidate() (ContextProjectionCandidate, bool) {
	if c.Comparison == (ProfileComparisonWindow{}) || !c.Valid() {
		return ContextProjectionCandidate{}, false
	}
	i := c.incidentCandidate()
	return i, i.Valid()
}

func (s ContextProjectionScope) BaselineScope() (ContextProjectionScope, bool) {
	if s.Comparison == (ProfileComparisonWindow{}) || !s.Valid() {
		return ContextProjectionScope{}, false
	}
	b := s.Comparison.Baseline
	out := ContextProjectionScope{RootID: s.RootID, CaseID: b.CaseID, ArtifactID: b.ArtifactID, CaptureID: b.CaptureID, ClusterID: b.ClusterID, NamespaceUID: b.NamespaceUID, WorkloadUID: b.WorkloadUID, PodUID: b.PodUID, Version: b.Version, SourceFormat: artifact.PprofFormat, DisplayVersion: ProfileSummaryDisplayVersion, Principal: s.Principal, NativeType: artifact.PprofArtifact, Profile: s.Profile}
	return out, out.Valid()
}
func (s ContextProjectionScope) IncidentScope() (ContextProjectionScope, bool) {
	if s.Comparison == (ProfileComparisonWindow{}) || !s.Valid() {
		return ContextProjectionScope{}, false
	}
	out := s
	out.Comparison = ProfileComparisonWindow{}
	out.DisplayVersion = ProfileSummaryDisplayVersion
	return out, out.Valid()
}
