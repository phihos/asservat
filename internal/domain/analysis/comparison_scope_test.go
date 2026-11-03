package analysis

import (
	"bytes"
	"encoding/json"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

func comparisonScopeFixture() ContextProjectionScope {
	s := sourceTestScope()
	s.NativeType, s.SourceFormat, s.DisplayVersion = artifact.PprofArtifact, artifact.PprofFormat, ProfileComparisonDisplayVersion
	s.SourceProjectionDigest, s.Selection = artifact.Digest{}, LineSelection{}
	s.Profile = ProfileSummarySelection{SampleType: "cpu", TopN: 20}
	s.Comparison = ProfileComparisonWindow{Normalization: ProfileComparisonRate, Baseline: ProfileComparisonBaseline{
		CaseID: queryOtherID, ArtifactID: queryOtherID, CaptureID: queryOtherID, ClusterID: queryOtherID,
		NamespaceUID: "baseline-ns", WorkloadUID: "baseline-workload", PodUID: "baseline-pod", Version: artifact.Digest{2},
	}}
	return s
}

func TestComparisonScopeResolvesTwoOrderedLegacyScopes(t *testing.T) {
	s := comparisonScopeFixture()
	if !s.Valid() || s.BeginTool() != "compare_profiles" || s.ReadBatches() != 1 || s.QueryUnits() != 20 {
		t.Fatal("comparison scope or accounting invalid", s)
	}
	src, ok := s.Source()
	if !ok || src.NativeType != artifact.PprofArtifact || src.DataClass != "raw" || src.OutputClass() != "extract" || src.ReadOperation() != authorization.ReadProfileSummary || src.NativeLimit != artifact.MaxPprofBytes {
		t.Fatal("comparison source reclassified", src)
	}
	legacy, _ := LookupProjectionSource(artifact.PprofArtifact)
	if legacy.DisplayVersion != ProfileSummaryDisplayVersion {
		t.Fatal("default summary display changed")
	}
	for _, kind := range []string{artifact.PodStatusArtifact, artifact.HTTPHeadersArtifact, artifact.SyscallRecordsArtifact, artifact.GoTraceArtifact} {
		if _, ok := LookupProjectionSourceFor(kind, ProfileComparisonDisplayVersion); ok {
			t.Fatal("comparison accepted another source", kind)
		}
	}
	c := s.Candidate()
	if !c.Valid() || c.Comparison.Baseline.Version != (artifact.Digest{}) {
		t.Fatal("candidate kept published version")
	}
	b, bok := s.BaselineScope()
	i, iok := s.IncidentScope()
	bc, bcok := c.BaselineCandidate()
	ic, icok := c.IncidentCandidate()
	if !bok || !iok || !bcok || !icok || b.Candidate() != bc || i.Candidate() != ic {
		t.Fatal("scope derivation disagrees with candidates")
	}
	if b.CaseID != s.Comparison.Baseline.CaseID || b.ArtifactID != s.Comparison.Baseline.ArtifactID || b.Version != s.Comparison.Baseline.Version || i.ArtifactID != s.ArtifactID || i.Version != s.Version {
		t.Fatal("ordered source pins changed")
	}
	for _, child := range []ContextProjectionScope{b, i} {
		if child.RootID != s.RootID || child.Principal != s.Principal || child.Profile != s.Profile || child.Comparison != (ProfileComparisonWindow{}) || child.DisplayVersion != ProfileSummaryDisplayVersion || child.BeginTool() != "get_profile_summary" || child.QueryUnits() != 10 {
			t.Fatal("child is not independent legacy summary", child)
		}
	}
	// Comparable immutable values remain suitable for exact request/scope keys.
	if !map[ContextProjectionScope]bool{s: true}[s] || !map[ContextProjectionCandidate]bool{c: true}[c] {
		t.Fatal("scope equality changed")
	}
	body, err := json.Marshal(s)
	var back ContextProjectionScope
	if err != nil || json.Unmarshal(body, &back) != nil || back != s {
		t.Fatal("comparison scope did not round trip", string(body), err)
	}
	body, err = json.Marshal(c)
	var candidate ContextProjectionCandidate
	if err != nil || json.Unmarshal(body, &candidate) != nil || candidate != c || bytes.Contains(body, []byte("Version")) {
		t.Fatal("candidate exposed version or did not round trip", string(body), err)
	}
	candidate.Comparison.Baseline.PodUID = "changed"
	if candidate == c || s.Comparison.Baseline.PodUID != "baseline-pod" {
		t.Fatal("value copy aliases source")
	}
	if _, ok := b.BaselineScope(); ok {
		t.Fatal("legacy summary acquired second source")
	}
}

func TestComparisonScopeRequiresClosedCompletePair(t *testing.T) {
	for name, mutate := range map[string]func(*ContextProjectionScope){
		"baseline-case":      func(s *ContextProjectionScope) { s.Comparison.Baseline.CaseID = "bad" },
		"baseline-artifact":  func(s *ContextProjectionScope) { s.Comparison.Baseline.ArtifactID = "" },
		"baseline-capture":   func(s *ContextProjectionScope) { s.Comparison.Baseline.CaptureID = "" },
		"baseline-cluster":   func(s *ContextProjectionScope) { s.Comparison.Baseline.ClusterID = "" },
		"baseline-namespace": func(s *ContextProjectionScope) { s.Comparison.Baseline.NamespaceUID = "" },
		"baseline-workload":  func(s *ContextProjectionScope) { s.Comparison.Baseline.WorkloadUID = "" },
		"baseline-pod":       func(s *ContextProjectionScope) { s.Comparison.Baseline.PodUID = "" },
		"baseline-version":   func(s *ContextProjectionScope) { s.Comparison.Baseline.Version = artifact.Digest{} },
		"incident-version":   func(s *ContextProjectionScope) { s.Version = artifact.Digest{} },
		"normalization":      func(s *ContextProjectionScope) { s.Comparison.Normalization = "rate" },
		"missing-comparison": func(s *ContextProjectionScope) { s.Comparison = ProfileComparisonWindow{} },
		"version-only": func(s *ContextProjectionScope) {
			s.Comparison = ProfileComparisonWindow{Baseline: ProfileComparisonBaseline{Version: artifact.Digest{2}}}
			s.DisplayVersion = ProfileSummaryDisplayVersion
		},
		"summary-display":      func(s *ContextProjectionScope) { s.DisplayVersion = ProfileSummaryDisplayVersion },
		"unknown-display":      func(s *ContextProjectionScope) { s.DisplayVersion = "other" },
		"source-type":          func(s *ContextProjectionScope) { s.NativeType = artifact.HTTPHeadersArtifact },
		"source-format":        func(s *ContextProjectionScope) { s.SourceFormat = artifact.ContextFormat },
		"source-projection":    func(s *ContextProjectionScope) { s.SourceProjectionDigest = artifact.Digest{1} },
		"line-branch":          func(s *ContextProjectionScope) { s.Selection = LineSelection{1, 1} },
		"header-branch":        func(s *ContextProjectionScope) { s.Headers = HTTPHeaderWindow{Limit: 1} },
		"syscall-branch":       func(s *ContextProjectionScope) { s.Syscalls = SyscallWindow{View: SyscallEventsView, Limit: 1} },
		"no-profile-selection": func(s *ContextProjectionScope) { s.Profile = ProfileSummarySelection{} },
	} {
		t.Run(name, func(t *testing.T) {
			s := comparisonScopeFixture()
			mutate(&s)
			if s.Valid() || s.QueryUnits() != 0 {
				t.Fatal("invalid comparison accepted", s)
			}
		})
	}
	c := comparisonScopeFixture().Candidate()
	c.Comparison.Baseline.Version = artifact.Digest{1}
	if c.Valid() {
		t.Fatal("candidate may not choose source version")
	}
	s := comparisonScopeFixture()
	s.Comparison.Normalization = ProfileComparisonRaw
	if !s.Valid() {
		t.Fatal("raw normalization refused")
	}
}

func TestComparisonSameArtifactRequiresIdenticalSourcePins(t *testing.T) {
	s := comparisonScopeFixture()
	s.Comparison.Baseline = ProfileComparisonBaseline{CaseID: s.CaseID, ArtifactID: s.ArtifactID, CaptureID: s.CaptureID, ClusterID: s.ClusterID, NamespaceUID: s.NamespaceUID, WorkloadUID: s.WorkloadUID, PodUID: s.PodUID, Version: s.Version}
	if !s.Valid() || !s.Candidate().Valid() || s.QueryUnits() != 20 {
		t.Fatal("same source comparison refused or underfunded")
	}
	for name, mutate := range map[string]func(*ProfileComparisonBaseline){
		"case":      func(b *ProfileComparisonBaseline) { b.CaseID = queryOtherID },
		"capture":   func(b *ProfileComparisonBaseline) { b.CaptureID = queryOtherID },
		"cluster":   func(b *ProfileComparisonBaseline) { b.ClusterID = queryOtherID },
		"namespace": func(b *ProfileComparisonBaseline) { b.NamespaceUID = "other" },
		"workload":  func(b *ProfileComparisonBaseline) { b.WorkloadUID = "other" },
		"pod":       func(b *ProfileComparisonBaseline) { b.PodUID = "other" },
		"version":   func(b *ProfileComparisonBaseline) { b.Version = artifact.Digest{9} },
	} {
		t.Run(name, func(t *testing.T) {
			v := s
			mutate(&v.Comparison.Baseline)
			if v.Valid() {
				t.Fatal("same artifact acquired conflicting source identity")
			}
		})
	}
	_, selection := comparisonResultFixture()
	r := ProfileComparisonRequest{CaseID: s.CaseID, ArtifactID: s.ArtifactID, BaselineCaseID: s.CaseID, BaselineArtifactID: s.ArtifactID, Selection: selection}
	if !r.Valid() || !map[ProfileComparisonRequest]bool{r: true}[r] {
		t.Fatal("same artifact request refused")
	}
	for _, bad := range []ProfileComparisonRequest{
		{CaseID: r.CaseID, ArtifactID: r.ArtifactID, BaselineCaseID: queryOtherID, BaselineArtifactID: r.ArtifactID, Selection: selection},
		{CaseID: r.CaseID, ArtifactID: r.ArtifactID, BaselineCaseID: r.CaseID, BaselineArtifactID: "", Selection: selection},
		{CaseID: r.CaseID, ArtifactID: r.ArtifactID, BaselineCaseID: r.CaseID, BaselineArtifactID: r.ArtifactID},
	} {
		if bad.Valid() {
			t.Fatal("invalid public selection accepted", bad)
		}
	}
}

func TestComparisonProjectionResultUsesOnlyComparisonBranch(t *testing.T) {
	s := comparisonScopeFixture()
	comparison, _ := comparisonResultFixture()
	r := ProjectionResult{Comparison: &comparison}
	if !r.Valid(s) {
		t.Fatal("comparison result refused")
	}
	legacy, _ := s.IncidentScope()
	if r.Valid(legacy) {
		t.Fatal("comparison result satisfied summary")
	}
	for name, mutate := range map[string]func(*ProjectionResult){
		"summary":         func(r *ProjectionResult) { r.Summary = &ProfileSummary{} },
		"headers":         func(r *ProjectionResult) { r.Headers.Records = []HTTPHeaderRecord{} },
		"pod":             func(r *ProjectionResult) { r.PodStatus.PodUID = "p" },
		"syscall-summary": func(r *ProjectionResult) { r.SyscallSummary = &SyscallSummaryPage{} },
		"syscall-events":  func(r *ProjectionResult) { r.SyscallEvents = &SyscallEventPage{} },
		"cursor":          func(r *ProjectionResult) { r.InvalidCursor = true },
		"oversize":        func(r *ProjectionResult) { r.TooLarge = true },
		"incompatible":    func(r *ProjectionResult) { r.IncompatibleProfiles = true },
		"missing":         func(r *ProjectionResult) { r.Comparison = nil },
	} {
		t.Run(name, func(t *testing.T) {
			bad := r
			mutate(&bad)
			if bad.Valid(s) {
				t.Fatal("mixed or absent result accepted")
			}
		})
	}
	changed := s
	changed.Comparison.Normalization = ProfileComparisonRaw
	if r.Valid(changed) {
		t.Fatal("result not bound to normalization")
	}
	changed = s
	changed.Profile.SampleType = "alloc_space"
	if r.Valid(changed) {
		t.Fatal("result not bound to selected sample")
	}
	rows := comparison.Rows
	r.Clear()
	if r.Comparison != nil || rows[0] != (ProfileComparisonRow{}) || comparison.Rows != nil {
		t.Fatal("comparison transient result retained")
	}
}

func TestComparisonIncompatibleResultIsContentFreeAndScopeSpecific(t *testing.T) {
	s := comparisonScopeFixture()
	r := ProjectionResult{IncompatibleProfiles: true}
	if !r.Valid(s) {
		t.Fatal("content-free semantic mismatch refused")
	}
	for name, mutate := range map[string]func(*ProjectionResult){
		"comparison":      func(r *ProjectionResult) { c, _ := comparisonResultFixture(); r.Comparison = &c },
		"summary":         func(r *ProjectionResult) { r.Summary = &ProfileSummary{} },
		"headers":         func(r *ProjectionResult) { r.Headers.Records = []HTTPHeaderRecord{} },
		"pod":             func(r *ProjectionResult) { r.PodStatus.PodUID = "p" },
		"syscall-summary": func(r *ProjectionResult) { r.SyscallSummary = &SyscallSummaryPage{} },
		"syscall-events":  func(r *ProjectionResult) { r.SyscallEvents = &SyscallEventPage{} },
		"cursor":          func(r *ProjectionResult) { r.InvalidCursor = true },
		"oversize":        func(r *ProjectionResult) { r.TooLarge = true },
	} {
		t.Run(name, func(t *testing.T) {
			bad := r
			mutate(&bad)
			if bad.Valid(s) {
				t.Fatal("mismatch carried another result branch")
			}
		})
	}
	legacy, _ := s.IncidentScope()
	for _, scope := range []ContextProjectionScope{legacy, sourceTestScope(), {}} {
		if r.Valid(scope) {
			t.Fatal("semantic mismatch accepted outside comparison")
		}
	}
	summary := ProfileSummary{SampleType: "cpu", Unit: "nanoseconds", Top: []ProfileHotspot{}, SymbolStatus: "missing"}
	old := ProjectionResult{Summary: &summary}
	if !old.Valid(legacy) {
		t.Fatal("legacy summary fixture refused")
	}
	before, err := json.Marshal(old)
	if err != nil || bytes.Contains(before, []byte("IncompatibleProfiles")) || bytes.Contains(before, []byte("Comparison")) {
		t.Fatal("legacy result gained comparison fields", string(before), err)
	}
	old.IncompatibleProfiles = true
	if old.Valid(legacy) {
		t.Fatal("legacy payload accepted semantic mismatch flag")
	}
	body, err := json.Marshal(r)
	var back ProjectionResult
	if err != nil || json.Unmarshal(body, &back) != nil || !back.IncompatibleProfiles || !back.Valid(comparisonScopeFixture()) {
		t.Fatal("semantic mismatch did not round trip", string(body), err)
	}
	r.Clear()
	if r.IncompatibleProfiles || r.Valid(comparisonScopeFixture()) {
		t.Fatal("clear retained semantic mismatch")
	}
}

func TestComparisonCommonReaderComparesOnlyPhysicalPlacement(t *testing.T) {
	b := testAuthority().Environment
	i := b
	i.Path.ID = queryOtherID
	i.Path.TargetClusterID = queryOtherID
	i.Location.ClusterID = queryOtherID
	i.Location.ArtifactID = queryOtherID
	if !CommonProfileComparisonReader(b, i) {
		t.Fatal("distinct accepted routes to same physical reader refused")
	}
	for name, mutate := range map[string]func(*ContextProjectionEnvironment){
		"root":           func(e *ContextProjectionEnvironment) { e.RootID = queryOtherID },
		"installation":   func(e *ContextProjectionEnvironment) { e.InstallationID = queryOtherID },
		"store":          func(e *ContextProjectionEnvironment) { e.StoreID = queryOtherID; e.Path.StoreID = queryOtherID },
		"storage-region": func(e *ContextProjectionEnvironment) { e.Path.StorageRegion = "other" },
		"acquisition-cluster": func(e *ContextProjectionEnvironment) {
			e.Path.AcquisitionClusterID = queryOtherID
			e.Path.ConnectorClusterID = queryOtherID
		},
		"acquisition-region":  func(e *ContextProjectionEnvironment) { e.Region = "other"; e.Path.AcquisitionRegion = "other" },
		"connector-region":    func(e *ContextProjectionEnvironment) { e.Path.ConnectorRegion = "other" },
		"hub-cluster":         func(e *ContextProjectionEnvironment) { e.Path.HubClusterID = queryOtherID },
		"hub-region":          func(e *ContextProjectionEnvironment) { e.Path.HubRegion = "other" },
		"worker-uid":          func(e *ContextProjectionEnvironment) { e.Path.WorkerConfiguration.UID = queryOtherID },
		"worker-generation":   func(e *ContextProjectionEnvironment) { e.Path.WorkerConfiguration.Generation++ },
		"worker-digest":       func(e *ContextProjectionEnvironment) { e.Path.WorkerConfiguration.Digest[0]++ },
		"hub-uid":             func(e *ContextProjectionEnvironment) { e.Path.HubConfiguration.UID = queryOtherID },
		"hub-generation":      func(e *ContextProjectionEnvironment) { e.Path.HubConfiguration.Generation++ },
		"hub-digest":          func(e *ContextProjectionEnvironment) { e.Path.HubConfiguration.Digest[0]++ },
		"invalid-path":        func(e *ContextProjectionEnvironment) { e.Path.ID = "" },
		"store-inconsistent":  func(e *ContextProjectionEnvironment) { e.StoreID = queryOtherID },
		"region-inconsistent": func(e *ContextProjectionEnvironment) { e.Region = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			e := i
			mutate(&e)
			if CommonProfileComparisonReader(b, e) {
				t.Fatal("incompatible reader accepted")
			}
		})
	}
	b.Recovery, i.Recovery = artifact.RecoveryProof{}, artifact.RecoveryProof{}
	b.Processing, i.Processing = artifact.DownloadProcessingProof{}, artifact.DownloadProcessingProof{}
	if !CommonProfileComparisonReader(b, i) || b.Valid(b.ObservedAt) || i.Valid(i.ObservedAt) {
		t.Fatal("structural helper was confused with current authority")
	}
}

// These are the retained pre-comparison layouts, including field order/tags.
// Comparing their exact JSON catches changes to legacy scope/candidate bytes.
type legacyComparisonScope struct {
	RootID, CaseID, ArtifactID, CaptureID, ClusterID, NamespaceUID, WorkloadUID, PodUID string
	Version, SourceProjectionDigest                                                     artifact.Digest
	SourceFormat, DisplayVersion                                                        string
	Selection                                                                           LineSelection
	Principal                                                                           identity.Principal
	NativeType                                                                          string                  `json:",omitempty"`
	Headers                                                                             HTTPHeaderWindow        `json:",omitzero"`
	Profile                                                                             ProfileSummarySelection `json:",omitzero"`
	Syscalls                                                                            SyscallWindow           `json:",omitzero"`
}
type legacyComparisonCandidate struct {
	RootID, CaseID, ArtifactID, CaptureID, ClusterID, NamespaceUID, WorkloadUID, PodUID string
	Selection                                                                           LineSelection
	Principal                                                                           identity.Principal
	NativeType                                                                          string                  `json:",omitempty"`
	Headers                                                                             HTTPHeaderWindow        `json:",omitzero"`
	Profile                                                                             ProfileSummarySelection `json:",omitzero"`
	Syscalls                                                                            SyscallWindow           `json:",omitzero"`
}

func TestComparisonAdditionPreservesEveryLegacyScopeAndCandidateEncoding(t *testing.T) {
	pod := sourceTestScope()
	http := pod
	profile, _ := comparisonScopeFixture().IncidentScope()
	http.NativeType, http.SourceFormat, http.DisplayVersion, http.SourceProjectionDigest = artifact.HTTPHeadersArtifact, artifact.HTTPHeadersFormat, HTTPHeadersDisplayVersion, artifact.Digest{}
	http.Selection, http.Headers = LineSelection{}, HTTPHeaderWindow{Limit: 100}
	scopes := []ContextProjectionScope{pod, http, profile}
	for _, kind := range []string{artifact.SyscallRecordsArtifact, artifact.SyscallArgumentsArtifact} {
		s := pod
		s.NativeType = kind
		s.Selection = LineSelection{}
		s.Syscalls = SyscallWindow{View: SyscallEventsView, Limit: 10}
		src, _ := LookupProjectionSourceFor(kind, SyscallEventsView.DisplayVersion())
		s.SourceFormat, s.DisplayVersion, s.SourceProjectionDigest = src.Format, src.DisplayVersion, src.ProjectionDigest
		scopes = append(scopes, s)
	}
	for _, s := range scopes {
		if !s.Valid() {
			t.Fatal("invalid legacy fixture", s)
		}
		old := legacyComparisonScope{s.RootID, s.CaseID, s.ArtifactID, s.CaptureID, s.ClusterID, s.NamespaceUID, s.WorkloadUID, s.PodUID, s.Version, s.SourceProjectionDigest, s.SourceFormat, s.DisplayVersion, s.Selection, s.Principal, s.NativeType, s.Headers, s.Profile, s.Syscalls}
		got, _ := json.Marshal(s)
		want, _ := json.Marshal(old)
		if !bytes.Equal(got, want) {
			t.Fatalf("legacy scope bytes changed: %s != %s", got, want)
		}
		c := s.Candidate()
		oc := legacyComparisonCandidate{c.RootID, c.CaseID, c.ArtifactID, c.CaptureID, c.ClusterID, c.NamespaceUID, c.WorkloadUID, c.PodUID, c.Selection, c.Principal, c.NativeType, c.Headers, c.Profile, c.Syscalls}
		got, _ = json.Marshal(c)
		want, _ = json.Marshal(oc)
		if !bytes.Equal(got, want) {
			t.Fatalf("legacy candidate bytes changed: %s != %s", got, want)
		}
	}
}
