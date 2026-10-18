package analysis

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

const queryTestID = "11111111-1111-4111-8111-111111111111"
const queryOtherID = "22222222-2222-4222-8222-222222222222"

func testAuthority() ContextProjectionAuthority {
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	until := now.Add(4 * time.Second)
	rev := identity.Revision{UID: queryTestID, Generation: 1, Digest: [32]byte{1}}
	principal := identity.Principal{Issuer: "https://issuer.example", Subject: "developer", ClientID: "client", Kind: identity.Human}
	location := artifact.Location{ClusterID: queryTestID, ArtifactID: queryTestID, AttemptID: queryTestID}
	scope := ContextProjectionScope{RootID: queryTestID, CaseID: queryTestID, ArtifactID: queryTestID, CaptureID: queryTestID, ClusterID: queryTestID,
		NamespaceUID: "namespace", WorkloadUID: "workload", PodUID: "pod", Version: artifact.Digest{2}, SourceProjectionDigest: ContextSourceProjectionDigest(),
		SourceFormat: artifact.ContextFormat, DisplayVersion: ContextDisplayVersion, Selection: LineSelection{1, 200}, Principal: principal}
	path := ContextProjectionPath{Purpose: ContextProjectionPurpose, ID: queryTestID, TargetClusterID: queryTestID, StoreID: queryTestID,
		StorageRegion: "region", AcquisitionClusterID: queryTestID, AcquisitionRegion: "region", ConnectorClusterID: queryTestID, ConnectorRegion: "region",
		HubClusterID: queryTestID, HubRegion: "region", WorkerConfiguration: rev, HubConfiguration: rev}
	environment := ContextProjectionEnvironment{RootID: queryTestID, InstallationID: queryTestID, Region: "region", StoreID: queryTestID,
		Location: location, Principal: principal, PolicyRevision: rev, Path: path, ObservedAt: now, ValidUntil: until,
		Recovery: artifact.RecoveryProof{InstallationID: queryTestID, IssuerEpoch: queryTestID, Revision: rev, ObservedAt: now, FreshUntil: until},
		Processing: artifact.DownloadProcessingProof{RootID: queryTestID, Epoch: queryTestID, CaptureID: queryTestID, Location: location, Sequence: 1,
			StateDigest: artifact.Digest{1}, ObservedAt: now, ValidUntil: until}}
	retention := artifact.RetentionProof{RootID: queryTestID, ClusterID: queryTestID, NamespaceUID: "namespace", WorkloadUID: "workload", PodUID: "pod",
		Topology: rev, Policy: rev, Selectors: rev, SourceCount: 1, ObservedAt: now, ValidUntil: until}
	retention.Sources[0] = artifact.RetentionSourceVersion{ClusterID: queryTestID, ControlNamespaceUID: "control", Epoch: queryTestID, Hub: true,
		ProtectionDigest: artifact.Digest{1}, SnapshotDigest: artifact.Digest{2}, Acceptance: rev}
	return ContextProjectionAuthority{Scope: scope, Environment: environment, Retention: retention, PermissionRevision: rev, IdentityRevision: rev,
		DecisionDigest: artifact.Digest{3}, CheckedAt: now, ValidUntil: until, AccessUntil: now.Add(time.Minute), DeleteBy: now.Add(2 * time.Minute)}
}

func TestProjectionAuthorityRequiresEveryCurrentBinding(t *testing.T) {
	valid := testAuthority()
	now := valid.CheckedAt.Add(time.Second)
	if !valid.Valid(now) {
		t.Fatal("valid current authority refused")
	}
	for name, mutate := range map[string]func(*ContextProjectionAuthority){
		"missing-case":             func(a *ContextProjectionAuthority) { a.Scope.CaseID = "" },
		"missing-version":          func(a *ContextProjectionAuthority) { a.Scope.Version = artifact.Digest{} },
		"wrong-native-format":      func(a *ContextProjectionAuthority) { a.Scope.SourceFormat = "other" },
		"wrong-native-projection":  func(a *ContextProjectionAuthority) { a.Scope.SourceProjectionDigest[0] ^= 1 },
		"wrong-display":            func(a *ContextProjectionAuthority) { a.Scope.DisplayVersion = "other" },
		"missing-selection":        func(a *ContextProjectionAuthority) { a.Scope.Selection = LineSelection{} },
		"missing-environment":      func(a *ContextProjectionAuthority) { a.Environment = ContextProjectionEnvironment{} },
		"missing-retention":        func(a *ContextProjectionAuthority) { a.Retention = artifact.RetentionProof{} },
		"missing-recovery":         func(a *ContextProjectionAuthority) { a.Environment.Recovery = artifact.RecoveryProof{} },
		"missing-processing":       func(a *ContextProjectionAuthority) { a.Environment.Processing = artifact.DownloadProcessingProof{} },
		"missing-path":             func(a *ContextProjectionAuthority) { a.Environment.Path = ContextProjectionPath{} },
		"download-purpose":         func(a *ContextProjectionAuthority) { a.Environment.Path.Purpose = "download" },
		"other-root":               func(a *ContextProjectionAuthority) { a.Scope.RootID = queryOtherID },
		"other-artifact":           func(a *ContextProjectionAuthority) { a.Scope.ArtifactID = queryOtherID },
		"other-cluster":            func(a *ContextProjectionAuthority) { a.Scope.ClusterID = queryOtherID },
		"other-capture":            func(a *ContextProjectionAuthority) { a.Scope.CaptureID = queryOtherID },
		"other-pod":                func(a *ContextProjectionAuthority) { a.Scope.PodUID = "other" },
		"other-namespace":          func(a *ContextProjectionAuthority) { a.Scope.NamespaceUID = "other" },
		"other-workload":           func(a *ContextProjectionAuthority) { a.Scope.WorkloadUID = "other" },
		"other-client":             func(a *ContextProjectionAuthority) { a.Scope.Principal.ClientID = "other" },
		"other-subject":            func(a *ContextProjectionAuthority) { a.Scope.Principal.Subject = "other" },
		"other-installation":       func(a *ContextProjectionAuthority) { a.Environment.Recovery.InstallationID = queryOtherID },
		"other-processing-root":    func(a *ContextProjectionAuthority) { a.Environment.Processing.RootID = queryOtherID },
		"other-processing-attempt": func(a *ContextProjectionAuthority) { a.Environment.Processing.Location.AttemptID = queryOtherID },
		"other-store":              func(a *ContextProjectionAuthority) { a.Environment.Path.StoreID = queryOtherID },
		"other-region":             func(a *ContextProjectionAuthority) { a.Environment.Region = "other" },
		"other-path-target":        func(a *ContextProjectionAuthority) { a.Environment.Path.TargetClusterID = queryOtherID },
		"foreign-connector":        func(a *ContextProjectionAuthority) { a.Environment.Path.ConnectorClusterID = queryOtherID },
		"missing-worker-config":    func(a *ContextProjectionAuthority) { a.Environment.Path.WorkerConfiguration = identity.Revision{} },
		"missing-policy":           func(a *ContextProjectionAuthority) { a.Environment.PolicyRevision = identity.Revision{} },
		"missing-permission":       func(a *ContextProjectionAuthority) { a.PermissionRevision = identity.Revision{} },
		"missing-identity":         func(a *ContextProjectionAuthority) { a.IdentityRevision = identity.Revision{} },
		"missing-decision":         func(a *ContextProjectionAuthority) { a.DecisionDigest = artifact.Digest{} },
		"closed-retention":         func(a *ContextProjectionAuthority) { a.AccessUntil = now },
		"deletion-before-access":   func(a *ContextProjectionAuthority) { a.DeleteBy = a.AccessUntil },
		"long-authority":           func(a *ContextProjectionAuthority) { a.ValidUntil = a.CheckedAt.Add(5*time.Second + 1) },
		"future-authority":         func(a *ContextProjectionAuthority) { a.CheckedAt = now.Add(time.Nanosecond) },
		"old-retention":            func(a *ContextProjectionAuthority) { a.Retention.ValidUntil = now },
		"extended-retention":       func(a *ContextProjectionAuthority) { a.Retention.ValidUntil = a.ValidUntil.Add(-time.Nanosecond) },
		"extended-environment":     func(a *ContextProjectionAuthority) { a.Environment.ValidUntil = a.ValidUntil.Add(-time.Nanosecond) },
		"extended-recovery": func(a *ContextProjectionAuthority) {
			a.Environment.Recovery.FreshUntil = a.ValidUntil.Add(-time.Nanosecond)
		},
		"extended-processing": func(a *ContextProjectionAuthority) {
			a.Environment.Processing.ValidUntil = a.ValidUntil.Add(-time.Nanosecond)
		},
	} {
		t.Run(name, func(t *testing.T) {
			a := valid
			mutate(&a)
			if a.Valid(now) {
				t.Fatal("invalid authority accepted")
			}
		})
	}
	if valid.Valid(valid.ValidUntil) || valid.Valid(valid.CheckedAt.Add(-time.Nanosecond)) {
		t.Fatal("deadline equality or clock rollback accepted")
	}
	// Time-zone representation does not change an absolute instant.
	valid.CheckedAt = valid.CheckedAt.In(time.FixedZone("other", 2*60*60))
	valid.ValidUntil = valid.ValidUntil.In(time.FixedZone("other", 2*60*60))
	if !valid.Valid(now) {
		t.Fatal("equivalent time representation refused")
	}
}

func TestProjectionQueryAndRequestDeadlinesStayDistinct(t *testing.T) {
	a := testAuthority()
	start := a.CheckedAt
	for _, tc := range []struct {
		lifetime     time.Duration
		access, want time.Time
	}{
		{0, start.Add(time.Minute), start.Add(10 * time.Second)},
		{60 * time.Second, start.Add(time.Hour), start.Add(time.Minute)},
		{30 * time.Second, start.Add(8 * time.Second), start.Add(8 * time.Second)},
	} {
		got, err := ContextQueryDeadline(start, tc.lifetime, tc.access)
		if err != nil || !got.Equal(tc.want) {
			t.Fatalf("query deadline: %v, %v; want %v", got, err, tc.want)
		}
	}
	for _, lifetime := range []time.Duration{-1, ContextMaxQueryTime + 1} {
		if _, err := ContextQueryDeadline(start, lifetime, start.Add(time.Hour)); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid total lifetime accepted", lifetime, err)
		}
	}
	if _, err := ContextQueryDeadline(start, 0, start); !errors.Is(err, ErrExpired) {
		t.Fatal("expired source accepted", err)
	}
	if _, err := ContextQueryDeadline(start, 0, time.Time{}); !errors.Is(err, ErrInvalid) {
		t.Fatal("absent source bound accepted", err)
	}
	// Query lifetime never makes the original request's authority valid longer.
	if a.Valid(start.Add(5 * time.Second)) {
		t.Fatal("query duration renewed a request authority")
	}
	// A new current request may read the same query after the old request ends;
	// its identity observation never becomes the total query lifetime.
	deadline, err := ContextQueryDeadline(start, 0, start.Add(time.Minute))
	if err != nil || !deadline.After(a.ValidUntil) {
		t.Fatal("request interval collapsed total query lifetime", deadline, err)
	}
}

func TestProjectionLineDefaultsAndSourceScope(t *testing.T) {
	s, err := NormalizeLineSelection(0, 0)
	if err != nil || s != (LineSelection{1, 200}) {
		t.Fatal("wrong defaults", s, err)
	}
	for _, v := range []LineSelection{{-1, 1}, {1, -1}, {1, 201}, {1_000_000_001, 1}} {
		if _, err := NormalizeLineSelection(v.LineStart, v.MaxLines); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid wire selection accepted", v)
		}
	}
	for _, mutate := range []func(*ContextProjectionScope){
		func(s *ContextProjectionScope) { s.SourceFormat = "other" },
		func(s *ContextProjectionScope) { s.SourceProjectionDigest[0] ^= 1 },
		func(s *ContextProjectionScope) { s.DisplayVersion = "other" },
		func(s *ContextProjectionScope) { s.Version = artifact.Digest{} },
	} {
		scope := testAuthority().Scope
		mutate(&scope)
		if scope.Valid() {
			t.Fatal("unsupported source scope accepted")
		}
	}
}

func TestContextSourceProjectionDigestMatchesImmutableDefinition(t *testing.T) {
	if ContextSourceProjectionDigest() != sha256.Sum256([]byte(artifact.ContextProjectionDefinition)) {
		t.Fatal("pinned native source projection digest drifted")
	}
}
