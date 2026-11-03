package authorization

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
)

type comparisonAuthorizationFixture struct {
	baseline, incident *projectionFixture
	now                time.Time
}

func (f *comparisonAuthorizationFixture) ResolveIdentity(ctx context.Context) (identity.Identity, error) {
	return f.baseline.ResolveIdentity(ctx)
}
func (f *comparisonAuthorizationFixture) Permissions(ctx context.Context, t value.Target) (value.Projection, error) {
	if t == f.baseline.permission.Target {
		return f.baseline.Permissions(ctx, t)
	}
	return f.incident.Permissions(ctx, t)
}
func (f *comparisonAuthorizationFixture) ContextProjectionEvidence(ctx context.Context, id string) (ContextProjectionEvidence, error) {
	if id == f.baseline.record.Retained.Registration.Location.ArtifactID {
		return f.baseline.ContextProjectionEvidence(ctx, id)
	}
	return f.incident.ContextProjectionEvidence(ctx, id)
}
func (f *comparisonAuthorizationFixture) ResolveRetained(ctx context.Context, in privacy.Input, d privacy.Deadlines, o []artifact.RetentionRule) (privacy.RetainedResolution, error) {
	if in.Target == f.baseline.record.Retained.Input.Target {
		return f.baseline.ResolveRetained(ctx, in, d, o)
	}
	return f.incident.ResolveRetained(ctx, in, d, o)
}
func (f *comparisonAuthorizationFixture) ProjectionEnvironment(ctx context.Context, r ContextProjectionEvidence, p identity.Principal) (analysis.ContextProjectionEnvironment, error) {
	if r.Retained.Registration.Location.ArtifactID == f.baseline.record.Retained.Registration.Location.ArtifactID {
		return f.baseline.ProjectionEnvironment(ctx, r, p)
	}
	return f.incident.ProjectionEnvironment(ctx, r, p)
}
func newComparisonAuthorizationFixture() (*comparisonAuthorizationFixture, ContextProjectionAuthority, analysis.ContextProjectionScope) {
	b, _, bs := newProfileProjectionFixture()
	copied := *b
	i := &copied
	i.counts = map[string]int{}
	i.calls = nil
	i.identity = cloneProjectionIdentity(b.identity)
	i.permission = cloneProjectionPermissions(b.permission)
	i.record = cloneProjectionEvidence(b.record)
	i.permission.Target = value.Target{ClusterID: projectionTestID(102), NamespaceUID: "incident-ns", WorkloadUID: "incident-workload", PodUID: "incident-pod"}
	is := bs
	is.CaseID = projectionTestID(103)
	is.ArtifactID = projectionTestID(105)
	is.CaptureID = projectionTestID(104)
	is.ClusterID = i.permission.Target.ClusterID
	is.NamespaceUID, is.WorkloadUID, is.PodUID = i.permission.Target.NamespaceUID, i.permission.Target.WorkloadUID, i.permission.Target.PodUID
	is.Version = artifact.Digest{106}
	i.record.CaseID, i.record.CaptureID, i.record.Version = is.CaseID, is.CaptureID, is.Version
	i.record.Retained.Registration.Location.ClusterID = is.ClusterID
	i.record.Retained.Registration.Location.ArtifactID = is.ArtifactID
	i.record.Retained.Input.Target = i.permission.Target
	i.retention.Target = i.permission.Target
	i.retention.Proof.ClusterID = is.ClusterID
	i.retention.Proof.NamespaceUID = is.NamespaceUID
	i.retention.Proof.WorkloadUID = is.WorkloadUID
	i.retention.Proof.PodUID = is.PodUID
	i.retention.Proof.Sources[0].ClusterID = is.ClusterID
	i.environment.Location = i.record.Retained.Registration.Location
	i.environment.Processing.Location = i.environment.Location
	i.environment.Processing.CaptureID = is.CaptureID
	i.environment.Path.TargetClusterID = is.ClusterID
	i.environment.Path.ID = projectionTestID(128)
	pair := is
	pair.DisplayVersion = analysis.ProfileComparisonDisplayVersion
	pair.Comparison = analysis.ProfileComparisonWindow{Normalization: analysis.ProfileComparisonRate, Baseline: analysis.ProfileComparisonBaseline{CaseID: bs.CaseID, ArtifactID: bs.ArtifactID, CaptureID: bs.CaptureID, ClusterID: bs.ClusterID, NamespaceUID: bs.NamespaceUID, WorkloadUID: bs.WorkloadUID, PodUID: bs.PodUID, Version: bs.Version}}
	f := &comparisonAuthorizationFixture{baseline: b, incident: i, now: b.now}
	return f, ContextProjectionAuthority{RootID: pair.RootID, Permissions: f, Catalog: f, Retention: f, Environment: f, Now: func() time.Time { return f.now }}, pair
}

func TestProfileComparisonAuthorizesBothSourcesAndRechecksFirst(t *testing.T) {
	f, s, pair := newComparisonAuthorizationFixture()
	out, err := s.ResolveProjectionCurrent(t.Context(), f, pair.Candidate())
	if err != nil || out.Scope != pair || !out.Valid(f.now) {
		t.Fatal("comparison not independently authorized", err, out)
	}
	if f.baseline.counts["catalog"] != 2 || f.incident.counts["catalog"] != 1 {
		t.Fatal("first source was not rechecked after second", f.baseline.calls, f.incident.calls)
	}
}

func TestProfileComparisonHiddenBaselineRefusesUniformly(t *testing.T) {
	for _, mode := range []string{"deny", "missing", "wrong-case", "retained-audience"} {
		t.Run(mode, func(t *testing.T) {
			f, s, pair := newComparisonAuthorizationFixture()
			switch mode {
			case "deny":
				f.baseline.permission.Allows = nil
			case "missing":
				f.baseline.fail = "catalog"
			case "wrong-case":
				f.baseline.record.CaseID = projectionTestID(999)
			case "retained-audience":
				f.baseline.record.Audience = nil
			}
			out, err := s.ResolveProjectionCurrent(t.Context(), f, pair.Candidate())
			if !errors.Is(err, analysis.ErrUnavailable) || err.Error() != analysis.ErrUnavailable.Error() || out != (analysis.ContextProjectionAuthority{}) || strings.Contains(err.Error(), "private") {
				t.Fatal("hidden baseline error disclosed source", mode, err)
			}
			if mode == "deny" && f.baseline.counts["catalog"] != 0 {
				t.Fatal("baseline lookup preceded ordinary rights")
			}
			if f.incident.counts["catalog"] != 0 {
				t.Fatal("continued after refused baseline")
			}
		})
	}
}

func TestProfileComparisonEachSourceKeepsOrdinaryRightsAndCurrentBounds(t *testing.T) {
	for _, source := range []string{"baseline", "incident"} {
		for _, mode := range []string{"deny", "audience", "expiry", "cancel", "missing", "private-environment"} {
			t.Run(source+"/"+mode, func(t *testing.T) {
				f, s, pair := newComparisonAuthorizationFixture()
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				selected := f.baseline
				if source == "incident" {
					selected = f.incident
				}
				shares := &projectionShares{now: func() time.Time { return f.now }}
				s.Shares = shares
				switch mode {
				case "deny":
					selected.permission.Allows = nil
				case "audience":
					selected.record.Audience = nil
				case "expiry":
					selected.retention.ExpiresAt = f.now
				case "cancel":
					selected.on = func(_ context.Context, step string, _ int) {
						if step == "environment" {
							cancel()
						}
					}
				case "missing":
					selected.fail = "catalog"
				case "private-environment":
					selected.environment.Processing.CaptureID = projectionTestID(999)
				}
				out, err := s.CheckProjectionCurrent(ctx, f, pair)
				if !errors.Is(err, analysis.ErrUnavailable) || out != (analysis.ContextProjectionAuthority{}) || shares.reads != 0 {
					t.Fatal("pair accepted unavailable source or share fallback", err)
				}
				if mode == "deny" && selected.counts["catalog"] != 0 {
					t.Fatal("protected source lookup preceded ordinary rights")
				}
			})
		}
	}
}

func TestProfileComparisonRechecksFixedBaselineAfterBlockingIncident(t *testing.T) {
	for _, mode := range []string{"deny", "version", "expiry", "cancel", "recovery"} {
		t.Run(mode, func(t *testing.T) {
			f, s, pair := newComparisonAuthorizationFixture()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			f.incident.on = func(_ context.Context, step string, n int) {
				if step != "environment" || n != 2 {
					return
				}
				switch mode {
				case "deny":
					f.baseline.permission.Allows = nil
				case "version":
					f.baseline.record.Version[0]++
				case "expiry":
					f.now = f.now.Add(6 * time.Second)
				case "cancel":
					cancel()
				case "recovery":
					f.baseline.environment.Recovery.IssuerEpoch = projectionTestID(999)
				}
			}
			if out, err := s.ResolveProjectionCurrent(ctx, f, pair.Candidate()); !errors.Is(err, analysis.ErrUnavailable) || out != (analysis.ContextProjectionAuthority{}) {
				t.Fatal("stale first source survived blocking second", mode, err)
			}
		})
	}
}

func TestProfileComparisonCheckNeverResolvesAReplacementVersion(t *testing.T) {
	for _, source := range []string{"baseline", "incident"} {
		t.Run(source, func(t *testing.T) {
			f, s, pair := newComparisonAuthorizationFixture()
			selected := f.baseline
			if source == "incident" {
				selected = f.incident
			}
			selected.record.Version = artifact.Digest{99}
			if _, err := s.CheckProjectionCurrent(t.Context(), f, pair); !errors.Is(err, analysis.ErrUnavailable) {
				t.Fatal("fixed source version replaced", err)
			}
			resolved, err := s.ResolveProjectionCurrent(t.Context(), f, pair.Candidate())
			if err != nil || !resolved.Valid(f.now) {
				t.Fatal("version-free candidate could not resolve current source", err)
			}
			if source == "baseline" && resolved.Scope.Comparison.Baseline.Version != selected.record.Version || source == "incident" && resolved.Scope.Version != selected.record.Version {
				t.Fatal("resolved wrong source version")
			}
		})
	}
}

func TestProfileComparisonPreservesOriginalFirstDeadlineAndShortensCutoffs(t *testing.T) {
	f, s, pair := newComparisonAuthorizationFixture()
	start := f.now
	firstUntil := start.Add(3 * time.Second)
	f.baseline.record.ValidUntil = firstUntil
	f.incident.on = func(_ context.Context, step string, n int) {
		if step == "environment" && n == 2 {
			f.now = start.Add(time.Second)
			f.baseline.record.ValidUntil = start.Add(5 * time.Second)
			f.baseline.retention.ExpiresAt = start.Add(30 * time.Minute)
			f.baseline.retention.DeleteBy = start.Add(90 * time.Minute)
		}
	}
	f.baseline.on = func(ctx context.Context, step string, n int) {
		if step == "catalog" && n == 2 {
			d, ok := ctx.Deadline()
			if !ok || d.After(firstUntil) {
				t.Error("baseline recheck renewed original deadline", d)
			}
		}
	}
	out, err := s.CheckProjectionCurrent(t.Context(), f, pair)
	if err != nil || !out.Valid(f.now) || !out.ValidUntil.Equal(firstUntil) || !out.CheckedAt.Equal(start) || out.Baseline == nil || !out.Baseline.CheckedAt.Equal(start) || !out.Baseline.ValidUntil.Equal(firstUntil) || !out.AccessUntil.Equal(f.baseline.retention.ExpiresAt) || !out.DeleteBy.Equal(f.baseline.retention.DeleteBy) {
		t.Fatal("original timing or restrictive recheck lost", err, out)
	}
	if f.baseline.counts["identity"] != 9 || f.baseline.counts["permissions"] != 4 || f.incident.counts["permissions"] != 2 || f.baseline.counts["retention"] != 4 || f.incident.counts["retention"] != 2 || f.baseline.counts["environment"] != 4 || f.incident.counts["environment"] != 2 {
		t.Fatal("unexpected source calls", f.baseline.counts, f.incident.counts)
	}
}

func TestProfileComparisonPinsExistingRequestIdentityAcrossSourceChecks(t *testing.T) {
	for _, mode := range []string{"groups", "scopes", "policy", "client", "shortened-expiry"} {
		t.Run(mode, func(t *testing.T) {
			f, s, pair := newComparisonAuthorizationFixture()
			f.baseline.on = func(_ context.Context, step string, n int) {
				if step != "identity" || n != 4 {
					return
				}
				switch mode {
				case "groups":
					f.baseline.identity.Groups = append(f.baseline.identity.Groups, "other")
				case "scopes":
					f.baseline.identity.Scopes = append(f.baseline.identity.Scopes, "evidence:download")
				case "policy":
					f.baseline.identity.Policy.Generation++
				case "client":
					f.baseline.identity.Principal.ClientID = "other"
				case "shortened-expiry":
					f.baseline.identity.ValidUntil = f.now
				}
			}
			if _, err := s.CheckProjectionCurrent(t.Context(), f, pair); !errors.Is(err, analysis.ErrUnavailable) {
				t.Fatal("changed request identity was accepted", mode, err)
			}
		})
	}
}

func TestProfileComparisonIdentityStillReadsCurrentAndNeverRenewsAnEarlierBound(t *testing.T) {
	f, _, _ := newComparisonAuthorizationFixture()
	until := f.now.Add(time.Second)
	adapter := comparisonIdentity{source: f, now: func() time.Time { return f.now }}
	f.baseline.identity.ValidUntil = until
	first, err := adapter.ResolveIdentity(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	f.baseline.identity.ValidUntil = f.now.Add(30 * time.Second)
	second, err := adapter.ResolveIdentity(t.Context())
	if err != nil || !second.ValidUntil.Equal(until) || f.baseline.counts["identity"] != 2 {
		t.Fatal("identity was cached or renewed", err)
	}
	first.Groups[0] = "mutated-return"
	third, err := adapter.ResolveIdentity(t.Context())
	if err != nil || third.Groups[0] != "team" {
		t.Fatal("adapter borrowed return groups", err)
	}
	f.now = until
	if _, err := adapter.ResolveIdentity(t.Context()); err == nil {
		t.Fatal("expired original identity renewed")
	}
}

func TestProfileComparisonRequiresCommonPhysicalReaderAndGlobalRevisions(t *testing.T) {
	for _, mode := range []string{"same-reader-cross-target", "store", "installation", "worker-config", "permission-stream", "identity-policy", "recovery-epoch", "recovery-revision"} {
		t.Run(mode, func(t *testing.T) {
			f, s, pair := newComparisonAuthorizationFixture()
			switch mode {
			case "store":
				f.incident.record.Retained.Registration.StoreID = projectionTestID(999)
				f.incident.environment.StoreID = projectionTestID(999)
				f.incident.environment.Path.StoreID = projectionTestID(999)
			case "installation":
				f.incident.environment.InstallationID = projectionTestID(999)
				f.incident.environment.Recovery.InstallationID = projectionTestID(999)
			case "worker-config":
				f.incident.environment.Path.WorkerConfiguration.Generation++
			case "permission-stream":
				f.incident.permission.Revision.Generation++
			case "identity-policy":
				f.incident.environment.Principal.ClientID = "other"
			case "recovery-epoch":
				f.incident.environment.Recovery.IssuerEpoch = projectionTestID(999)
			case "recovery-revision":
				f.incident.environment.Recovery.Revision.Generation++
			}
			out, err := s.CheckProjectionCurrent(t.Context(), f, pair)
			if mode == "same-reader-cross-target" {
				if err != nil || !out.Valid(f.now) || out.Baseline.Environment.Path.TargetClusterID == out.Environment.Path.TargetClusterID || out.Baseline.Environment.Path.ID == out.Environment.Path.ID {
					t.Fatal("same physical reader rejected distinct accepted routes", err)
				}
			} else if !errors.Is(err, analysis.ErrUnavailable) || out != (analysis.ContextProjectionAuthority{}) {
				t.Fatal("incompatible pair authorized", mode, err)
			}
		})
	}
}

func TestProfileComparisonReturnsOwnedBaselineAndBindsPairSelection(t *testing.T) {
	f, s, pair := newComparisonAuthorizationFixture()
	first, err := s.CheckProjectionCurrent(t.Context(), f, pair)
	if err != nil {
		t.Fatal(err)
	}
	other := pair
	other.Comparison.Normalization = analysis.ProfileComparisonRaw
	next, err := s.CheckProjectionCurrent(t.Context(), f, other)
	if err != nil || first.Baseline == next.Baseline || first.DecisionDigest == next.DecisionDigest {
		t.Fatal("pair selection/delivery ownership not bound", err)
	}
	first.Baseline.Environment.Processing.StateDigest[0]++
	first.Baseline.Scope.PodUID = "mutated-return"
	if !next.Valid(f.now) || f.baseline.environment.Processing.StateDigest != next.Baseline.Environment.Processing.StateDigest || f.baseline.record.Retained.Input.Target.PodUID != next.Baseline.Scope.PodUID {
		t.Fatal("returned child aliased fixture or another result")
	}
	f.baseline.environment.Path.WorkerConfiguration.Generation++
	if !next.Valid(f.now) {
		t.Fatal("returned child borrowed provider state")
	}
}

func TestProfileComparisonSameArtifactStillAuthorizesTwice(t *testing.T) {
	f, s, pair := newComparisonAuthorizationFixture()
	f.incident = f.baseline
	b := pair.Comparison.Baseline
	pair.CaseID, pair.ArtifactID, pair.CaptureID, pair.ClusterID = b.CaseID, b.ArtifactID, b.CaptureID, b.ClusterID
	pair.NamespaceUID, pair.WorkloadUID, pair.PodUID, pair.Version = b.NamespaceUID, b.WorkloadUID, b.PodUID, b.Version
	out, err := s.CheckProjectionCurrent(t.Context(), f, pair)
	if err != nil || !out.Valid(f.now) || f.baseline.counts["catalog"] != 3 || f.baseline.counts["permissions"] != 6 || f.baseline.counts["identity"] != 9 {
		t.Fatal("same artifact skipped independent authorizations", err, f.baseline.counts)
	}
}
