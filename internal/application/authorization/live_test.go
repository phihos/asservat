package authorization

import (
	identities "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	live "asservat.local/asservat/internal/domain/live"
	"asservat.local/asservat/internal/domain/targets"
	"context"
	"errors"
	"testing"
	"time"
)

type liveAuthorityFixture struct {
	*fixture
	record                         LiveSourceRecord
	catalogReads, environmentReads int
	disabled                       bool
	afterRead                      func()
}

func (f *liveAuthorityFixture) ResolveIdentity(context.Context) (identity.Identity, error) {
	return f.i, nil
}
func (f *liveAuthorityFixture) ResolveWorkloadIdentity(_ context.Context, r targets.WorkloadRequest) (targets.WorkloadIdentityResolution, error) {
	return targets.WorkloadIdentityResolution{Reference: r, ClusterID: r.ClusterID, Namespace: configuration.NamespaceRef{Name: r.Namespace, UID: f.p.Target.NamespaceUID}, Workload: configuration.WorkloadRef{Kind: r.Kind, Name: r.Name, UID: f.p.Target.WorkloadUID}, ObservedAt: f.now, FreshUntil: f.now.Add(5 * time.Second)}, nil
}
func (f *liveAuthorityFixture) WorkloadPermissions(context.Context, value.WorkloadTarget) (value.WorkloadProjection, error) {
	p := f.p
	return value.WorkloadProjection{Target: value.WorkloadTarget{ClusterID: p.Target.ClusterID, NamespaceUID: p.Target.NamespaceUID, WorkloadUID: p.Target.WorkloadUID}, Revision: p.Revision, ObservedAt: p.ObservedAt, FreshUntil: p.FreshUntil, DeniesComplete: p.DeniesComplete, DeniesObservedAt: p.DeniesObservedAt, DeniesFreshUntil: p.DeniesFreshUntil, Allows: p.Allows, Denies: p.Denies}, nil
}
func (f *liveAuthorityFixture) ListLiveSources(context.Context, value.WorkloadTarget, string, int) ([]LiveSourceRecord, string, error) {
	f.catalogReads++
	return []LiveSourceRecord{f.record}, "", nil
}
func (f *liveAuthorityFixture) ReadLiveSource(context.Context, live.Source) (LiveSourceRecord, error) {
	f.catalogReads++
	if f.afterRead != nil {
		f.afterRead()
	}
	return f.record, nil
}
func (f *liveAuthorityFixture) LiveSourceRead(context.Context, live.Source, string, identity.Principal) (LiveEnvironmentDecision, error) {
	f.environmentReads++
	if f.disabled {
		return LiveEnvironmentDecision{}, live.ErrDenied
	}
	return LiveEnvironmentDecision{ValidUntil: f.now.Add(5 * time.Second), Limits: live.DefaultLimits(), Projections: []string{live.Packet, live.HTTP, live.Syscall}}, nil
}
func liveAuthFixture() (*liveAuthorityFixture, LiveSourceAuthority) {
	f, _, _ := newFixture()
	id := "11111111-1111-4111-8111-111111111111"
	f.i.Scopes = []string{"evidence:read"}
	f.p.Target.PodUID = id
	f.e.Target = f.p.Target
	m := collector.ManualLiveSource{RootID: id, ExecutorPodUID: id, ExecutorEpoch: id, CaptureID: id, AttemptID: id, ActionID: "packets", WorkID: id, PodUID: id, NodeUID: id, BootID: id, CollectorPodUID: id, CollectorEpoch: id, Scope: [32]byte{1}, ExpectationDigest: [32]byte{3}, StartedAt: f.now, HardUntil: f.now.Add(20 * time.Second)}
	source := live.Source{RootID: id, Manual: &m, Target: f.p.Target, OwnerKind: "manualSession", OwnerID: id, State: "Ready", SaveVia: "captureOutcome", Projections: []string{live.Packet}, LeaseUntil: f.now.Add(20 * time.Second), HardUntil: f.now.Add(20 * time.Second), PrivacyUntil: f.now.Add(time.Hour)}
	original := f.i
	original.Scopes = []string{"evidence:capture"}
	original.ValidUntil = f.now.Add(5 * time.Second)
	l := &liveAuthorityFixture{fixture: f, record: LiveSourceRecord{Source: source, Audience: f.e.Audience, Executor: original.Principal, ObservedAt: f.now, ValidUntil: f.now.Add(5 * time.Second)}}
	return l, LiveSourceAuthority{RootID: id, Targets: l, Workloads: l, Permissions: l, Catalog: l, Environment: l, Now: func() time.Time { return l.now }}
}

var _ identities.CurrentIdentity = (*liveAuthorityFixture)(nil)

func TestLiveAuthorityReadOnlyViewerNeedsMaintainerOriginalAudienceAndCurrentFiniteExecution(t *testing.T) {
	f, s := liveAuthFixture()
	expected := f.record.Source.Clone()
	source, end, e := s.Check(t.Context(), f, expected, live.Packet)
	if e != nil || !source.Same(expected) || !end.Equal(f.record.ValidUntil) || f.catalogReads != 1 {
		t.Fatal(source, end, e)
	}
	for _, mode := range []string{"reader", "owner", "denied", "changed-original-audience", "execution-ended", "source-replaced", "feature-disabled", "late-catalog"} {
		t.Run(mode, func(t *testing.T) {
			f, s := liveAuthFixture()
			expected := f.record.Source.Clone()
			switch mode {
			case "reader":
				f.p.Allows[0].Audience.Role = "evidence-reader"
			case "owner":
				f.p.Allows[0].Audience.Role = "evidence-owner"
			case "denied":
				f.p.Denies = f.p.Allows
			case "changed-original-audience":
				f.record.Audience = append(f.record.Audience[:0:0], f.record.Audience...)
				f.record.Audience[0].AssignmentID = "22222222-2222-4222-8222-111111111111"
			case "execution-ended":
				f.record.ValidUntil = f.now
			case "source-replaced":
				f.record.Source.Manual.WorkID = "22222222-2222-4222-8222-111111111111"
			case "feature-disabled":
				f.disabled = true
			case "late-catalog":
				f.afterRead = func() { f.now = f.now.Add(6 * time.Second) }
			}
			_, _, e := s.Check(t.Context(), f, expected, live.Packet)
			if mode == "late-catalog" {
				if !errors.Is(e, live.ErrUnavailable) || errors.Is(e, live.ErrDenied) {
					t.Fatal("elapsed observation became an access decision", e)
				}
			} else if !errors.Is(e, live.ErrDenied) || errors.Is(e, live.ErrUnavailable) {
				t.Fatal("actual access change treated as a transient observation", e)
			}
			if (mode == "reader" || mode == "owner" || mode == "denied") && f.catalogReads != 0 {
				t.Fatal("protected lookup before ordinary maintainer rights")
			}
			if mode == "late-catalog" && f.environmentReads != 0 {
				t.Fatal("advanced after original source proof expiry")
			}
		})
	}
}

func TestLiveAuthorityChangedIdentityAfterSourceReadCannotDisclose(t *testing.T) {
	f, s := liveAuthFixture()
	expected := f.record.Source.Clone()
	f.afterRead = func() { f.i.Groups = append(f.i.Groups[:0:0], "replacement-group") }
	if _, _, e := s.Check(t.Context(), f, expected, live.Packet); e == nil {
		t.Fatal("changed identity after blocking source lookup accepted")
	}
}

func (f *liveAuthorityFixture) LiveSourceTarget(context.Context, string, string) (value.Target, error) {
	return f.record.Source.Target, nil
}
func (f *liveAuthorityFixture) ReadLiveSourceID(ctx context.Context, _ value.Target, _ string, _ string) (LiveSourceRecord, error) {
	return f.ReadLiveSource(ctx, f.record.Source)
}

func TestLiveManualAcceptedExecutionDoesNotReconstructOldHumanIdentity(t *testing.T) {
	f, s := liveAuthFixture()
	// The protected catalog/holder supplies the existing accepted execution and
	// its original finite interval. It cannot recreate old human token/groups.

	if _, _, err := s.Check(t.Context(), f, f.record.Source.Clone(), live.Packet); err != nil {
		t.Fatal("accepted finite source incorrectly required reconstructed executor identity", err)
	}
}
