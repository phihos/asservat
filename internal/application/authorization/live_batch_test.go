package authorization

import (
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/live"
	"asservat.local/asservat/internal/domain/privacy"
	"context"
	"fmt"
	"testing"
	"time"
)

type livePhaseFixture struct {
	*liveAuthorityFixture
	records              []LiveSourceRecord
	podReads, batchReads int
}

func (f *livePhaseFixture) Permissions(ctx context.Context, target value.Target) (value.Projection, error) {
	f.podReads++
	return f.fixture.Permissions(ctx, target)
}
func (f *livePhaseFixture) ReadLiveSourceRecords(context.Context, []live.SourceReference) ([]LiveSourceRecord, error) {
	f.batchReads++
	return append([]LiveSourceRecord(nil), f.records...), nil
}

func TestLiveAuthorizationPhasesShareOnlyCommonObservationsAtOneAndSixteenSources(t *testing.T) {
	for _, count := range []int{1, 16} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			base, s := liveAuthFixture()
			// This test exercises real context deadlines; align synthetic
			// observations with the authority clock instead of October's
			// historical pure-domain fixture date.
			now := time.Now().UTC()
			base.now = now
			base.i.VerifiedAt = now
			base.i.ValidUntil = now.Add(30 * time.Second)
			base.p.ObservedAt = now
			base.p.FreshUntil = now.Add(30 * time.Second)
			base.p.DeniesObservedAt = now
			base.p.DeniesFreshUntil = now.Add(5 * time.Second)
			for n := range base.p.Allows {
				base.p.Allows[n].ObservedAt = now
				base.p.Allows[n].FreshUntil = now.Add(30 * time.Second)
			}
			base.record.ObservedAt = now
			base.record.ValidUntil = now.Add(5 * time.Second)
			base.record.Source.LeaseUntil = now.Add(20 * time.Second)
			base.record.Source.HardUntil = now.Add(20 * time.Second)
			base.record.Source.Manual.StartedAt = now
			base.record.Source.Manual.HardUntil = base.record.Source.HardUntil
			base.record.Source.PrivacyUntil = now.Add(time.Hour)
			f := &livePhaseFixture{liveAuthorityFixture: base}
			environment, _, _, _ := newEnvironmentFixture()
			environment.now = base.now
			environment.policy.ObservedAt = base.now
			environment.policy.FreshUntil = base.now.Add(5 * time.Second)
			environment.recovery.ObservedAt = base.now
			environment.recovery.FreshUntil = base.now.Add(5 * time.Second)
			environment.policy.RootID = base.record.Source.Root()
			environment.policy.Paths[0].TargetClusterID = base.record.Source.Target.ClusterID
			actor := base.i.Principal
			root := privacy.LiveRootLimits{Watches: 16, PrincipalWatches: 16, WorkloadWatches: 16, Rate: 1 << 20, Burst: 1 << 20}
			environment.policy.LiveRead = &privacy.LiveRead{Root: root, Projections: []string{live.Packet}, Clients: []privacy.LiveClient{{Issuer: actor.Issuer, ID: actor.ClientID, Kind: actor.Kind, PathIDs: []string{environment.policy.Paths[0].ID}}}, Ceilings: []privacy.LiveCeiling{{ClusterID: base.record.Source.Target.ClusterID, Limits: privacy.LiveLimits{Duration: 60, Output: 1 << 20, Rate: 16 << 10, Rows: 10, Buffer: 64 << 10, RowAge: 10, Replay: 2}}}}
			s.Catalog = f
			s.Permissions = f
			s.Environment = CurrentLiveEnvironment{RootID: s.RootID, InstallationID: environment.policy.InstallationID, AcceptedRoot: root, Policies: environment, Recovery: environment, Now: func() time.Time { return environment.now }}
			expected := make([]live.Source, count)
			for n := range expected {
				record := base.record
				record.Source = record.Source.Clone()
				record.Source.Manual.CaptureID = fmt.Sprintf("00000000-0000-4000-8000-%012d", n+1)
				record.Source.OwnerID = record.Source.Manual.CaptureID
				expected[n] = record.Source.Clone()
				f.records = append(f.records, record)
			}
			for phase := 1; phase <= 2; phase++ {
				got, end, err := s.CheckSources(t.Context(), f, expected, live.Packet)
				if err != nil || len(got) != count || !end.After(base.now) || f.podReads != count*phase || f.batchReads != phase || environment.policyReads != phase || environment.recoveryReads != phase {
					t.Fatalf("sources=%d phase=%d result=%d error=%v pod=%d sourcebatch=%d policy=%d recovery=%d", count, phase, len(got), err, f.podReads, f.batchReads, environment.policyReads, environment.recoveryReads)
				}
			}
			// The post-node phase cannot reuse the previous phase's positive policy.
			environment.policy.LiveRead.Clients = []privacy.LiveClient{}
			if _, _, err := s.CheckSources(t.Context(), f, expected, live.Packet); err == nil {
				t.Fatal("authority crossed phases")
			}
		})
	}
}
