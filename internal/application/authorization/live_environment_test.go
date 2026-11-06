package authorization

import (
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/live"
	"asservat.local/asservat/internal/domain/privacy"
	"context"
	"testing"
	"time"
)

func TestCurrentLiveEnvironmentRetainsOriginalPolicyRecoveryAndClientBounds(t *testing.T) {
	for _, mode := range []string{"valid", "disabled", "download-only", "projection", "region", "scope", "changed-policy", "changed-recovery", "late-policy", "late-final", "parent"} {
		t.Run(mode, func(t *testing.T) {
			f, _, r, actor := newEnvironmentFixture()
			target := authorization.Target{ClusterID: r.Retained.Input.Target.ClusterID, NamespaceUID: r.Retained.Input.Target.NamespaceUID, WorkloadUID: r.Retained.Input.Target.WorkloadUID, PodUID: r.Retained.Input.Target.PodUID}
			source := live.Source{RootID: f.policy.RootID, Target: target}
			// Only the root is relevant to this environment port; C3 owns exact source proof.
			source.Manual = &collector.ManualLiveSource{}
			f.policy.LiveRead = &privacy.LiveRead{Root: privacy.LiveRootLimits{Watches: 16, PrincipalWatches: 4, WorkloadWatches: 4, Rate: 1 << 20, Burst: 1 << 20}, Projections: []string{live.Packet}, Clients: []privacy.LiveClient{{Issuer: actor.Issuer, ID: actor.ClientID, Kind: actor.Kind, PathIDs: []string{f.policy.Paths[0].ID}}}, Ceilings: []privacy.LiveCeiling{{ClusterID: target.ClusterID, Limits: privacy.LiveLimits{Duration: 60, Output: 1 << 20, Rate: 16 << 10, Rows: 10, Buffer: 64 << 10, RowAge: 10, Replay: 2}}}}
			s := CurrentLiveEnvironment{RootID: f.policy.RootID, InstallationID: f.policy.InstallationID, AcceptedRoot: f.policy.LiveRead.Root, Policies: f, Recovery: f, Now: func() time.Time { return f.now }}
			ctx := t.Context()
			original := f.now.Add(time.Second)
			f.policy.FreshUntil = original
			switch mode {
			case "disabled":
				f.policy.LiveRead = nil
			case "download-only":
				f.policy.LiveRead.Clients = []privacy.LiveClient{}
			case "projection":
				f.policy.LiveRead.Projections = []string{live.HTTP}
			case "region":
				f.policy.PermittedRegions = []string{}
			case "scope":
				f.policy.LiveRead.Ceilings[0].ClusterID = "99999999-9999-4999-8999-999999999999"
			case "changed-policy":
				f.policyHook = func() {
					if f.policyReads == 2 {
						f.policy.Revision.Generation++
					}
				}
			case "changed-recovery":
				f.recoveryHook = func() {
					if f.recoveryReads == 2 {
						f.recovery.Revision.Generation++
					}
				}
			case "late-policy":
				f.policyHook = func() {
					if f.policyReads == 1 {
						f.now = original
					}
				}
			case "late-final":
				f.recoveryHook = func() {
					if f.recoveryReads == 2 {
						f.now = original
					}
				}
			case "parent":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			out, err := s.LiveSourceRead(ctx, source, live.Packet, actor)
			if mode != "valid" {
				if err == nil {
					t.Fatal("invalid live environment accepted", out)
				}
				return
			}
			if err != nil || !out.ValidUntil.Equal(original) || out.Limits.Rows != 10 || out.Limits.RowAge != 10 || f.policyReads != 2 || f.recoveryReads != 2 || f.processingReads != 0 {
				t.Fatal(out, err, f.policyReads, f.recoveryReads)
			}
		})
	}
}
