package bootstrap

import (
	"context"
	"errors"
	"testing"
	"time"

	captureapp "asservat.local/asservat/internal/application/capture"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	capture "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/live"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

type liveCatalogFixture struct {
	rows                                  []captureapp.RecordingCandidate
	policy                                captureapp.RecordingPolicy
	replies                               []targets.SourceSnapshotResolution
	scans, lookups, compiles, statusReads int
	statusError                           bool
}

func (f *liveCatalogFixture) LiveSourceTarget(context.Context, string) (authorization.Target, error) {
	return f.rows[0].Source.Target.Target(), nil
}
func (f *liveCatalogFixture) RecordingCandidates(context.Context, authorization.WorkloadTarget, captureapp.RecordingCandidateQuery) (captureapp.RecordingCandidatePage, error) {
	f.scans++
	return captureapp.RecordingCandidatePage{Rows: f.rows}, nil
}
func (f *liveCatalogFixture) RecordingSources(context.Context, authorization.WorkloadTarget, []string) ([]captureapp.RecordingCandidate, error) {
	f.lookups++
	return f.rows[:1], nil
}
func (f *liveCatalogFixture) SourcePolicy(context.Context, string, string) (captureapp.RecordingPolicy, error) {
	f.compiles++
	return f.policy, nil
}
func (f *liveCatalogFixture) ResolveSourceSnapshots(context.Context, []targets.SourceSnapshotTarget) ([]targets.SourceSnapshotResolution, error) {
	f.statusReads++
	if f.statusError {
		return nil, live.ErrUnavailable
	}
	return f.replies, nil
}
func newLiveCatalogFixture(t *testing.T) (liveSourceCatalog, *liveCatalogFixture, authorization.WorkloadTarget) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	permit := sourceOwnerPermit(now.Add(-time.Second))
	b := permit.Binding
	id := b.PodUID
	request := targets.Request{ClusterID: id, Namespace: configuration.NamespaceRef{Name: "app", UID: id}, Workload: configuration.WorkloadRef{Kind: "Pod", Name: "pod", UID: id}, PodName: "pod", PodUID: id}
	original := targets.SourceSnapshotTarget{Request: request, Pin: artifact.PinnedPod{Namespace: "app", NamespaceUID: id, Name: "pod", UID: id}, NodeUID: b.NodeUID, BootID: b.BootID, CollectorPodUID: b.CollectorPodUID, CollectorEpoch: b.CollectorEpoch, SourceID: b.SourceID, Fence: b.Fence, BindingDigest: [32]byte{1}}
	state := captureapp.PolicySourceState{Binding: b, ClusterID: id, NamespaceUID: id, WorkloadUID: id, Target: &original, StartedAt: permit.StartedAt, HardUntil: permit.HardUntil, InitialLeafUntil: permit.LeafUntil, Audience: []artifact.AudienceAssignment{}}
	authority := authorization.AcceptedPolicyAuthority{PolicyUID: b.PolicyUID, ScopeDigest: artifact.Digest(b.Scope), ClusterID: id, NamespaceUID: id, WorkloadUID: id}
	policy := captureapp.RecordingPolicy{Policy: capture.RestartPolicy{Recorder: &planning.PolicyRecorderConfiguration{Digest: artifact.Digest(b.ExpectationDigest), Action: planning.RecorderAction{ID: b.ActionID, Kind: "packetCapture", PacketProfile: "networkHeaders", ExecutionMode: "ongoing"}}}, Accepted: authorization.AcceptedPolicySnapshot{Authority: authority, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}}
	reply := targets.SourceSnapshotResolution{Original: original, Process: targets.PacketSourceObservation{PodUID: id, NodeUID: b.NodeUID, BootID: b.BootID, CollectorPodUID: b.CollectorPodUID, CollectorEpoch: b.CollectorEpoch, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, State: targets.RecorderSourceState{SourceID: b.SourceID, Fence: b.Fence, IssuedAt: permit.IssuedAt, LeafUntil: permit.LeafUntil, Credit: permit.Credit, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), ReportedAt: now, ReportFreshUntil: now.Add(5 * time.Second), LiveProjections: []string{live.Packet}}
	f := &liveCatalogFixture{rows: []captureapp.RecordingCandidate{{PolicyName: "source", Source: state}}, policy: policy, replies: []targets.SourceSnapshotResolution{reply}}
	return liveSourceCatalog{root: b.RootID, candidates: f, policies: f, status: f, now: func() time.Time { return now }}, f, authorization.WorkloadTarget{ClusterID: id, NamespaceUID: id, WorkloadUID: id}
}
func TestLiveCatalogNeedsActualCurrentCapabilityAndOriginalSourceWithoutSaveOptIn(t *testing.T) {
	for _, mode := range []string{"valid", "old-node", "status-unavailable", "replaced-source", "changed-policy", "expired-report", "input-unknown", "existing-thirty-second-policy-observation"} {
		t.Run(mode, func(t *testing.T) {
			s, f, target := newLiveCatalogFixture(t)
			switch mode {
			case "existing-thirty-second-policy-observation":
				f.policy.Accepted.ObservedAt = s.now().Add(-10 * time.Second)
				f.policy.Accepted.FreshUntil = s.now().Add(20 * time.Second)
			case "old-node":
				f.replies[0].LiveProjections = nil
			case "status-unavailable":
				f.statusError = true
			case "replaced-source":
				f.replies[0].Original.Fence = "22222222-2222-4222-8222-222222222222"
			case "changed-policy":
				f.policy.Accepted.Authority.ScopeDigest = artifact.Digest{99}
			case "expired-report":
				f.replies[0].FreshUntil = s.now()
			case "input-unknown":
				f.replies[0].State.InputUnknown = true
			}
			out, _, err := s.ListLiveSources(t.Context(), target, "", 20)
			if mode == "replaced-source" || mode == "expired-report" {
				if err == nil {
					t.Fatal("invalid original report accepted")
				}
				return
			}
			if mode == "changed-policy" {
				if err != nil || len(out) != 0 {
					t.Fatal(out, err)
				}
				return
			}
			if err != nil || len(out) != 1 || out[0].Source.SaveVia != "unavailable" || f.scans != 1 || f.lookups != 0 || f.compiles != 1 || f.statusReads != 1 {
				t.Fatal(out, err, f)
			}
			if mode == "existing-thirty-second-policy-observation" && (!out[0].ObservedAt.Equal(s.now()) || out[0].ValidUntil.After(s.now().Add(5*time.Second))) {
				t.Fatal("record reused the policy observer clock or extended the current read", out[0])
			}
			row := out[0].Source
			if mode == "old-node" || mode == "status-unavailable" {
				if row.State != "Unavailable" || len(row.Projections) != 0 {
					t.Fatal("invented live capability", row)
				}
				return
			}
			if !row.Valid(s.now()) || len(row.Projections) != 1 || row.Projections[0] != live.Packet || !row.LeaseUntil.Equal(f.replies[0].State.LeafUntil) || row.State == "Ready" && mode == "input-unknown" {
				t.Fatal(row)
			}
		})
	}
}

func TestLiveCatalogExactReadRetainsStatusMissAsUnavailable(t *testing.T) {
	s, f, _ := newLiveCatalogFixture(t)
	original := f.rows[0].Source
	refs := []live.SourceReference{{ID: original.Binding.SourceID, Kind: "policy", Target: original.Target.Target()}}
	f.statusError = true
	rows, err := s.ReadLiveSourceRecords(t.Context(), refs)
	if !errors.Is(err, live.ErrUnavailable) || errors.Is(err, live.ErrDenied) || len(rows) != 0 {
		t.Fatal("status miss reached authorization as a source with no projection", len(rows), err)
	}
	// A new read may observe the same original source again. Neither the failed
	// read nor recovery creates a recorder or renews its lease or hard deadline.
	f.statusError = false
	rows, err = s.ReadLiveSourceRecords(t.Context(), refs)
	if err != nil || len(rows) != 1 || rows[0].Source.Binding != original.Binding || !rows[0].Source.LeaseUntil.Equal(f.replies[0].State.LeafUntil) || !rows[0].Source.HardUntil.Equal(original.HardUntil) || f.lookups != 2 || f.statusReads != 2 {
		t.Fatal("fresh read changed the original source or bounds", len(rows), err)
	}
}
