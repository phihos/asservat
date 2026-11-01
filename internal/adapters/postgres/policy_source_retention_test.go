package postgres

import (
	"encoding/json"
	"testing"
	"time"

	captureapp "asservat.local/asservat/internal/application/capture"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
)

// Structural/current-time guard only, not accepted SQL authority. Real profile
// compilation and retention arithmetic establish requested vs effective age.
func sourceRetentionCheckFixture(t *testing.T, maximum, deletion int64) (captureapp.PolicySourceCheck, time.Time) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	preview := previewTestValue(t)
	var scope authorization.PolicyGrantScope
	if err := json.Unmarshal(policyGrantTestRow(t).PolicyScope, &scope); err != nil {
		t.Fatal(err)
	}
	a := scope.Authority
	a.Limits.MaxObservedBytes = 1 << 20
	if !a.Valid(now) {
		t.Fatal("invalid synthetic accepted-policy fixture")
	}
	composition := planning.ProfileComposition{Components: []planning.ProfileComponent{{ID: "net", Profile: planning.ProfileRef{Catalog: "builtin", Name: "network-connections", Version: "v1"}}}, MaxTotalBytes: 16 << 20, MaxDuration: "20s"}
	recorder, err := compiler.CompileOngoingPolicyRecorder(composition, nil)
	if err != nil {
		t.Fatal("ongoing profile fixture", err)
	}
	p := value.RestartPolicy{ClusterID: a.ClusterID, Namespace: preview.Target.Namespace.Name, WorkloadKind: preview.Target.Workload.Kind, WorkloadName: preview.Target.Workload.Name, Reasons: []string{"Error"}, Interval: time.Minute, Burst: 1, RetentionSeconds: 60, ObservedPods: 1, Recorder: &recorder}
	r := preview.Target
	target := targets.PodResolution{ExecutionClass: artifact.ContextAPIExecution, Request: r, Pin: artifact.PinnedPod{Namespace: r.Namespace.Name, NamespaceUID: r.Namespace.UID, Name: r.PodName, UID: r.PodUID, ControllerUID: "replicaset"}, PodResourceVersion: "1", WorkloadResourceVersion: "1", ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	revision := identity.Revision{UID: preview.ID, Generation: 1, Digest: artifact.Digest{1}}
	proof := artifact.RetentionProof{RootID: preview.RootID, ClusterID: a.ClusterID, NamespaceUID: a.NamespaceUID, WorkloadUID: a.WorkloadUID, PodUID: target.Pin.UID, Topology: revision, Policy: revision, Selectors: revision, ObservedAt: now, ValidUntil: now.Add(5 * time.Second), SourceCount: 1, Sources: [2]artifact.RetentionSourceVersion{{ClusterID: a.ClusterID, ControlNamespaceUID: "control", Epoch: preview.ID, Hub: true, ProtectionDigest: artifact.Digest{1}, SnapshotDigest: artifact.Digest{2}, Acceptance: revision}}}
	set := privacy.PolicySet{Target: target.Target(), Revision: revision, Complete: true, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), Proof: proof, Policies: []privacy.Policy{{Revision: revision, Baseline: true, PurposeRef: "diagnostics", DefaultSeconds: 10, MaximumSeconds: maximum, DeletionBudgetSeconds: deletion}}}
	retention, err := privacy.Resolve(set, privacy.Input{Target: target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: "packetCapture", RequestedSeconds: 60, AnchorAt: now}, now)
	if err != nil {
		t.Fatal("actual retention resolver", err)
	}
	settings := identity.Policy{Revision: revision, Issuer: a.Creator.Issuer, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), Clients: []identity.Client{{ID: a.Creator.ClientID, Kind: identity.Human, ClassQualified: true}}, EligibleGroups: []string{"team"}, GroupsAtIssueQualified: true, GroupMaxAge: time.Minute}
	return captureapp.PolicySourceCheck{Policy: p, Authority: a, Target: target, Node: targets.PacketSourceObservation{PodUID: target.Pin.UID, NodeUID: preview.ID, BootID: preview.ID, CollectorPodUID: preview.ID, CollectorEpoch: preview.ID, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, Recovery: artifact.RecoveryProof{InstallationID: a.InstallationID, IssuerEpoch: preview.ID, Revision: revision, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, Retention: retention, Settings: settings, SourceID: preview.ID, Fence: preview.ID, BytesPerSecond: 1 << 20, SourceSlots: 1, Initial: true, InitialCredit: 1 << 20, ObservedAt: now, ValidUntil: now.Add(5 * time.Second)}, now
}

func TestPolicySourceRingFitsEffectiveContentRetention(t *testing.T) {
	baseline, now := sourceRetentionCheckFixture(t, 120, 20)
	if !sourceCheckCurrent(baseline, now) {
		t.Fatal("valid baseline source refused before effective-age negative")
	}
	constrained, at := sourceRetentionCheckFixture(t, 40, 20)
	if constrained.Retention.RequestedSeconds != 60 || constrained.Retention.ExpiresAt.Sub(constrained.Retention.AnchorAt) != 20*time.Second {
		t.Fatal("fixture failed to preserve requested60s versus effective20s")
	}
	if sourceCheckCurrent(constrained, at) {
		t.Fatal("30s live ring accepted beyond administrator-resolved20s content expiry merely because requested retention was60s")
	}
}
