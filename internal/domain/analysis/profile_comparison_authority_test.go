package analysis

import (
	"asservat.local/asservat/internal/domain/authorization"
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

func comparisonAuthorityFixture() ContextProjectionAuthority {
	a := testAuthority()
	a.Scope.NativeType, a.Scope.SourceFormat, a.Scope.DisplayVersion = artifact.PprofArtifact, artifact.PprofFormat, ProfileComparisonDisplayVersion
	a.Scope.SourceProjectionDigest, a.Scope.Selection, a.Scope.Profile = artifact.Digest{}, LineSelection{}, ProfileSummarySelection{SampleType: "cpu", TopN: 20}
	a.Scope.Comparison = ProfileComparisonWindow{Normalization: ProfileComparisonRate, Baseline: ProfileComparisonBaseline{CaseID: queryOtherID, ArtifactID: queryOtherID, CaptureID: queryOtherID, ClusterID: queryOtherID, NamespaceUID: "baseline-ns", WorkloadUID: "baseline-workload", PodUID: "baseline-pod", Version: artifact.Digest{4}}}
	b := a
	b.Scope, _ = a.Scope.BaselineScope()
	b.Environment.Location.ClusterID = b.Scope.ClusterID
	b.Environment.Location.ArtifactID = b.Scope.ArtifactID
	b.Environment.Processing.Location = b.Environment.Location
	b.Environment.Processing.CaptureID = b.Scope.CaptureID
	b.Environment.Path.ID = queryOtherID
	b.Environment.Path.TargetClusterID = b.Scope.ClusterID
	b.Retention.ClusterID = b.Scope.ClusterID
	b.Retention.NamespaceUID = b.Scope.NamespaceUID
	b.Retention.WorkloadUID = b.Scope.WorkloadUID
	b.Retention.PodUID = b.Scope.PodUID
	b.Retention.Sources[0].ClusterID = b.Scope.ClusterID
	a.Baseline = &b
	return a
}

func TestProfileComparisonAuthorityRequiresExactlyOneMatchingLegacyChild(t *testing.T) {
	valid := comparisonAuthorityFixture()
	now := valid.CheckedAt.Add(time.Second)
	if !valid.Valid(now) || !valid.Baseline.Valid(now) {
		t.Fatal("independent legacy child refused")
	}
	for name, mutate := range map[string]func(*ContextProjectionAuthority){
		"missing-child":     func(a *ContextProjectionAuthority) { a.Baseline = nil },
		"nested-child":      func(a *ContextProjectionAuthority) { child := testAuthority(); a.Baseline.Baseline = &child },
		"compound-child":    func(a *ContextProjectionAuthority) { a.Baseline.Scope = a.Scope },
		"child-version":     func(a *ContextProjectionAuthority) { a.Baseline.Scope.Version[0]++ },
		"child-route":       func(a *ContextProjectionAuthority) { a.Baseline.Scope.CaseID = queryTestID },
		"identity-policy":   func(a *ContextProjectionAuthority) { a.Baseline.IdentityRevision.Generation++ },
		"permission-stream": func(a *ContextProjectionAuthority) { a.Baseline.PermissionRevision.Generation++ },
		"recovery-epoch":    func(a *ContextProjectionAuthority) { a.Baseline.Environment.Recovery.IssuerEpoch = queryOtherID },
		"recovery-revision": func(a *ContextProjectionAuthority) { a.Baseline.Environment.Recovery.Revision.Generation++ },
		"physical-config":   func(a *ContextProjectionAuthority) { a.Baseline.Environment.Path.WorkerConfiguration.Generation++ },
		"first-checked-at":  func(a *ContextProjectionAuthority) { a.CheckedAt = a.CheckedAt.Add(time.Nanosecond) },
		"first-deadline":    func(a *ContextProjectionAuthority) { a.Baseline.ValidUntil = a.ValidUntil.Add(-time.Nanosecond) },
		"first-access":      func(a *ContextProjectionAuthority) { a.Baseline.AccessUntil = a.AccessUntil.Add(-time.Nanosecond) },
		"first-deletion":    func(a *ContextProjectionAuthority) { a.Baseline.DeleteBy = a.DeleteBy.Add(-time.Nanosecond) },
		"expired-child":     func(a *ContextProjectionAuthority) { a.Baseline.ValidUntil = now },
	} {
		t.Run(name, func(t *testing.T) {
			a := valid
			b := *valid.Baseline
			a.Baseline = &b
			mutate(&a)
			if a.Valid(now) {
				t.Fatal("invalid compound authority accepted")
			}
		})
	}
	// Refuse cycles before a recursive Valid call, including a self-referential
	// comparison and a legacy child pointing back to its compound parent.
	self := valid
	self.Baseline = &self
	if self.Valid(now) {
		t.Fatal("self-cycle accepted")
	}
	cycle := valid
	child := *valid.Baseline
	cycle.Baseline = &child
	child.Baseline = &cycle
	if cycle.Valid(now) {
		t.Fatal("child cycle accepted")
	}
	legacy := testAuthority()
	legacy.Baseline = valid.Baseline
	if legacy.Valid(now) {
		t.Fatal("legacy authority accepted comparison child")
	}
}

func TestProfileComparisonAuthorityKeepsLegacyAuthorityJSON(t *testing.T) {
	a := testAuthority()
	// Explicit pre-comparison layout keeps the persisted decision's field order.
	old := struct {
		Scope                                        ContextProjectionScope
		Environment                                  ContextProjectionEnvironment
		Retention                                    artifact.RetentionProof
		PermissionRevision, IdentityRevision         identity.Revision
		DecisionDigest                               artifact.Digest
		CheckedAt, ValidUntil, AccessUntil, DeleteBy time.Time
	}{a.Scope, a.Environment, a.Retention, a.PermissionRevision, a.IdentityRevision, a.DecisionDigest, a.CheckedAt, a.ValidUntil, a.AccessUntil, a.DeleteBy}
	got, err := json.Marshal(a)
	want, otherErr := json.Marshal(old)
	if err != nil || otherErr != nil || !bytes.Equal(got, want) {
		t.Fatal("legacy authority bytes changed", string(got), string(want), err, otherErr)
	}
	pair := comparisonAuthorityFixture()
	encoded, err := json.Marshal(pair)
	var back ContextProjectionAuthority
	if err != nil || json.Unmarshal(encoded, &back) != nil || back.Baseline == nil || !back.Valid(pair.CheckedAt.Add(time.Second)) || back.Scope != pair.Scope || *back.Baseline != *pair.Baseline {
		t.Fatal("compound authority failed bounded roundtrip", err)
	}
}

// maximumComparisonAuthority fills each bounded free-text field with the
// largest JSON-escaped valid byte, each digest with three-digit bytes, both
// retention sources and maximum numeric/revision/timestamp widths. This is
// encoding evidence, not source authority or runtime resource qualification.
func maximumComparisonAuthority() ContextProjectionAuthority {
	a := comparisonAuthorityFixture()
	start := time.Date(2026, 1, 1, 12, 0, 0, 999999999, time.FixedZone("size-fixture", 23*3600+59*60))
	var digest artifact.Digest
	for j := range digest {
		digest[j] = 255
	}
	text := func(n int) string { return strings.Repeat("<", n) }
	revision := func(uuid bool) identity.Revision {
		uid := text(64)
		if uuid {
			uid = queryTestID
		}
		return identity.Revision{UID: uid, Generation: 2147483647, Digest: digest}
	}
	principal := identity.Principal{Issuer: text(2048), Subject: text(256), ClientID: text(256), Kind: identity.Workload}
	for _, v := range []*ContextProjectionAuthority{&a, a.Baseline} {
		v.Scope.NamespaceUID, v.Scope.WorkloadUID, v.Scope.PodUID = text(64), text(64), text(64)
		v.Scope.Principal = principal
		v.Scope.Version = digest
		v.Scope.Profile = ProfileSummarySelection{SampleType: text(64), TopN: 100}
		v.Environment.Principal = principal
		v.Environment.Region = text(63)
		v.Environment.PolicyRevision = revision(false)
		p := &v.Environment.Path
		p.StorageRegion, p.AcquisitionRegion, p.ConnectorRegion, p.HubRegion = text(63), text(63), text(63), text(63)
		p.WorkerConfiguration, p.HubConfiguration = revision(true), revision(true)
		v.Environment.ObservedAt, v.Environment.ValidUntil = start, start.Add(4*time.Second)
		v.Environment.Recovery.Revision = revision(false)
		v.Environment.Recovery.ObservedAt, v.Environment.Recovery.FreshUntil = start, start.Add(4*time.Second)
		v.Environment.Processing.Sequence = 1 << 60
		v.Environment.Processing.StateDigest = digest
		v.Environment.Processing.ObservedAt, v.Environment.Processing.ValidUntil = start, start.Add(4*time.Second)
		r := &v.Retention
		r.NamespaceUID, r.WorkloadUID, r.PodUID = v.Scope.NamespaceUID, v.Scope.WorkloadUID, v.Scope.PodUID
		r.Topology, r.Policy, r.Selectors = revision(false), revision(false), revision(false)
		r.SourceCount = 2
		r.ObservedAt, r.ValidUntil = start, start.Add(4*time.Second)
		r.Sources = [2]artifact.RetentionSourceVersion{
			{ClusterID: queryTestID, ControlNamespaceUID: text(64), Epoch: queryTestID, Hub: true, ProtectionDigest: digest, SnapshotDigest: digest, Acceptance: revision(true)},
			{ClusterID: v.Scope.ClusterID, ControlNamespaceUID: strings.Repeat(">", 64), Epoch: queryOtherID, ProtectionDigest: digest, SnapshotDigest: digest, Acceptance: revision(true)},
		}
		v.PermissionRevision, v.IdentityRevision = revision(true), revision(false)
		v.DecisionDigest = digest
		v.CheckedAt, v.ValidUntil, v.AccessUntil, v.DeleteBy = start, start.Add(4*time.Second), start.Add(time.Minute), start.Add(2*time.Minute)
	}
	b := a.Baseline.Scope
	a.Scope.Comparison.Baseline = ProfileComparisonBaseline{CaseID: b.CaseID, ArtifactID: b.ArtifactID, CaptureID: b.CaptureID, ClusterID: b.ClusterID, NamespaceUID: b.NamespaceUID, WorkloadUID: b.WorkloadUID, PodUID: b.PodUID, Version: b.Version}
	return a
}

func TestProfileComparisonMaximumAuthorityEncoding(t *testing.T) {
	a := maximumComparisonAuthority()
	if !a.Valid(a.CheckedAt.Add(time.Second)) {
		t.Fatal("maximum authority fixture invalid")
	}
	scope, err := json.Marshal(a.Scope)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	// A complete binding-shaped envelope retains the current Batch/Worker fields
	// and compound authority. Pair plan/key children are deliberately not yet
	// activated, so this is not b.Valid or a SQL row qualification.
	digest := a.DecisionDigest
	rev := a.Environment.Path.WorkerConfiguration
	start := a.CheckedAt
	worker := ContextQueryWorker{QueryID: queryTestID, WorkerID: queryTestID, PeerID: queryTestID, PodUID: queryTestID, ProcessEpoch: queryTestID, Certificate: digest, Configuration: rev}
	request := ContextQueryRequest{Call: ContextQueryCall{ID: queryTestID, RootID: a.Scope.RootID, Tool: "get_profile_summary", InputFormat: "context-query-input/v1", MACVersion: strings.Repeat("<", 64), InputDigest: digest, PrincipalDigest: digest, Principal: a.Scope.Principal, StartedAt: start, Until: a.ValidUntil, WriteUntil: start.Add(30 * time.Second)}, OwnerID: queryTestID, HubProcessEpoch: queryTestID}
	proof := ContextProjectionWorkerProof{Binding: ContextProjectionWorkerBinding{QueryID: queryTestID, WorkerID: queryTestID, InstallationID: a.Environment.InstallationID, ClusterID: a.Environment.Path.AcquisitionClusterID, Namespace: strings.Repeat("<", 63), NamespaceUID: strings.Repeat("<", 64), ServiceAccount: strings.Repeat("<", 253), ServiceAccountUID: strings.Repeat("<", 64), Job: strings.Repeat("<", 63), JobUID: strings.Repeat("<", 64), Pod: strings.Repeat("<", 253), PodUID: queryTestID, JobSpec: digest, PodSpec: digest, Configuration: rev}, Peer: authorization.KeyPeer{InstallationID: a.Environment.InstallationID, PeerID: queryTestID, Role: "acquisition", Certificate: digest, NotBefore: start, NotAfter: start.Add(time.Hour)}, ProcessEpoch: queryTestID, PublicKey: digest, TokenDigest: digest, Protection: a.IdentityRevision, ObservedAt: start, ValidUntil: a.ValidUntil}
	binding := ContextProjectionKeyBinding{Purpose: ContextProjectionPurpose, ClaimID: queryTestID, Batch: ContextReadBatch{QueryID: queryTestID, ID: queryTestID, OperationID: queryTestID, Generation: 1, Worker: worker, Request: request, StartedAt: start, Until: a.ValidUntil, CleanupUntil: start.Add(time.Hour)}, SourceVersion: a.Scope.Version, Scope: authorization.KeyScope{InstallationID: a.Environment.InstallationID, Purpose: "artifact", KeyID: strings.Repeat("x", 128)}, Worker: proof, Authority: a, CreatedAt: start, Until: a.ValidUntil}
	if !request.Valid(start) || !proof.Binding.Valid() || !proof.Peer.Valid(start) || !binding.Scope.Valid() {
		t.Fatal("binding envelope component invalid")
	}
	envelope, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	spaces := func(b []byte) int { return len(b) + bytes.Count(b, []byte{':'}) + bytes.Count(b, []byte{','}) }
	t.Logf("maximum valid pair scope=%dB authority=%dB; complete binding-shaped envelope=%dB (not activated/SQL-qualified); conservative JSONB spacing ceilings scope=%dB authority=%dB binding=%dB", len(scope), len(encoded), len(envelope), spaces(scope), spaces(encoded), spaces(envelope))
	// Size the proposed fixed, comparable second-plan field without activating
	// its admission/current/SQL contract. All plan components retain their
	// existing independent validity; the compound query is not qualified here.
	maximumPlan := func(source ContextProjectionAuthority) ContextQueryPlan {
		p := queryPlan(source)
		p.AllocationRevision = 1 << 60
		p.Profile.Lifetime = ContextMaxQueryTime
		p.Profile.PollLimit, p.Profile.ControlTransitionLimit = 1000000, 1000000
		w := &p.Profile.Worker
		w.CPUMilli, w.MemoryBytes, w.EphemeralStorageBytes = 1<<60, 1<<60, 1<<60
		w.WorkerTransientBytes, w.HubTransientBytes = 1<<60, 1<<60
		w.ProviderConcurrency, w.AuthenticationConcurrency = 1<<60, 1<<60
		w.Runtime, w.CredentialLifetime, w.ProviderEffectLifetime, w.Cleanup = 1<<63-1, 1<<63-1, 1<<63-1, 1<<63-1
		c := &p.Profile.Cost
		c.ProviderRequests, c.AuthenticationRequests, c.SigningAttempts = 1<<60, 1<<60, 1<<60
		c.AuditObjects, c.SQLRows, c.SQLBytes, c.WALBytes, c.BackupBytes = 1<<60, 1<<60, 1<<60, 1<<60, 1<<60
		p.HardUntil = p.ObservedAt.Add(ContextMaxQueryTime)
		p.EffectsUntil = p.ObservedAt.Add(w.Runtime)
		p.CleanupUntil = p.EffectsUntil.Add(w.Cleanup)
		p.RetireBy = p.CleanupUntil.Add(time.Minute)
		return p
	}
	incident, _ := a.Scope.IncidentScope()
	ip, bp := maximumPlan(a), maximumPlan(*a.Baseline)
	if !ip.Valid(incident, start) || !bp.Valid(a.Baseline.Scope, start) || !ip.Profile.SharedBudget().SharedBudgetValid() || !bp.Profile.SharedBudget().SharedBudgetValid() {
		t.Fatal("maximum independent plan fixture invalid")
	}
	query := struct {
		ContextQuery
		BaselinePlan ContextQueryPlan `json:",omitzero"`
	}{ContextQuery: ContextQuery{ID: queryTestID, OperationID: queryTestID, WorkerID: queryTestID, Scope: a.Scope, Plan: ip, RecoveryIssuerEpoch: a.Environment.Recovery.IssuerEpoch, RecoveryRevision: a.Environment.Recovery.Revision, CreatedAt: start, Deadline: ip.HardUntil, WorkerUntil: ip.EffectsUntil, CredentialUntil: ip.EffectsUntil, ProviderUntil: ip.EffectsUntil, CleanupUntil: ip.CleanupUntil}, BaselinePlan: bp}
	planJSON, err := json.Marshal(ip)
	if err != nil {
		t.Fatal(err)
	}
	queryJSON, err := json.Marshal(query)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("maximum independent plan=%dB; proposed query+value BaselinePlan envelope=%dB (not admitted/SQL-qualified); conservative JSONB spacing ceilings plan=%dB pair-query=%dB", len(planJSON), len(queryJSON), spaces(planJSON), spaces(queryJSON))
	if len(scope) > 32<<10 || len(encoded) > 128<<10 || len(envelope) > 128<<10 || len(queryJSON) > 128<<10 {
		t.Fatal("maximum encoding exceeded proposed pair-purpose planning ceiling")
	}
}
