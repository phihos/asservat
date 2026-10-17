package bootstrap

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	audit "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	fleet "asservat.local/asservat/internal/domain/fleet"
)

// The capture lane policy is installer-provided, canonical, of its own lane,
// root and installation; unknown fields or another lane, root or installation
// are refused.
func TestPublicAuditPolicyIsExactCanonicalAndOwnLane(t *testing.T) {
	n := time.Now().UTC().Truncate(time.Microsecond)
	p := audit.OperationLifecyclePolicy{RootID: runtimeID, Lane: "capture", InstallationID: runtimeID, StoreID: runtimeID, PolicyID: runtimeID, BackupProfileID: runtimeID, PolicyDigest: artifact.Digest{1}, BackupProfileDigest: artifact.Digest{2}, BackingRevision: 1, MetadataSlots: 1, BackupReservedBytes: 1<<63 - 1, WALReservedBytes: 1<<63 - 1, MaxPurgeLeases: 8, CleanupBudgetSeconds: 15, ProofWindowSeconds: 1, ValidUntil: n.Add(time.Hour), History: &audit.OperationHistoryQualification{ID: runtimeID, Digest: artifact.Digest{3}, Layout: audit.CaptureOperationHistoryLayout, MaximumRowFootprintBytes: 256 << 10, MaximumTransitionWALBytes: 256 << 10, BackupCopies: 2, WALCopies: 2}}
	raw, _ := json.Marshal(p)
	if got, e := decodeAuditPolicy(raw, "capture", runtimeID, runtimeID); e != nil || got.StoreID != runtimeID {
		t.Fatal("exact capture policy", e)
	}
	pretty, _ := json.MarshalIndent(p, "", " ")
	other := "10000000-0000-4000-8000-0000000000aa"
	for name, c := range map[string]struct {
		raw                      []byte
		lane, root, installation string
	}{
		"lane":         {raw, "normal", runtimeID, runtimeID},
		"root":         {raw, "capture", other, runtimeID},
		"installation": {raw, "capture", runtimeID, other},
		"unknown":      {append(raw[:len(raw)-1], []byte(`,"Extra":1}`)...), "capture", runtimeID, runtimeID},
		"empty":        {nil, "capture", runtimeID, runtimeID},
	} {
		if _, e := decodeAuditPolicy(c.raw, c.lane, c.root, c.installation); e == nil {
			t.Fatal("policy accepted", name)
		}
	}
	// JCS canonicalization accepts whitespace-only reformatting of the same value.
	if _, e := decodeAuditPolicy(pretty, "capture", runtimeID, runtimeID); e != nil {
		t.Fatal("reformatted identical policy", e)
	}
}

// Capability and signing route only to the target's own cluster.
func TestPublicRoutingRefusesUnknownAndCrossClusterTargets(t *testing.T) {
	ctx := context.Background()
	other := "10000000-0000-4000-8000-0000000000aa"
	if _, e := (publicCapabilities{}).ContextCapability(ctx, authorization.Target{ClusterID: other, NamespaceUID: "ns", WorkloadUID: "w", PodUID: "p"}); e == nil {
		t.Fatal("capability of an uninstalled cluster")
	}
	w := fleet.APIContextWork{Target: authorization.Target{ClusterID: other}}
	if _, e := (publicSigners{}).SignAPIContextWork(ctx, w); e == nil {
		t.Fatal("signed for an uninstalled cluster")
	}
	signers := publicSigners{other: nil}
	w.Channel.Connector.Binding.ClusterID = runtimeID
	if _, e := signers.SignAPIContextWork(ctx, w); e == nil {
		t.Fatal("signed work routed to another cluster's connector")
	}
}

func TestPublicConnectorProfileIsPinnedToItsCluster(t *testing.T) {
	source, _ := json.Marshal(contracts.ConnectorIdentityConfiguration{Format: contracts.ConnectorIdentityFormat, ClusterID: "10000000-0000-4000-8000-0000000000aa"})
	v := contracts.OwnerPublicCluster{ClusterID: runtimeID, Connector: contracts.FederationPeer{SourceUID: runtimeID, Source: source}}
	if _, e := publicConnectorProfile(v, runtimeID, runtimeID); e == nil {
		t.Fatal("connector source of another cluster accepted")
	}
	if _, ok := publicDigest("00"); ok {
		t.Fatal("short digest")
	}
	if _, ok := publicDigest("0000000000000000000000000000000000000000000000000000000000000000"); ok {
		t.Fatal("zero digest")
	}
}
