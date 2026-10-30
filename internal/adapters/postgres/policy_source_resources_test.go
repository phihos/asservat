package postgres

import (
	"encoding/json"
	"io/fs"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	capacity "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/migrations"
)

// Synthetic typed row, not SQL acceptance authority. Its stored lifetime comes
// from migration 73; the original accepted payload keeps its five-second span.
func sourceResourceTestRow(t *testing.T) (custodydb.ReadPolicySourceResourceSelectionRow, capacity.CapacitySourceObservation, string, time.Time) {
	t.Helper()
	sql, err := fs.ReadFile(migrations.Files(), "00073_capacity_source_freshness.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, _, ok := strings.Cut(string(sql), "-- +goose Down")
	if !ok || !strings.Contains(up, "fresh_until=observed+interval '30 seconds',suspended=false") || !strings.Contains(up, "'FreshUntil',until_at") {
		t.Fatal("stored-source/caller-receipt contract changed")
	}
	now := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	cluster := "11111111-1111-4111-8111-111111111111"
	resource := cfg.Resource{ClusterID: cluster, Namespace: "control", NamespaceUID: "control", Kind: "EvidenceBudgetPolicy", Name: "apps", UID: "budget-policy", Generation: 1, ResourceVersion: "1", SpecDigest: artifact.Digest{1}}
	snapshot := capacity.CapacitySnapshot{ClusterID: cluster, ControlNamespace: cfg.NamespaceRef{Name: "control", UID: "control"}, PoolResourceVersion: "1", PolicyResourceVersion: "1", ObservedAt: now, FreshUntil: now.Add(capacity.CapacitySourceInterval), Policies: []capacity.BudgetPolicyObservation{{Resource: resource, Pool: "capacity", Scope: &capacity.BudgetScope{ClusterID: cluster}, Budget: &capacity.PolicyBudgetInput{Name: "apps", Pool: "capacity", Cluster: cluster}, SourceResources: &capacity.SourceResourceLimits{Node: collector.PolicyLimits{SourceLimits: collector.SourceLimits{MaxActiveSources: 4, InputBytesPerSecond: 4 << 20, InputBurstBytes: 4 << 20}}, Workload: collector.SourceLimits{MaxActiveSources: 4, InputBytesPerSecond: 4 << 20, InputBurstBytes: 4 << 20}}}}}
	versions := []capacity.CapacitySourceVersion{{Kind: resource.Kind, Name: resource.Name, UID: resource.UID, Generation: resource.Generation, Spec: resource.SpecDigest}}
	digest, err := capacity.CapacitySourceDigest(snapshot, versions)
	if err != nil {
		t.Fatal(err)
	}
	observation := capacity.CapacitySourceObservation{Snapshot: snapshot, Versions: versions, Digest: digest}
	raw, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	return custodydb.ReadPolicySourceResourceSelectionRow{AcceptedRevision: 1, AcceptedSnapshot: raw, AcceptedDigest: digest[:], ObservedAt: ts(now), FreshUntil: ts(now.Add(30 * time.Second)), PolicyUid: resource.UID}, observation, cluster, now
}

func TestPolicySourceResourcesUseStoredThirtySecondObservation(t *testing.T) {
	row, original, cluster, now := sourceResourceTestRow(t)
	if capacity.CapacitySourceInterval != 5*time.Second || !original.Valid(now) || original.Valid(now.Add(15*time.Second)) {
		t.Fatal("fixture does not distinguish original receipt from stored current row")
	}
	if identity.Fresh(row.ObservedAt.Time, row.FreshUntil.Time, now, capacity.CapacitySourceInterval) {
		t.Fatal("original defect's five-second bound unexpectedly accepts stored30s row")
	}
	for _, offset := range []time.Duration{0, 15 * time.Second, 30*time.Second - time.Microsecond} {
		t.Run(offset.String(), func(t *testing.T) {
			resources, digest, err := sourceResources(row, cluster, now.Add(offset))
			if err != nil || resources.PolicyUID != row.PolicyUid || resources.Workload.MaxActiveSources != 4 || digest == ([32]byte{}) {
				t.Fatal("valid accepted30s row rejected by caller5s rule", err)
			}
		})
	}
	for _, name := range []string{"expired", "overlong", "suspended", "changed-digest", "malformed-original-span"} {
		t.Run(name, func(t *testing.T) {
			invalid := row
			at := now
			switch name {
			case "expired":
				at = now.Add(30 * time.Second)
			case "overlong":
				invalid.FreshUntil = ts(now.Add(30*time.Second + time.Microsecond))
			case "suspended":
				invalid.Suspended = true
			case "changed-digest":
				invalid.AcceptedDigest = make([]byte, 32)
			case "malformed-original-span":
				bad := original
				bad.Snapshot.FreshUntil = now.Add(6 * time.Second)
				invalid.AcceptedSnapshot, _ = json.Marshal(bad)
			}
			if _, _, err := sourceResources(invalid, cluster, at); err == nil {
				t.Fatal("invalid accepted source became current")
			}
		})
	}
	if !original.Snapshot.FreshUntil.Equal(now.Add(5*time.Second)) || !row.FreshUntil.Time.Equal(now.Add(30*time.Second)) {
		t.Fatal("validation rewrote original intervals")
	}
}
