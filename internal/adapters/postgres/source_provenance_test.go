package postgres

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	deliveryapp "asservat.local/asservat/internal/application/delivery"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

func sourceProvenanceTestRow(t *testing.T, readers int) (custodydb.PolicyRecordingSource, *planning.SourceSnapshotContext) {
	t.Helper()
	in, now := sourceRetentionCheckFixture(t, 120, 20)
	in.Target.Request.PodUID, in.Target.Pin.UID, in.Node.PodUID = in.SourceID, in.SourceID, in.SourceID
	audience := slices.Clone(in.Authority.Owners)
	if len(audience) != 1 {
		t.Fatal("fixture needs one contributing owner")
	}
	for i := 1; i < readers; i++ {
		a := audience[0]
		a.AssignmentID = fmt.Sprintf("20000000-0000-4000-8000-%012d", i)
		a.SubjectID = fmt.Sprintf("readers-%d", i)
		a.Role = "evidence-reader"
		audience = append(audience, a)
	}
	digest, err := compiler.SourceAudienceDigest(audience)
	if err != nil {
		t.Fatal(err)
	}
	b := collector.SourceBinding{RootID: in.Retention.Proof.RootID, PolicyUID: in.Authority.PolicyUID, AcceptanceID: in.SourceID, SourceID: in.SourceID, Fence: in.Fence, ActionID: in.Policy.Recorder.Action.ID, PodUID: in.Node.PodUID, NodeUID: in.Node.NodeUID, BootID: in.Node.BootID, CollectorPodUID: in.Node.CollectorPodUID, CollectorEpoch: in.Node.CollectorEpoch, Scope: [32]byte(in.Authority.ScopeDigest), ExpectationDigest: [32]byte(in.Policy.Recorder.Digest), ResourceDigest: [32]byte{1}, AudienceDigest: [32]byte(digest)}
	if !b.Valid() {
		t.Fatal("source binding fixture")
	}
	target := targets.SourceSnapshotTarget{Request: in.Target.Request, Pin: in.Target.Pin, NodeUID: b.NodeUID, BootID: b.BootID, CollectorPodUID: b.CollectorPodUID, CollectorEpoch: b.CollectorEpoch, SourceID: b.SourceID, Fence: b.Fence, BindingDigest: deliveryapp.SourceBindingDigest(b)}
	if !target.Valid() {
		t.Fatal("original target fixture")
	}
	raw, _ := json.Marshal(b)
	rawAudience, _ := json.Marshal(audience)
	rawTarget, _ := json.Marshal(target)
	row := custodydb.PolicyRecordingSource{RootID: id(b.RootID), ID: id(b.SourceID), Fence: id(b.Fence), PolicyUid: b.PolicyUID, AcceptanceID: id(b.AcceptanceID), ActionID: b.ActionID, ClusterID: id(in.Authority.ClusterID), NamespaceUid: in.Authority.NamespaceUID, WorkloadUid: in.Authority.WorkloadUID, PodUid: b.PodUID, BindingJson: raw, StartedAt: ts(now), HardUntil: ts(in.Authority.NotAfter), StartBy: ts(now.Add(5 * time.Second)), InitialLeafUntil: ts(now.Add(30 * time.Second)), InitialCredit: 1 << 20, Credit: 1 << 20, BytesPerSecond: 1 << 20, SourceAudienceJson: rawAudience, SourceAudienceDigest: digest[:], SourceTargetJson: rawTarget}
	selected := &planning.SourceSnapshotContext{ActionID: b.ActionID, PolicyUID: b.PolicyUID, ExecutionDigest: artifact.Digest(b.Scope), SourceAudience: slices.Clone(audience), SourceAudienceDigest: digest, SourceTarget: &target, Request: artifact.SourceSnapshotRequest{SourceID: b.SourceID, Fence: b.Fence, SourceBindingDigest: artifact.Digest(target.BindingDigest), SourceStartedAt: now, SourceHardUntil: in.Authority.NotAfter}}
	return row, selected
}

func TestSourceOriginalProvenanceAndCurrentAudienceIntersection(t *testing.T) {
	row, selected := sourceProvenanceTestRow(t, 2)
	source, err := policySourceState(row)
	if err != nil {
		t.Fatal(err)
	}
	if len(source.Audience) != 2 || source.Target == nil {
		t.Fatal("full audience/original target lost")
	}
	added := source.Audience[0]
	added.AssignmentID = "30000000-0000-4000-8000-000000000001"
	added.SubjectID = "new-readers"
	current := append(slices.Clone(source.Audience), added)
	got, err := sourceSnapshotAudience(source, selected, current)
	if err != nil || !slices.Equal(got, source.Audience) {
		t.Fatal("new readers gained original source bytes", err)
	}
	current = []artifact.AudienceAssignment{source.Audience[0], added}
	got, err = sourceSnapshotAudience(source, selected, current)
	if err != nil || !slices.Equal(got, source.Audience[:1]) {
		t.Fatal("removed original audience persisted", err)
	}
	source.EndedAt = source.StartedAt.Add(time.Second)
	if err = sourceSnapshotProvenance(source, selected); err != nil {
		t.Fatal("source end blocked already admitted processing", err)
	}
}

func TestSourceProvenanceRejectsLegacyAndChangedReviewedMetadata(t *testing.T) {
	for _, name := range []string{"legacy", "partial", "audience", "namesake", "node", "binding"} {
		t.Run(name, func(t *testing.T) {
			row, selected := sourceProvenanceTestRow(t, 2)
			if name == "legacy" {
				var b collector.SourceBinding
				_ = json.Unmarshal(row.BindingJson, &b)
				b.AudienceDigest = [32]byte{}
				row.BindingJson, _ = json.Marshal(b)
				row.SourceAudienceJson, row.SourceAudienceDigest, row.SourceTargetJson = nil, nil, nil
				legacy, err := policySourceState(row)
				if err != nil || legacy.Audience != nil || legacy.Target != nil {
					t.Fatal("legacy source fabricated provenance", err)
				}
				if sourceSnapshotProvenance(legacy, selected) == nil {
					t.Fatal("legacy source adopted current audience/target")
				}
				return
			}
			if name == "partial" {
				row.SourceTargetJson = nil
				if _, err := policySourceState(row); err == nil {
					t.Fatal("partial provenance accepted")
				}
				return
			}
			source, err := policySourceState(row)
			if err != nil {
				t.Fatal(err)
			}
			selected = selected.Clone()
			switch name {
			case "audience":
				selected.SourceAudience[1].SubjectID = "substituted-reader"
				selected.SourceAudienceDigest, _ = compiler.SourceAudienceDigest(selected.SourceAudience)
			case "namesake":
				selected.SourceTarget.Request.PodUID = "30000000-0000-4000-8000-000000000001"
				selected.SourceTarget.Pin.UID = selected.SourceTarget.Request.PodUID
			case "node":
				selected.SourceTarget.NodeUID = "30000000-0000-4000-8000-000000000001"
			case "binding":
				selected.Request.SourceBindingDigest = artifact.Digest{9}
			}
			if sourceSnapshotProvenance(source, selected) == nil {
				t.Fatal("reviewed metadata escaped retained original")
			}
		})
	}
}

func TestSourceProvenanceMaintenanceMetadataCost(t *testing.T) {
	for _, refs := range []int{4, 32} {
		t.Run(fmt.Sprintf("%drefs", refs), func(t *testing.T) {
			row, _ := sourceProvenanceTestRow(t, refs)
			source, err := policySourceState(row)
			if err != nil {
				t.Fatal(err)
			}
			rows := make([]interface{}, 20)
			for i := range rows {
				rows[i] = source
			}
			raw, err := json.Marshal(rows)
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			for i := 0; i < 20; i++ {
				if _, err = policySourceState(row); err != nil {
					t.Fatal(err)
				}
			}
			t.Logf("20sources_%drefs DTO_JSON_bytes=%d original_JSON_field_bytes_per_source=%d local20row_decode_hash_wall=%s; DTO serialization/local timing only, not actual PG wire/runtime overhead. SQL row bound112KiB x1025 safety rows=117555200bytes maximum record data per list; no new query/cache", refs, len(raw), len(row.BindingJson)+len(row.SourceAudienceJson)+len(row.SourceTargetJson), time.Since(start))
		})
	}
}
