package postgres

import (
	"bytes"
	"encoding/json"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/capture"
	deliveryapp "asservat.local/asservat/internal/application/delivery"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

// NULL legacy acquisition is kept as legacy; current readers/names are never
// substituted into an old source. The existing row guard makes these immutable.
func sourceOriginalProvenance(row custodydb.PolicyRecordingSource, source *app.PolicySourceState) error {
	if len(row.SourceAudienceJson) == 0 && len(row.SourceAudienceDigest) == 0 && len(row.SourceTargetJson) == 0 {
		if source.Binding.AudienceDigest != ([32]byte{}) {
			return value.ErrChanged
		}
		return nil
	}
	if len(row.SourceAudienceJson) == 0 || len(row.SourceAudienceDigest) != 32 || len(row.SourceTargetJson) == 0 {
		return value.ErrChanged
	}
	var original targets.SourceSnapshotTarget
	if json.Unmarshal(row.SourceAudienceJson, &source.Audience) != nil || json.Unmarshal(row.SourceTargetJson, &original) != nil {
		return value.ErrChanged
	}
	source.Target = &original
	digest, err := compiler.SourceAudienceDigest(source.Audience)
	if err != nil || !bytes.Equal(digest[:], row.SourceAudienceDigest) {
		return value.ErrChanged
	}
	return sourceProvenanceComplete(*source)
}

// Retained provenance is independent of whether the ring is still accepting
// input. In-flight frozen copies can finish after source end under their own
// original processing/storage authority.
func sourceProvenanceComplete(source app.PolicySourceState) error {
	b, t := source.Binding, source.Target
	digest, err := compiler.SourceAudienceDigest(source.Audience)
	if err != nil || !b.Valid() || b.AudienceDigest == ([32]byte{}) || digest != artifact.Digest(b.AudienceDigest) || t == nil || !t.Valid() {
		return value.ErrDenied
	}
	if t.SourceID != b.SourceID || t.Fence != b.Fence || t.BindingDigest != deliveryapp.SourceBindingDigest(b) || t.NodeUID != b.NodeUID || t.BootID != b.BootID || t.CollectorPodUID != b.CollectorPodUID || t.CollectorEpoch != b.CollectorEpoch || t.Request.ClusterID != source.ClusterID || t.Request.Namespace.UID != source.NamespaceUID || t.Request.Workload.UID != source.WorkloadUID || t.Request.PodUID != b.PodUID {
		return value.ErrChanged
	}
	return nil
}

func sourceSnapshotProvenance(source app.PolicySourceState, selected *planning.SourceSnapshotContext) error {
	if err := sourceProvenanceComplete(source); err != nil {
		return err
	}
	if selected == nil || selected.SourceTarget == nil {
		return value.ErrChanged
	}
	digest, err := compiler.SourceAudienceDigest(selected.SourceAudience)
	b, q := source.Binding, selected.Request
	if err != nil || digest != selected.SourceAudienceDigest || digest != artifact.Digest(b.AudienceDigest) || *selected.SourceTarget != *source.Target || selected.PolicyUID != b.PolicyUID || selected.ActionID != b.ActionID || selected.ExecutionDigest != artifact.Digest(b.Scope) || q.SourceID != b.SourceID || q.Fence != b.Fence || q.SourceBindingDigest != artifact.Digest(deliveryapp.SourceBindingDigest(b)) || !q.SourceStartedAt.Equal(source.StartedAt) || !q.SourceHardUntil.Equal(source.HardUntil) {
		return value.ErrChanged
	}
	return nil
}

func sourceSnapshotAudience(source app.PolicySourceState, selected *planning.SourceSnapshotContext, current []artifact.AudienceAssignment) ([]artifact.AudienceAssignment, error) {
	if err := sourceSnapshotProvenance(source, selected); err != nil {
		return nil, err
	}
	return app.SnapshotAudience(selected, current)
}
