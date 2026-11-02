package analysis

import "asservat.local/asservat/internal/domain/artifact"

// The approved read path carries exactly one result per read batch (ADR-282
// slice 5): the pod-status DTO for a pod-status scope, or one httpHeaders page
// (or an invalid-cursor refusal) for an extract scope.
const (
	// HTTPHeaderPageWireBytes bounds the encoded page in the 64 KiB native
	// control frame (with its envelope). The worker sends the longest record
	// prefix that fits; the public response trims further to 24 KiB.
	HTTPHeaderPageWireBytes = 46 << 10
	// HTTPHeaderQueryUnits is the number of accepted query units one
	// get_http_headers query reserves: its single read batch of one recording
	// frame (NativeWindowReadWork) exceeds one pod-status unit's two 4 MiB
	// batches, and two units cover it in every cost dimension.
	HTTPHeaderQueryUnits = 2
)

// ProjectionResult is the approved result of one read batch. Exactly the
// scope's branch is populated; InvalidCursor discloses no record.
type ProjectionResult struct {
	PodStatus     PodStatusProjection
	Headers       HTTPHeaderPage
	InvalidCursor bool
}

// Valid reports whether the result is exactly the scope's source branch.
func (r ProjectionResult) Valid(s ContextProjectionScope) bool {
	if !s.Valid() {
		return false
	}
	switch s.NativeType {
	case artifact.PodStatusArtifact:
		return !r.InvalidCursor && r.Headers.empty() && r.PodStatus.Valid() && r.PodStatus.NamespaceUID == s.NamespaceUID && r.PodStatus.PodUID == s.PodUID
	case artifact.HTTPHeadersArtifact:
		if r.PodStatus != (PodStatusProjection{}) {
			return false
		}
		if r.InvalidCursor {
			return r.Headers.empty()
		}
		return r.Headers.Valid(s.Headers.Selection(s.CaseID, s.ArtifactID))
	}
	return false
}

// Clear drops the transient record values.
func (r *ProjectionResult) Clear() {
	clear(r.Headers.Records)
	clear(r.Headers.CoverageGaps)
	*r = ProjectionResult{}
}

func (p HTTPHeaderPage) empty() bool {
	return p.ProjectionDigest == (artifact.Digest{}) && p.Start == 0 && p.Total == 0 && p.Records == nil &&
		p.DroppedFlows == 0 && p.IncompleteFlows == 0 && p.CoverageGaps == nil
}

// BeginTool is the public tool that admits a query of this scope.
func (s ContextProjectionScope) BeginTool() string {
	if s.NativeType == artifact.HTTPHeadersArtifact {
		return "get_http_headers"
	}
	return "get_file_excerpt"
}

// ReadBatches is the number of read batches a query of this scope may
// start: one page read for an extract, the historical two for pod status.
func (s ContextProjectionScope) ReadBatches() int64 {
	if s.NativeType == artifact.HTTPHeadersArtifact {
		return 1
	}
	return ContextMaxReadBatches
}
