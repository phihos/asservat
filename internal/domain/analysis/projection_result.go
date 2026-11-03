package analysis

import (
	"asservat.local/asservat/internal/domain/artifact"
)

// The approved read path carries exactly one result per read batch (ADR-282
// slice 5): the pod-status DTO for a pod-status scope, or one httpHeaders page
// (or an invalid-cursor refusal) for an extract scope, or the closed pprof
// summary for its exact selected sample type.
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
	// ProfileSummaryQueryUnits conservatively funds the full 64 MiB native
	// window (nine encrypted frames, two index pages) plus metadata.
	ProfileSummaryQueryUnits = 10
	// ProfileSummaryWorkerBytes is the whole physical worker memory bound,
	// also declared as transient capacity before summary admission.
	ProfileSummaryWorkerBytes = 256 << 20
	// SyscallProjectionQueryUnits funds one complete recording read (one 8 MiB
	// frame, index and manifest) with the same backing as an HTTP-header page.
	SyscallProjectionQueryUnits = 2
	// SyscallProjectionWorkerBytes reuses the existing regional worker bound.
	// Composed maximum-input framing/parser qualification is recorded in ADR-294.
	SyscallProjectionWorkerBytes = 256 << 20
)

// ProjectionResult is the approved result of one read batch. Exactly the
// scope's branch is populated; InvalidCursor discloses no record.
type ProjectionResult struct {
	PodStatus      PodStatusProjection
	Headers        HTTPHeaderPage
	Summary        *ProfileSummary     `json:",omitempty"`
	SyscallSummary *SyscallSummaryPage `json:",omitempty"`
	SyscallEvents  *SyscallEventPage   `json:",omitempty"`
	InvalidCursor  bool
	// TooLarge refuses a page whose first selected record alone exceeds the
	// wire bound; it discloses no record and paging cannot pass that record.
	TooLarge bool
}

// Valid reports whether the result is exactly the scope's source branch.
func (r ProjectionResult) Valid(s ContextProjectionScope) bool {
	if !s.Valid() {
		return false
	}
	if s.NativeType == artifact.SyscallRecordsArtifact || s.NativeType == artifact.SyscallArgumentsArtifact {
		if r.PodStatus != (PodStatusProjection{}) || !r.Headers.empty() || r.Summary != nil {
			return false
		}
		if r.InvalidCursor || r.TooLarge {
			return r.InvalidCursor != r.TooLarge && r.SyscallSummary == nil && r.SyscallEvents == nil
		}
		selection := s.Syscalls.Selection(s.CaseID, s.ArtifactID)
		if s.Syscalls.View == SyscallSummaryView {
			return r.SyscallEvents == nil && r.SyscallSummary != nil && r.SyscallSummary.Valid(selection, s.Version)
		}
		return r.SyscallSummary == nil && r.SyscallEvents != nil && r.SyscallEvents.ValidShape(selection, s.Version, s.PodUID)
	}
	if r.SyscallSummary != nil || r.SyscallEvents != nil {
		return false
	}
	switch s.NativeType {
	case artifact.PodStatusArtifact:
		return !r.InvalidCursor && !r.TooLarge && r.Headers.empty() && r.Summary == nil && r.PodStatus.Valid() && r.PodStatus.NamespaceUID == s.NamespaceUID && r.PodStatus.PodUID == s.PodUID
	case artifact.HTTPHeadersArtifact:
		if r.PodStatus != (PodStatusProjection{}) || r.Summary != nil {
			return false
		}
		if r.InvalidCursor || r.TooLarge {
			return r.InvalidCursor != r.TooLarge && r.Headers.empty()
		}
		return r.Headers.Valid(s.Headers.Selection(s.CaseID, s.ArtifactID))
	case artifact.PprofArtifact:
		return r.PodStatus == (PodStatusProjection{}) && r.Headers.empty() && !r.InvalidCursor && !r.TooLarge && r.Summary != nil && r.Summary.Valid(s.Profile)
	}
	return false
}

// Clear drops the transient record values.
func (r *ProjectionResult) Clear() {
	if r.SyscallSummary != nil {
		clear(r.SyscallSummary.Rows)
		*r.SyscallSummary = SyscallSummaryPage{}
	}
	if r.SyscallEvents != nil {
		clear(r.SyscallEvents.Events)
		*r.SyscallEvents = SyscallEventPage{}
	}

	if r.Summary != nil {
		clear(r.Summary.Top)
		*r.Summary = ProfileSummary{}
	}
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
	if s.NativeType == artifact.SyscallRecordsArtifact || s.NativeType == artifact.SyscallArgumentsArtifact {
		switch s.Syscalls.View {
		case SyscallSummaryView:
			return "get_syscall_summary"
		case SyscallEventsView:
			return "get_syscall_events"
		}
		return ""
	}

	if s.NativeType == artifact.PprofArtifact {
		return "get_profile_summary"
	}
	if s.NativeType == artifact.HTTPHeadersArtifact {
		return "get_http_headers"
	}
	return "get_file_excerpt"
}

// ReadBatches is the number of read batches a query of this scope may
// start: one page read for an extract, the historical two for pod status.
func (s ContextProjectionScope) ReadBatches() int64 {
	if s.NativeType == artifact.HTTPHeadersArtifact || s.NativeType == artifact.PprofArtifact || s.NativeType == artifact.SyscallRecordsArtifact || s.NativeType == artifact.SyscallArgumentsArtifact {
		return 1
	}
	return ContextMaxReadBatches
}
