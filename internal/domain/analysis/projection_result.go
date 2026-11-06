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
	// ProfileComparisonQueryUnits funds two complete maximum pprof reads.
	// It is a conservative work declaration, not qualified worker memory.
	ProfileComparisonQueryUnits = 2 * ProfileSummaryQueryUnits
	// ProfileSummaryWorkerBytes is the whole physical worker memory bound,
	// also declared as transient capacity before summary admission.
	ProfileSummaryWorkerBytes = 256 << 20
	// ProfileComparisonWorkerBytes is the provisional physical and transient
	// declaration for two-source comparisons, pending full native qualification.
	// It adds 128 MiB per comparison-capable worker over the summary declaration.
	ProfileComparisonWorkerBytes = 384 << 20
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
	Logs          *LogPage `json:",omitempty"`
	PodStatus     PodStatusProjection
	Headers       HTTPHeaderPage
	Summary       *ProfileSummary    `json:",omitempty"`
	PacketQuery   *PacketQueryResult `json:",omitempty"`
	PacketSummary *PacketSummary     `json:",omitempty"`
	Comparison    *ProfileComparison `json:",omitempty"`
	// IncompatibleProfiles is a content-free semantic result after both
	// authenticated source reads, not an unknown read/transport failure.
	IncompatibleProfiles bool                 `json:",omitempty"`
	SyscallSummary       *SyscallSummaryPage  `json:",omitempty"`
	SyscallEvents        *SyscallEventPage    `json:",omitempty"`
	SyscallQuery         *SyscallArgumentPage `json:",omitempty"`
	InvalidCursor        bool
	// TooLarge refuses a page whose first selected record alone exceeds the
	// wire bound, or an authenticated comparison that exceeds its result bound.
	// It discloses no content and never denotes an input/parser budget failure.
	TooLarge bool
}

// Valid reports whether the result is exactly the scope's source branch.
func (r ProjectionResult) Valid(s ContextProjectionScope) bool {
	if !s.Valid() {
		return false
	}
	if s.NativeType == artifact.LogsArtifact {
		if r.PodStatus != (PodStatusProjection{}) || !r.Headers.empty() || r.Summary != nil || r.PacketQuery != nil || r.PacketSummary != nil || r.Comparison != nil || r.IncompatibleProfiles || r.SyscallSummary != nil || r.SyscallEvents != nil || r.SyscallQuery != nil {
			return false
		}
		if r.InvalidCursor || r.TooLarge {
			return r.InvalidCursor != r.TooLarge && r.Logs == nil
		}
		return r.Logs != nil && r.Logs.ValidShape(s.Logs.Selection(s.CaseID, s.ArtifactID), s.Version, s.PodUID)
	}
	if r.Logs != nil {
		return false
	}
	if r.SyscallQuery != nil && s.DisplayVersion != SyscallQueryDisplayVersion {
		return false
	}
	if s.DisplayVersion == SyscallQueryDisplayVersion {
		if r.PodStatus != (PodStatusProjection{}) || !r.Headers.empty() || r.Summary != nil || r.PacketQuery != nil || r.PacketSummary != nil || r.Comparison != nil || r.IncompatibleProfiles || r.SyscallSummary != nil || r.SyscallEvents != nil {
			return false
		}
		if r.InvalidCursor || r.TooLarge {
			return r.InvalidCursor != r.TooLarge && r.SyscallQuery == nil
		}
		return r.SyscallQuery != nil && r.SyscallQuery.ValidShape(s.Syscalls.Selection(s.CaseID, s.ArtifactID), s.Version, s.PodUID)
	}
	if s.PacketQuery != (PacketQueryWindow{}) {
		return r.PodStatus == (PodStatusProjection{}) && r.Headers.empty() && r.Summary == nil && r.PacketSummary == nil && r.Comparison == nil && !r.IncompatibleProfiles && r.SyscallSummary == nil && r.SyscallEvents == nil && !r.InvalidCursor && !r.TooLarge && r.PacketQuery != nil && r.PacketQuery.Valid(s.PacketQuery.Selection(), s.NativeType)
	}
	if r.PacketQuery != nil {
		return false
	}
	if s.Comparison != (ProfileComparisonWindow{}) {
		if r.PodStatus != (PodStatusProjection{}) || !r.Headers.empty() || r.Summary != nil || r.PacketSummary != nil || r.SyscallSummary != nil || r.SyscallEvents != nil || r.InvalidCursor {
			return false
		}
		if r.IncompatibleProfiles || r.TooLarge {
			return r.Comparison == nil && r.IncompatibleProfiles != r.TooLarge
		}
		return r.Comparison != nil && r.Comparison.Valid(s.Comparison.Selection(s.Profile))
	}
	if r.Comparison != nil || r.IncompatibleProfiles {
		return false
	}
	if s.NativeType == artifact.SyscallRecordsArtifact || s.NativeType == artifact.SyscallArgumentsArtifact {
		if r.PodStatus != (PodStatusProjection{}) || !r.Headers.empty() || r.Summary != nil || r.PacketSummary != nil {
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
	if s.NativeType == artifact.PCAPNGArtifact || s.NativeType == artifact.RawPCAPNGArtifact {
		return r.PodStatus == (PodStatusProjection{}) && r.Headers.empty() && r.Summary == nil && r.SyscallSummary == nil && r.SyscallEvents == nil && !r.InvalidCursor && !r.TooLarge && r.PacketSummary != nil && r.PacketSummary.Valid() && (s.NativeType == artifact.RawPCAPNGArtifact) == (r.PacketSummary.CaptureMode == "rawPackets")
	}
	if r.PacketSummary != nil {
		return false
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
	if r.Logs != nil {
		r.Logs.Clear()
	}
	if r.SyscallQuery != nil {
		r.SyscallQuery.Clear()
		r.SyscallQuery = nil
	}
	if r.PacketQuery != nil {
		r.PacketQuery.Clear()
		r.PacketQuery = nil
	}
	if r.Comparison != nil {
		r.Comparison.Clear()
	}
	if r.SyscallSummary != nil {
		clear(r.SyscallSummary.Rows)
		*r.SyscallSummary = SyscallSummaryPage{}
	}
	if r.SyscallEvents != nil {
		clear(r.SyscallEvents.Events)
		*r.SyscallEvents = SyscallEventPage{}
	}

	if r.PacketSummary != nil {
		clear(r.PacketSummary.Conversations)
		*r.PacketSummary = PacketSummary{}
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
	if s.NativeType == artifact.LogsArtifact && s.Logs.Valid() {
		return "get_logs"
	}
	if s.DisplayVersion == PacketQueryDisplayVersion && s.PacketQuery != (PacketQueryWindow{}) {
		return "pcap_query"
	}
	if s.NativeType == artifact.PCAPNGArtifact || s.NativeType == artifact.RawPCAPNGArtifact {
		return "get_pcap_summary"
	}
	if s.NativeType == artifact.SyscallRecordsArtifact || s.NativeType == artifact.SyscallArgumentsArtifact {
		switch s.Syscalls.View {
		case SyscallSummaryView:
			return "get_syscall_summary"
		case SyscallEventsView:
			return "get_syscall_events"
		case SyscallQueryView:
			return "syscall_query"
		}
		return ""
	}

	if s.NativeType == artifact.PprofArtifact {
		if s.Comparison != (ProfileComparisonWindow{}) {
			return "compare_profiles"
		}
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
	if s.NativeType == artifact.LogsArtifact && s.Logs.Valid() {
		return LogQueryReadBatches
	}
	if s.DisplayVersion == SyscallQueryDisplayVersion && s.Syscalls.View == SyscallQueryView {
		return SyscallQueryReadBatches
	}
	if s.DisplayVersion == PacketQueryDisplayVersion && s.PacketQuery != (PacketQueryWindow{}) {
		return PacketQueryReadBatches
	}
	if s.NativeType == artifact.PCAPNGArtifact || s.NativeType == artifact.RawPCAPNGArtifact || s.NativeType == artifact.HTTPHeadersArtifact || s.NativeType == artifact.PprofArtifact || s.NativeType == artifact.SyscallRecordsArtifact || s.NativeType == artifact.SyscallArgumentsArtifact {
		return 1
	}
	return ContextMaxReadBatches
}
