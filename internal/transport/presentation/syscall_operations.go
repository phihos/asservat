package presentation

import (
	"context"
	"encoding/json"

	analysisapp "asservat.local/asservat/internal/application/analysis"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

type SyscallQueryService interface {
	Begin(context.Context, identities.CurrentIdentity, analysisapp.ContextQueryInvocation, value.SyscallQueryRequest) (*analysisapp.ContextProjectionDelivery, error)
}

type SyscallOperationInput struct {
	CaseID     string   `json:"case_id"`
	ArtifactID string   `json:"artifact_id"`
	Cursor     string   `json:"cursor,omitempty"`
	Limit      int      `json:"limit,omitempty"`
	Names      []string `json:"syscall_names,omitempty"`
	ErrorsOnly bool     `json:"errors_only,omitempty"`
}

func syscallQueryOperation(name string) bool {
	return name == "get_syscall_summary" || name == "get_syscall_events"
}
func syscallView(name string) value.SyscallView {
	if name == "get_syscall_summary" {
		return value.SyscallSummaryView
	}
	if name == "get_syscall_events" {
		return value.SyscallEventsView
	}
	return ""
}
func (s *ContextProjectionOperations) WithSyscalls(syscalls SyscallQueryService) (*ContextProjectionOperations, error) {
	if s == nil || syscalls == nil || s.syscalls != nil {
		return nil, ErrOperationsConfiguration
	}
	out := *s
	out.syscalls = syscalls
	return &out, nil
}

type syscallCoverage struct {
	Dropped     *uint64  `json:"dropped_events"` // acquisition loss is unknown in these stored formats
	Unmatched   uint64   `json:"unmatched_events"`
	Unfinished  uint64   `json:"unfinished_events"`
	Unknown     uint64   `json:"unknown_events"`
	RecordCount uint64   `json:"record_count"`
	Truncated   *bool    `json:"truncated"`
	Gaps        []string `json:"gaps"`
}

func savedSyscallCoverage(c value.SyscallRecordCounts) syscallCoverage {
	return syscallCoverage{Unmatched: c.UnmatchedEvents, Unfinished: c.UnfinishedEvents, Unknown: c.UnknownEvents, RecordCount: c.RecordCount, Gaps: []string{"Acquisition coverage and dropped-event count are unknown; counts describe only the recorded file."}}
}

var syscallInvalidCursor = OperationFailure{Code: "InvalidCursor", Message: "The cursor is not valid for this syscall view. Start again without a cursor.", Retryable: false}
var syscallNotAvailable = OperationFailure{Code: "NotAvailable", Message: "Syscall evidence is not available with your current access or service conditions. Check your access or retry later.", Retryable: true}
var syscallTooLarge = OperationFailure{Code: "AnalysisUnavailable", Message: "This syscall record does not fit the response limit.", Retryable: false}

const syscallHandling = "SensitiveDataHandling: Process and thread references may contain user data. This view omits arguments, paths, buffers and pointers. Automatic deletion covers Asservat-managed copies; copies already delivered cannot be recalled."

// renderSyscallResult bounds the entire public response, including a poll's
// nested result and notices. Trimming keeps a prefix and resumes at its first
// omitted item; it never changes or discards the complete-source counters.
func renderSyscallResult(requestID, name string, d *analysisapp.ContextProjectionDelivery, times queryViewTimes) ([]byte, error) {
	artifactID, version := d.Provenance()
	// The association carries the comparable selection; the exact case/artifact
	// binding used to create its cursors is retained by the delivered page scope.
	selection := d.SyscallSelection()
	summary, isSummary := d.SyscallSummary()
	events, isEvents := d.SyscallEvents()
	if isSummary == isEvents {
		return nil, ErrOperationDelivery
	}
	defer clear(summary.Rows)
	defer clear(events.Events)
	n := len(summary.Rows)
	if isEvents {
		n = len(events.Events)
	}
	for {
		inner := OperationEnvelope{SchemaVersion: "mcp-result/v1", RequestID: requestID, DataClass: "extract", Status: "ok", Warnings: []string{syscallHandling}, Provenance: []any{httpHeaderProvenance{ArtifactID: artifactID, Digest: hash(version)}}}
		cursor := ""
		if isSummary {
			prefix := summary
			prefix.Rows = summary.Rows[:n]
			cursor = prefix.Next(selection, version)
			inner.Data = struct {
				Kind     string               `json:"kind"`
				Rows     []value.SyscallCount `json:"rows"`
				Coverage syscallCoverage      `json:"coverage"`
				queryViewTimes
			}{"syscallSummary", prefix.Rows, savedSyscallCoverage(summary.SyscallRecordCounts), times}
		} else {
			prefix := events
			prefix.Events = events.Events[:n]
			cursor = prefix.Next(selection, version)
			inner.Data = struct {
				Kind     string                          `json:"kind"`
				Events   []artifact.SyscallMetadataEvent `json:"events"`
				Coverage syscallCoverage                 `json:"coverage"`
				queryViewTimes
			}{"syscallEvents", prefix.Events, savedSyscallCoverage(events.SyscallRecordCounts), times}
		}
		if cursor != "" {
			inner.NextCursor = &cursor
		}
		outer := inner
		if name == "get_query_result" {
			outer.NextCursor, outer.Provenance = nil, []any{}
			outer.Data = queryResult(d.Association().QueryID, d.Tool(), inner, times)
		}
		body, err := json.Marshal(outer)
		fits := err == nil && len(body) <= contracts.InvestigationOutputLimit
		if fits {
			return body, nil
		}
		clear(body)
		if err != nil {
			return nil, ErrOperationDelivery
		}
		if n <= 1 {
			return nil, value.ErrRecordTooLarge
		}
		n--
	}
}
