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

type RawSyscallQueryService interface {
	Begin(context.Context, identities.CurrentIdentity, string, value.RawSyscallQueryRequest) (*analysisapp.ContextProjectionDelivery, error)
}

const rawSyscallHandling = "SensitiveDataHandling: Recorded syscall arguments may contain sensitive user data. Values are recorded decimal scalars, base64 bytes or unavailable:fault; acquisition truncation is separate from pagination. Managed deletion does not recall delivered copies."

func renderRawSyscallResult(requestID, name string, d *analysisapp.ContextProjectionDelivery, times queryViewTimes) ([]byte, error) {
	page, ok := d.SyscallQuery()
	if !ok {
		return nil, ErrOperationDelivery
	}
	defer page.Clear()
	selection := d.SyscallSelection()
	artifactID, version := d.Provenance()
	for n := len(page.Events); ; n-- {
		prefix := page
		prefix.Events = page.Events[:n]
		cursor := prefix.Next(selection, version)
		inner := OperationEnvelope{SchemaVersion: "mcp-result/v1", RequestID: requestID, DataClass: "raw", Status: "ok", Warnings: []string{rawSyscallHandling}, Provenance: []any{httpHeaderProvenance{ArtifactID: artifactID, Digest: hash(version)}}}
		inner.Data = struct {
			Kind     string                      `json:"kind"`
			Events   []artifact.RawArgumentEvent `json:"events"`
			Coverage syscallCoverage             `json:"coverage"`
			queryViewTimes
		}{"syscallQuery", prefix.Events, savedSyscallCoverage(page.SyscallRecordCounts), times}
		if cursor != "" {
			inner.NextCursor, inner.Truncated = &cursor, true
			hint := "Continue with the returned cursor to inspect more recorded calls."
			inner.NarrowingHint = &hint
		}
		outer := inner
		if name == "get_query_result" {
			outer.Truncated, outer.NextCursor, outer.NarrowingHint, outer.Provenance = false, nil, nil, []any{}
			outer.Data = queryResult(d.Association().QueryID, d.Tool(), inner, times)
		}
		body, err := json.Marshal(outer)
		if err == nil && len(body) <= contracts.InvestigationOutputLimit {
			return body, nil
		}
		clear(body)
		if err != nil {
			return nil, ErrOperationDelivery
		}
		if n <= 1 {
			return nil, value.ErrRecordTooLarge
		}
	}
}

func (s *ContextProjectionOperations) WithRawSyscallQueries(q RawSyscallQueryService) (*ContextProjectionOperations, error) {
	if s == nil || q == nil || s.rawSyscalls != nil {
		return nil, ErrOperationsConfiguration
	}
	out := *s
	out.rawSyscalls = q
	return &out, nil
}
