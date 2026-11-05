package presentation

import (
	"context"
	"encoding/json"
	"slices"
	"strconv"

	analysisapp "asservat.local/asservat/internal/application/analysis"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

type RawSyscallQueryService interface {
	Begin(context.Context, identities.CurrentIdentity, analysisapp.ContextQueryInvocation, value.RawSyscallQueryRequest) (*analysisapp.ContextProjectionDelivery, error)
}

type RawSyscallQueryOperationInput struct {
	CaseID         string   `json:"case_id"`
	ArtifactID     string   `json:"artifact_id"`
	GrantID        string   `json:"grant_id,omitempty"`
	IdempotencyKey string   `json:"idempotency_key"`
	Cursor         string   `json:"cursor,omitempty"`
	Limit          int      `json:"limit,omitempty"`
	Names          []string `json:"syscall_names,omitempty"`
	ErrorsOnly     bool     `json:"errors_only,omitempty"`
}

func normalizeRawSyscallInput(in RawSyscallQueryOperationInput) RawSyscallQueryOperationInput {
	if in.Limit == 0 {
		in.Limit = value.SyscallPageRecords
	}
	in.Names = slices.Clone(in.Names)
	slices.Sort(in.Names)
	return in
}

func (in RawSyscallQueryOperationInput) request() (value.RawSyscallQueryRequest, error) {
	in = normalizeRawSyscallInput(in)
	s, err := value.NormalizeSyscallSelection(in.CaseID, in.ArtifactID, value.SyscallQueryView, in.Cursor, in.Limit, in.Names, in.ErrorsOnly)
	return value.RawSyscallQueryRequest{CaseID: in.CaseID, ArtifactID: in.ArtifactID, GrantID: in.GrantID, IdempotencyKey: in.IdempotencyKey, Selection: s.Window()}, err
}

func rawSyscallInput(r value.RawSyscallQueryRequest) RawSyscallQueryOperationInput {
	s := r.Selection.Selection(r.CaseID, r.ArtifactID)
	in := RawSyscallQueryOperationInput{CaseID: r.CaseID, ArtifactID: r.ArtifactID, GrantID: r.GrantID, IdempotencyKey: r.IdempotencyKey, Limit: s.Limit, Names: s.Names, ErrorsOnly: s.ErrorsOnly}
	if s.Start > 0 {
		in.Cursor = strconv.Itoa(s.Start) + ":" + s.Binding
	}
	return normalizeRawSyscallInput(in)
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
