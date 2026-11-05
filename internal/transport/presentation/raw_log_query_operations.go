package presentation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"time"
	"unicode/utf8"

	analysisapp "asservat.local/asservat/internal/application/analysis"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/analysis"
)

type RawLogQueryService interface {
	Begin(context.Context, identities.CurrentIdentity, analysisapp.ContextQueryInvocation, value.RawLogQueryRequest) (*analysisapp.ContextProjectionDelivery, error)
}
type RawLogQueryOperationInput struct {
	CaseID         string `json:"case_id"`
	ArtifactID     string `json:"artifact_id"`
	GrantID        string `json:"grant_id,omitempty"`
	IdempotencyKey string `json:"idempotency_key"`
	Cursor         string `json:"cursor,omitempty"`
	Limit          int    `json:"limit,omitempty"`
}

func normalizeRawLogInput(in RawLogQueryOperationInput) RawLogQueryOperationInput {
	if in.Limit == 0 {
		in.Limit = value.LogPageRecords
	}
	return in
}
func (in RawLogQueryOperationInput) request() (value.RawLogQueryRequest, error) {
	in = normalizeRawLogInput(in)
	s, err := value.NormalizeLogSelection(in.CaseID, in.ArtifactID, in.Cursor, in.Limit)
	return value.RawLogQueryRequest{CaseID: in.CaseID, ArtifactID: in.ArtifactID, GrantID: in.GrantID, IdempotencyKey: in.IdempotencyKey, Selection: s.LogWindow}, err
}
func rawLogInput(r value.RawLogQueryRequest) RawLogQueryOperationInput {
	in := RawLogQueryOperationInput{CaseID: r.CaseID, ArtifactID: r.ArtifactID, GrantID: r.GrantID, IdempotencyKey: r.IdempotencyKey, Limit: r.Selection.Limit}
	if r.Selection.Fragment != 0 || r.Selection.Offset != 0 {
		in.Cursor = strconv.FormatUint(r.Selection.Fragment, 10) + ":" + strconv.FormatUint(uint64(r.Selection.Offset), 10) + ":" + r.Selection.Binding
	}
	return normalizeRawLogInput(in)
}

type logOriginOutput struct {
	OriginID      uint16  `json:"origin_id"`
	ContainerKind string  `json:"container_kind"`
	ContainerName string  `json:"container_name"`
	Source        string  `json:"source"`
	Stream        string  `json:"stream"`
	RuntimeID     *string `json:"runtime_id"`
	RestartCount  *uint32 `json:"restart_count"`
}
type logEntryOutput struct {
	Origin       logOriginOutput `json:"origin"`
	Fragment     uint64          `json:"fragment"`
	Line         uint64          `json:"line"`
	Offset       uint64          `json:"offset"`
	LineOffset   uint64          `json:"line_offset"`
	Continuation bool            `json:"continuation"`
	EndLine      bool            `json:"end_line"`
	SourceTime   *string         `json:"source_time"`
	Text         *string         `json:"text"`
	BytesBase64  *string         `json:"bytes_base64"`
}
type logCoverageOutput struct {
	Origins     uint16 `json:"origins"`
	Complete    uint16 `json:"complete_origins"`
	Partial     uint16 `json:"partial_origins"`
	Unavailable uint16 `json:"unavailable_origins"`
	Unknown     uint16 `json:"unknown_timestamp_origins"`
	Gapped      uint16 `json:"gapped_origins"`
	SourceBytes uint64 `json:"source_bytes"`
	Fragments   uint64 `json:"total_fragments"`
}

func logOutputEntries(p value.LogPage) ([]logEntryOutput, error) {
	out := make([]logEntryOutput, 0, len(p.Entries))
	for _, e := range p.Entries {
		raw, err := base64.StdEncoding.Strict().DecodeString(e.Data)
		if err != nil {
			return nil, ErrOperationDelivery
		}
		o := e.Origin
		r := logEntryOutput{Origin: logOriginOutput{o.OriginID, o.ContainerKind, o.ContainerName, o.Source, o.Stream, o.RuntimeID, o.RestartCount}, Fragment: e.Fragment, Line: e.Line, Offset: e.Offset, LineOffset: e.LineOffset, Continuation: e.Continuation, EndLine: e.EndLine, SourceTime: e.SourceTime}
		if utf8.Valid(raw) {
			s := string(raw)
			r.Text = &s
		} else {
			s := e.Data
			r.BytesBase64 = &s
		}
		clear(raw)
		out = append(out, r)
	}
	return out, nil
}

const rawLogHandling = "SensitiveDataHandling: Saved logs are raw user data. Streams are combined; timestamps may be unknown and completed fetching does not establish complete history. Automatic deletion covers managed copies and cannot recall delivered copies."

func renderRawLogResult(requestID, name string, d *analysisapp.ContextProjectionDelivery, times queryViewTimes) ([]byte, error) {
	page, ok := d.Logs()
	if !ok {
		return nil, ErrOperationDelivery
	}
	defer page.Clear()
	entries, err := logOutputEntries(page)
	if err != nil {
		return nil, err
	}
	artifactID, version := d.Provenance()
	inner := OperationEnvelope{SchemaVersion: "mcp-result/v1", RequestID: requestID, DataClass: "raw", Status: "ok", Warnings: []string{rawLogHandling}, Provenance: []any{httpHeaderProvenance{ArtifactID: artifactID, Digest: hash(version)}}}
	inner.Data = struct {
		Kind        string            `json:"kind"`
		PodUID      string            `json:"pod_uid"`
		WindowStart time.Time         `json:"window_start"`
		WindowEnd   time.Time         `json:"window_end"`
		Entries     []logEntryOutput  `json:"entries"`
		Coverage    logCoverageOutput `json:"coverage"`
		queryViewTimes
	}{"logs", page.PodUID, page.WindowStart, page.WindowEnd, entries, logCoverageOutput{page.OriginCount, page.CompleteOrigins, page.PartialOrigins, page.UnavailableOrigins, page.UnknownTimestampOrigins, page.GappedOrigins, page.SourceBytes, page.TotalFragments}, times}
	if cursor := page.Next(d.LogSelection(), version); cursor != "" {
		inner.NextCursor = &cursor
		inner.Truncated = true
		hint := "Continue with the returned cursor to inspect more saved log bytes."
		inner.NarrowingHint = &hint
	}
	outer := inner
	if name == "get_query_result" {
		outer.Truncated = false
		outer.NextCursor = nil
		outer.NarrowingHint = nil
		outer.Provenance = []any{}
		outer.Data = queryResult(d.Association().QueryID, d.Tool(), inner, times)
	}
	body, err := json.Marshal(outer)
	if err != nil {
		return nil, ErrOperationDelivery
	}
	if len(body) > contracts.InvestigationOutputLimit {
		clear(body)
		return nil, value.ErrRecordTooLarge
	}
	return body, nil
}
func (s *ContextProjectionOperations) WithRawLogQueries(q RawLogQueryService) (*ContextProjectionOperations, error) {
	if s == nil || q == nil || s.rawLogs != nil {
		return nil, ErrOperationsConfiguration
	}
	out := *s
	out.rawLogs = q
	return &out, nil
}
