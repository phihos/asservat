package presentation

import (
	"context"
	"encoding/json"
	"time"

	analysisapp "asservat.local/asservat/internal/application/analysis"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

// HTTPHeaderQueryService is the C-18 get_http_headers admission (ADR-282):
// one approved query per page, answered with its pending handle; the page
// itself is served by get_query_result.
type HTTPHeaderQueryService interface {
	Begin(context.Context, identities.CurrentIdentity, analysisapp.ContextQueryInvocation, value.HTTPHeaderSelection) (*analysisapp.ContextProjectionDelivery, error)
}

// HTTPHeaderOperationInput is the closed get_http_headers input; the audit
// digest covers the cursor as supplied and the defaulted limit.
type HTTPHeaderOperationInput struct {
	CaseID     string `json:"case_id"`
	ArtifactID string `json:"artifact_id"`
	Cursor     string `json:"cursor,omitempty"`
	Limit      int    `json:"limit,omitempty"`
}

type httpHeaderField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type httpHeaderRecord struct {
	Timestamp time.Time         `json:"timestamp"`
	Method    string            `json:"method,omitempty"`
	Status    int               `json:"status,omitempty"`
	Headers   []httpHeaderField `json:"headers"`
	Partial   bool              `json:"partial"`
}
type httpHeaderData struct {
	Protocol         string             `json:"protocol"`
	ProjectionDigest string             `json:"projection_digest"`
	Records          []httpHeaderRecord `json:"records"`
	DroppedFlows     uint64             `json:"dropped_flows"`
	IncompleteFlows  uint64             `json:"incomplete_flows"`
	CoverageGaps     []string           `json:"coverage_gaps"`
}
type httpHeaderProvenance struct {
	ArtifactID string `json:"artifactID"`
	Digest     string `json:"digest"`
}

// httpHeaderHandling is the fixed handling notice of every disclosed page.
const httpHeaderHandling = "SensitiveDataHandling: This evidence may contain personal or user data. Minimize disclosure, review recipients and use organization-approved clients. Automatic deletion follows source deadlines and covers Asservat-managed copies only; copies already delivered to users or agents cannot be recalled. Authorized artifact notices show current access cutoffs and deletion status."

// The fixed refusals of get_http_headers. Every refusal other than a cursor
// shares one nondisclosing outcome.
var (
	httpHeaderInvalidCursor = OperationFailure{Code: "InvalidCursor", Message: "The cursor is not valid for this HTTP header projection. Start again without a cursor.", Retryable: false}
	httpHeaderNotAvailable  = OperationFailure{Code: "NotAvailable", Message: "HTTP header evidence is not available with your current access or service conditions. Check your access or retry later.", Retryable: true}
	httpHeaderTooLarge      = OperationFailure{Code: "AnalysisUnavailable", Message: "This HTTP header record does not fit the response limit.", Retryable: false}
)

// renderHTTPHeaderPage renders the get_http_headers envelope of the longest
// record prefix for which wrap(envelope) fits the response limit; next_cursor
// continues after the last delivered record, so no record is silently
// skipped. A single record that cannot fit is an explicit error.
func renderHTTPHeaderPage(requestID string, p value.HTTPHeaderPage, artifactID string, version artifact.Digest, wrap func(OperationEnvelope) any) (OperationEnvelope, error) {
	records := make([]httpHeaderRecord, 0, len(p.Records))
	for _, x := range p.Records {
		headers := make([]httpHeaderField, 0, len(x.Headers))
		for _, h := range x.Headers {
			headers = append(headers, httpHeaderField{Name: h.Name, Value: h.Value})
		}
		records = append(records, httpHeaderRecord{Timestamp: x.Timestamp.UTC(), Method: x.Method, Status: x.Status, Headers: headers, Partial: x.Partial})
	}
	out := OperationEnvelope{SchemaVersion: "mcp-result/v1", RequestID: requestID, Status: "ok", DataClass: "extract",
		Warnings: []string{httpHeaderHandling}, Provenance: []any{httpHeaderProvenance{ArtifactID: artifactID, Digest: hash(version)}}}
	data := httpHeaderData{Protocol: "http1", ProjectionDigest: hash(p.ProjectionDigest), DroppedFlows: p.DroppedFlows, IncompleteFlows: p.IncompleteFlows, CoverageGaps: append([]string{}, p.CoverageGaps...)}
	for n := len(records); n >= 0; n-- {
		if n == 0 && len(records) > 0 {
			break
		}
		data.Records = records[:n]
		out.Data, out.NextCursor = data, nil
		if next := p.Next(n); next != "" {
			out.NextCursor = &next
		}
		b, err := json.Marshal(wrap(out))
		size := len(b)
		clear(b)
		if err != nil {
			return out, value.ErrUnavailable
		}
		if size <= contracts.InvestigationOutputLimit {
			return out, nil
		}
	}
	return httpHeaderFailure(requestID, httpHeaderTooLarge), nil
}

func httpHeaderFailure(requestID string, f OperationFailure) OperationEnvelope {
	return OperationEnvelope{SchemaVersion: "mcp-result/v1", RequestID: requestID, Status: "error", DataClass: "metadata", Warnings: []string{}, Provenance: []any{}, Data: f}
}
