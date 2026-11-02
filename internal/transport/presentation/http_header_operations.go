package presentation

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"time"

	analysisapp "asservat.local/asservat/internal/application/analysis"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// HTTPHeaderReadUseCase is the C-18 get_http_headers service.
type HTTPHeaderReadUseCase interface {
	Read(context.Context, identities.CurrentIdentity, value.HTTPHeaderSelection) (analysisapp.HTTPHeaderResult, error)
}

// HTTPHeaderOperations serves get_http_headers (ADR-282 slice 4) to MCP and
// the browser through the same audited operation path as other reads. Only
// an explicitly composed service advertises it.
type HTTPHeaderOperations struct {
	origin    string
	now       func() time.Time
	newID     func() string
	reads     HTTPHeaderReadUseCase
	contracts *contracts.InvestigationContracts
}

func NewHTTPHeaderOperations(origin string, now func() time.Time, newID func() string, reads HTTPHeaderReadUseCase) (*HTTPHeaderOperations, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || reads == nil || now == nil || newID == nil {
		return nil, ErrOperationsConfiguration
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		return nil, err
	}
	return &HTTPHeaderOperations{origin: origin, now: now, newID: newID, reads: reads, contracts: wire}, nil
}

func (s *HTTPHeaderOperations) PublicOrigin() string {
	if s == nil {
		return ""
	}
	return s.origin
}
func (s *HTTPHeaderOperations) ToolNames() []string { return []string{"get_http_headers"} }
func (s *HTTPHeaderOperations) Tool(name string) (contracts.InvestigationTool, bool) {
	if s == nil || name != "get_http_headers" {
		return contracts.InvestigationTool{}, false
	}
	return s.contracts.Tool(name)
}

// HTTPHeaderOperationInput is the closed get_http_headers input; the audit
// digest covers the cursor and limit as supplied.
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

func (s *HTTPHeaderOperations) Call(ctx context.Context, current identities.CurrentIdentity, name string, raw json.RawMessage) (OperationReply, error) {
	if s == nil {
		return OperationReply{}, ErrOperationsConfiguration
	}
	return s.CallWithContext(ctx, current, OperationCall{requestID: s.newID()}, name, raw)
}

func (s *HTTPHeaderOperations) CallWithContext(ctx context.Context, current identities.CurrentIdentity, call OperationCall, name string, raw json.RawMessage) (OperationReply, error) {
	if s == nil || ctx == nil || current == nil {
		return OperationReply{}, value.ErrUnavailable
	}
	if name != "get_http_headers" || s.contracts.ValidateInput(name, raw) != nil || !authorization.UUID(call.requestID) {
		return OperationReply{}, contracts.ErrInvestigationWire
	}
	var in HTTPHeaderOperationInput
	if json.Unmarshal(raw, &in) != nil {
		return OperationReply{}, contracts.ErrInvestigationWire
	}
	initial, err := current.ResolveIdentity(ctx)
	if err != nil || ctx.Err() != nil || !initial.Valid(s.now()) || !slices.Contains(initial.Scopes, "evidence:read") {
		return OperationReply{}, identity.ErrDenied
	}
	until := initial.ValidUntil
	out := OperationEnvelope{SchemaVersion: "mcp-result/v1", RequestID: call.requestID, DataClass: "metadata", Status: "error", Warnings: []string{}, Provenance: []any{}}
	var decision operationAuditDecision
	sel, err := value.NormalizeHTTPHeaderSelection(in.CaseID, in.ArtifactID, in.Cursor, in.Limit)
	var result analysisapp.HTTPHeaderResult
	if err == nil {
		result, err = s.reads.Read(ctx, current, sel)
	}
	switch {
	case errors.Is(err, value.ErrInvalidCursor):
		// Judged only after current read rights (or before any lookup for a
		// malformed cursor); it names no artifact fact.
		out.Data, decision = OperationFailure{Code: "InvalidCursor", Message: "The cursor is not valid for this HTTP header projection. Start again without a cursor.", Retryable: false}, operationAuditInvalid
	case err != nil:
		// Existence, type, publication, rights and service failures share one
		// nondisclosing outcome; a raw or metadata artifact is never read here.
		out.Data, decision = OperationFailure{Code: "NotAvailable", Message: "HTTP header evidence is not available with your current access or service conditions. Check your access or retry later.", Retryable: true}, operationAuditDenied
	default:
		if result.Page.Start != sel.Start || result.Authority.ArtifactID != sel.ArtifactID || result.Authority.CaseID != sel.CaseID {
			return OperationReply{}, value.ErrUnavailable
		}
		until = identity.Earlier(until, result.ValidUntil)
		out, err = s.page(out, result)
		if err != nil {
			return OperationReply{}, err
		}
	}
	final, err := current.ResolveIdentity(ctx)
	if err != nil || ctx.Err() != nil || !final.Valid(s.now()) || final.Principal != initial.Principal {
		return OperationReply{}, identity.ErrDenied
	}
	until = identity.Earlier(until, final.ValidUntil)
	b, err := json.Marshal(out)
	if err != nil || len(b) > contracts.InvestigationOutputLimit || s.contracts.ValidateOutput(name, b) != nil {
		clear(b)
		return OperationReply{}, value.ErrUnavailable
	}
	if !s.now().Before(until) || ctx.Err() != nil {
		clear(b)
		return OperationReply{}, value.ErrUnavailable
	}
	return OperationReply{Body: b, ValidUntil: until, auditDecision: decision}, nil
}

// page renders the longest prefix of the page that fits the response limit;
// next_cursor continues after the last delivered record, so no record is
// silently skipped. A single record that cannot fit is an explicit error.
func (s *HTTPHeaderOperations) page(out OperationEnvelope, r analysisapp.HTTPHeaderResult) (OperationEnvelope, error) {
	p := r.Page
	records := make([]httpHeaderRecord, 0, len(p.Records))
	for _, x := range p.Records {
		headers := make([]httpHeaderField, 0, len(x.Headers))
		for _, h := range x.Headers {
			headers = append(headers, httpHeaderField{Name: h.Name, Value: h.Value})
		}
		records = append(records, httpHeaderRecord{Timestamp: x.Timestamp.UTC(), Method: x.Method, Status: x.Status, Headers: headers, Partial: x.Partial})
	}
	out.Status, out.DataClass = "ok", "extract"
	out.Warnings = []string{httpHeaderHandling}
	out.Provenance = []any{httpHeaderProvenance{ArtifactID: r.Authority.ArtifactID, Digest: hash(r.Authority.Version)}}
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
		b, err := json.Marshal(out)
		size := len(b)
		clear(b)
		if err != nil {
			return out, value.ErrUnavailable
		}
		if size <= contracts.InvestigationOutputLimit {
			return out, nil
		}
	}
	out.Status, out.DataClass, out.Warnings, out.Provenance, out.NextCursor = "error", "metadata", []string{}, []any{}, nil
	out.Data = OperationFailure{Code: "AnalysisUnavailable", Message: "This HTTP header record does not fit the response limit.", Retryable: false}
	return out, nil
}
