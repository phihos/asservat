package presentation

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	analysisapp "asservat.local/asservat/internal/application/analysis"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/identity"
)

// Initial admission and passive results are separate consumer capabilities.
// Both return the concrete C-18 owner; arbitrary result DTOs are insufficient.
type ContextExcerptService interface {
	BeginExcerpt(context.Context, identities.CurrentIdentity, analysisapp.ContextQueryInvocation, value.ContextExcerptSelection) (*analysisapp.ContextProjectionDelivery, error)
}
type ContextQueryResults interface {
	GetQueryResult(context.Context, identities.CurrentIdentity, analysisapp.ContextQueryInvocation, string) (*analysisapp.ContextProjectionDelivery, error)
}

// This adapter deliberately has no ToolNames, Tool or unaudited Call. Explicit
// installation composition adds its two operations to InvestigationOperations;
// the existing audit wrapper alone supplies each live invocation owner.
type ContextProjectionOperations struct {
	excerpts  ContextExcerptService
	results   ContextQueryResults
	headers   HTTPHeaderQueryService
	profiles  ProfileSummaryQueryService
	contracts *contracts.InvestigationContracts
}

func NewContextProjectionOperations(excerpts ContextExcerptService, results ContextQueryResults) (*ContextProjectionOperations, error) {
	if excerpts == nil || results == nil {
		return nil, ErrOperationsConfiguration
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		return nil, err
	}
	return &ContextProjectionOperations{excerpts: excerpts, results: results, contracts: wire}, nil
}

// WithHTTPHeaders adds the ADR-282 get_http_headers admission to the same
// audited query operations; get_query_result then also serves its pages.
func (s *ContextProjectionOperations) WithHTTPHeaders(headers HTTPHeaderQueryService) (*ContextProjectionOperations, error) {
	if s == nil || headers == nil || s.headers != nil {
		return nil, ErrOperationsConfiguration
	}
	out := *s
	out.headers = headers
	return &out, nil
}

// serves reports whether name is one of this composition's operations.
func (s *ContextProjectionOperations) serves(name string) bool {
	return s != nil && queryOperation(name) && (name != "get_http_headers" || s.headers != nil) && (name != "get_profile_summary" || s.profiles != nil)
}

// toolNames are the operations this composition advertises.
func (s *ContextProjectionOperations) toolNames() []string {
	names := []string{"get_file_excerpt", "get_query_result"}
	if s.headers != nil {
		names = append(names, "get_http_headers")
	}
	if s.profiles != nil {
		names = append(names, "get_profile_summary")
	}
	return names
}

func (s *ContextProjectionOperations) CallWithContext(ctx context.Context, current identities.CurrentIdentity, call OperationCall, name string, raw json.RawMessage) (OperationReply, error) {
	noDispatch := OperationReply{auditNoDispatch: true, auditEffect: operationEffectNone}
	if s == nil || ctx == nil || ctx.Err() != nil || current == nil || call.queryInvocation == nil ||
		!s.serves(name) || s.contracts.ValidateInput(name, raw) != nil {
		return noDispatch, stopped("query-call", ErrOperationDelivery)
	}
	i := call.queryInvocation
	record, err := i.Invocation(ctx)
	if err != nil || record.ID != call.requestID || record.Tool != name {
		return noDispatch, stopped("query-invocation", ErrOperationDelivery)
	}
	var input analysisapp.ContextQueryInput
	switch name {
	case "get_profile_summary":
		var in ProfileSummaryOperationInput
		if json.Unmarshal(raw, &in) != nil {
			return noDispatch, ErrOperationDelivery
		}
		selection, e := value.NormalizeProfileSummarySelection(in.SampleType, in.TopN)
		if e != nil {
			return noDispatch, ErrOperationDelivery
		}
		input.Profile = value.ProfileSummaryRequest{CaseID: in.CaseID, ArtifactID: in.ArtifactID, Selection: selection}
	case "get_http_headers":
		var in HTTPHeaderOperationInput
		if json.Unmarshal(raw, &in) != nil {
			return noDispatch, ErrOperationDelivery
		}
		sel, e := value.NormalizeHTTPHeaderSelection(in.CaseID, in.ArtifactID, in.Cursor, in.Limit)
		if e != nil {
			// A malformed cursor is judged before any lookup and names no
			// artifact fact; any other input refusal is the shared outcome.
			failure, decision := httpHeaderNotAvailable, operationAuditDenied
			if errors.Is(e, value.ErrInvalidCursor) {
				failure, decision = httpHeaderInvalidCursor, operationAuditInvalid
			}
			return s.refusal(record.ID, name, record.Until, failure, decision, operationEffectNone, true)
		}
		input.Headers = sel
	case "get_file_excerpt":
		var in struct {
			CaseID     string `json:"case_id"`
			ArtifactID string `json:"artifact_id"`
			LineStart  int    `json:"line_start"`
			MaxLines   int    `json:"max_lines"`
		}
		if json.Unmarshal(raw, &in) != nil {
			return noDispatch, ErrOperationDelivery
		}
		selection, e := value.NormalizeLineSelection(in.LineStart, in.MaxLines)
		if e != nil {
			return noDispatch, ErrOperationDelivery
		}
		input.Selection = value.ContextExcerptSelection{CaseID: in.CaseID, ArtifactID: in.ArtifactID, Selection: selection}
	default:
		var in struct {
			QueryHandle string `json:"query_handle"`
		}
		if json.Unmarshal(raw, &in) != nil {
			return noDispatch, ErrOperationDelivery
		}
		input.QueryID = in.QueryHandle
	}
	if i.CheckInput(ctx, input) != nil {
		return noDispatch, stopped("query-input", ErrOperationDelivery)
	}
	var d *analysisapp.ContextProjectionDelivery
	switch name {
	case "get_profile_summary":
		d, err = s.profiles.Begin(ctx, current, i, input.Profile)
	case "get_file_excerpt":
		d, err = s.excerpts.BeginExcerpt(ctx, current, i, input.Selection)
	case "get_http_headers":
		d, err = s.headers.Begin(ctx, current, i, input.Headers)
	default:
		d, err = s.results.GetQueryResult(ctx, current, i, input.QueryID)
	}
	// Any dispatched error may have spent query/read/control capacity. Closing
	// an accompanying handle is mandatory and never establishes no effect.
	transferred := false
	defer func() {
		if !transferred {
			i.close()
			if d != nil {
				until := identity.Earlier(record.WriteUntil, d.CleanupUntil())
				cleanup, cancel := context.WithDeadline(context.WithoutCancel(ctx), until)
				_ = d.Close(cleanup)
				cancel()
			}
		}
	}()
	if d == nil && errors.Is(err, value.ErrInvalidCursor) && name != "get_file_excerpt" {
		// The worker judged the cursor against the rechecked document after
		// current read rights; the read stays charged and nothing is disclosed.
		return s.refusal(record.ID, name, record.Until, httpHeaderInvalidCursor, operationAuditInvalid, operationEffectAccepted, false)
	}
	if d == nil && errors.Is(err, value.ErrRecordTooLarge) && name != "get_file_excerpt" {
		// The worker's first selected record alone exceeds the wire bound; the
		// read stays charged and nothing is disclosed.
		return s.refusal(record.ID, name, record.Until, httpHeaderTooLarge, operationAuditDenied, operationEffectAccepted, false)
	}
	if d == nil && errors.Is(err, value.ErrBusy) && name == "get_http_headers" {
		// ADR-282: the live worker caps are full; the query was not admitted
		// or charged, and a later page request may succeed.
		return s.refusal(record.ID, name, record.Until, httpHeaderNotAvailable, operationAuditDenied, operationEffectNone, false)
	}
	if err != nil || d == nil {
		// The service's own closed stage names this refusal in the report.
		return OperationReply{}, stoppedAt("query", err, ErrOperationDelivery)
	}
	select {
	case <-d.Done():
		return OperationReply{}, stopped("query-done", ErrOperationDelivery)
	default:
	}
	body, err := s.serialize(call.requestID, name, d)
	if errors.Is(err, value.ErrRecordTooLarge) && d.Tool() == "get_profile_summary" {
		return s.refusal(record.ID, name, record.Until, profileSummaryTooLarge, operationAuditDenied, operationEffectAccepted, false)
	}
	if err != nil {
		return OperationReply{}, stopped("query-output", ErrOperationDelivery)
	}
	if i.bind(ctx, d, int64(len(body))) != nil {
		clear(body)
		return OperationReply{}, stopped("query-bind", ErrOperationDelivery)
	}
	reply := OperationReply{Body: body, ValidUntil: d.ValidUntil(), auditEffect: operationEffectAccepted}
	reply, err = ownOperationReply(ctx, reply, &contextProjectionGuard{delivery: d, invocation: i, preparedUntil: reply.ValidUntil},
		identity.Earlier(record.WriteUntil, d.CleanupUntil()), i.acknowledge)
	if err != nil {
		clear(body)
		return OperationReply{}, stoppedAt("query-reply", err, err)
	}
	transferred = true
	return reply, nil
}

type queryViewTimes struct {
	ObservedAt time.Time `json:"query_observed_at"`
	ExpiresAt  time.Time `json:"query_expires_at"`
}

func (s *ContextProjectionOperations) serialize(requestID, name string, d *analysisapp.ContextProjectionDelivery) ([]byte, error) {
	times := queryViewTimes{ObservedAt: d.ObservedAt(), ExpiresAt: d.QueryDeadline()}
	envelope := OperationEnvelope{SchemaVersion: "mcp-result/v1", RequestID: requestID,
		DataClass: "metadata", Status: "ok", Warnings: []string{}, Provenance: []any{}}
	switch {
	case d.Pending() && name == "get_http_headers":
		// The canonical get_http_headers pending branch carries the handle only.
		envelope.Status = "pending"
		envelope.Data = struct {
			QueryHandle string `json:"query_handle"`
			RetryAfter  int    `json:"retry_after_seconds"`
		}{d.Association().QueryID, 1}
	case d.Pending():
		envelope.Status = "pending"
		envelope.Data = struct {
			QueryHandle string `json:"query_handle"`
			RetryAfter  int    `json:"retry_after_seconds"`
			queryViewTimes
		}{d.Association().QueryID, 1, times}
	case d.Tool() == "get_profile_summary":
		summary, ok := d.ProfileSummary()
		if !ok {
			return nil, ErrOperationDelivery
		}
		artifactID, version := d.Provenance()
		envelope.DataClass = "extract"
		envelope.Warnings = []string{profileSummaryHandling}
		if summary.SymbolStatus != "complete" {
			envelope.Warnings = append(envelope.Warnings, "SymbolCoverage: Some or all function names are unavailable; unresolved samples remain in the totals.")
		}
		envelope.Provenance = []any{httpHeaderProvenance{ArtifactID: artifactID, Digest: hash(version)}}
		envelope.Data = struct {
			value.ProfileSummary
			queryViewTimes
		}{summary, times}
		if name == "get_query_result" {
			envelope.Data = queryResult(d.Association().QueryID, d.Tool(), envelope, times)
			envelope.Provenance = []any{}
		}
	case d.Tool() == "get_http_headers":
		page, ok := d.HeaderPage()
		if !ok {
			return nil, ErrOperationDelivery
		}
		artifactID, version := d.Provenance()
		wrap := func(inner OperationEnvelope) any { return inner }
		if name == "get_query_result" {
			wrap = func(inner OperationEnvelope) any {
				outer := envelope
				outer.Data = queryResult(d.Association().QueryID, d.Tool(), inner, times)
				if inner.Status == "ok" {
					outer.DataClass, outer.Warnings = "extract", []string{httpHeaderHandling}
				}
				return outer
			}
		}
		inner, err := renderHTTPHeaderPage(requestID, page, artifactID, version, wrap)
		if err != nil {
			return nil, ErrOperationDelivery
		}
		if inner.Status != "ok" {
			// A record that cannot fit is the tool's explicit error.
			envelope = inner
		} else if outer, ok := wrap(inner).(OperationEnvelope); ok {
			envelope = outer
		} else {
			return nil, ErrOperationDelivery
		}
	default:
		excerpt, ok := d.Excerpt()
		if !ok {
			return nil, ErrOperationDelivery
		}
		defer clear(excerpt.Lines)
		envelope.Data = struct {
			value.ContextExcerpt
			queryViewTimes
		}{excerpt, times}
		if name == "get_query_result" {
			envelope.Data = queryResult(d.Association().QueryID, "get_file_excerpt", envelope, times)
		}
	}
	body, err := json.Marshal(envelope)
	if err == nil && len(body) > contracts.InvestigationOutputLimit && d.Tool() == "get_profile_summary" {
		clear(body)
		return nil, value.ErrRecordTooLarge
	}
	if err != nil || len(body) > contracts.InvestigationOutputLimit || s.contracts.ValidateOutput(name, body) != nil {
		clear(body)
		return nil, ErrOperationDelivery
	}
	return body, nil
}

func queryResult(queryID, tool string, inner OperationEnvelope, times queryViewTimes) any {
	return struct {
		QueryHandle string            `json:"query_handle"`
		ToolName    string            `json:"tool_name"`
		Result      OperationEnvelope `json:"result"`
		queryViewTimes
	}{queryID, tool, inner, times}
}

// refusal is a fixed error reply without a delivery. noDispatch marks a
// refusal proven before any query effect.
func (s *ContextProjectionOperations) refusal(requestID, name string, until time.Time, f OperationFailure, decision operationAuditDecision, effect operationAuditEffect, noDispatch bool) (OperationReply, error) {
	body, err := json.Marshal(httpHeaderFailure(requestID, f))
	if err != nil || len(body) > contracts.InvestigationOutputLimit || s.contracts.ValidateOutput(name, body) != nil {
		clear(body)
		return OperationReply{auditNoDispatch: noDispatch, auditEffect: effect}, ErrOperationDelivery
	}
	return OperationReply{Body: body, ValidUntil: until, auditDecision: decision, auditEffect: effect, auditNoDispatch: noDispatch}, nil
}

type contextProjectionGuard struct {
	delivery      *analysisapp.ContextProjectionDelivery
	invocation    *contextQueryInvocation
	preparedUntil time.Time
}

func (g *contextProjectionGuard) CheckDisclosure(ctx context.Context) error {
	if err := g.delivery.CheckDisclosure(ctx); err != nil {
		return err
	}
	// The serialized reply/socket selected the prepared bound. A blocking
	// check that discovers an earlier lease rejects this exact response; it
	// cannot leave the transport using its older, longer deadline.
	if g.delivery.ValidUntil().Before(g.preparedUntil) {
		return ErrOperationDelivery
	}
	return nil
}
func (g *contextProjectionGuard) Done() <-chan struct{} { return g.delivery.Done() }
func (g *contextProjectionGuard) Close(ctx context.Context) error {
	g.invocation.close()
	return g.delivery.Close(ctx)
}

// ProfileSummaryQueryService admits one closed aggregate through the existing
// query pipeline. Installing this optional facet is a separate qualification gate.
type ProfileSummaryQueryService interface {
	Begin(context.Context, identities.CurrentIdentity, analysisapp.ContextQueryInvocation, value.ProfileSummaryRequest) (*analysisapp.ContextProjectionDelivery, error)
}

func (s *ContextProjectionOperations) WithProfileSummaries(profiles ProfileSummaryQueryService) (*ContextProjectionOperations, error) {
	if s == nil || profiles == nil || s.profiles != nil {
		return nil, ErrOperationsConfiguration
	}
	out := *s
	out.profiles = profiles
	return &out, nil
}

const profileSummaryHandling = "SensitiveDataHandling: Function names may contain user data. This summary omits raw samples, labels, paths and addresses. Automatic deletion covers Asservat-managed copies; copies already delivered cannot be recalled."

var profileSummaryTooLarge = OperationFailure{Code: "AnalysisUnavailable", Message: "This profile summary does not fit the response limit. Select fewer hotspots.", Retryable: false}
