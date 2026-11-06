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
	excerpts      ContextExcerptService
	results       ContextQueryResults
	headers       HTTPHeaderQueryService
	comparisons   ProfileComparisonQueryService
	profiles      ProfileSummaryQueryService
	packets       PacketSummaryQueryService
	packetQueries PacketQueryService
	syscalls      SyscallQueryService
	rawSyscalls   RawSyscallQueryService
	rawLogs       RawLogQueryService
	contracts     *contracts.InvestigationContracts
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
	return s != nil && queryOperation(name) && (name != "get_logs" || s.rawLogs != nil) && (name != "syscall_query" || s.rawSyscalls != nil) && (name != "get_http_headers" || s.headers != nil) && (name != "get_profile_summary" || s.profiles != nil) && (name != "get_pcap_summary" || s.packets != nil) && (name != "pcap_query" || s.packetQueries != nil) && (name != "compare_profiles" || s.comparisons != nil) && (!syscallQueryOperation(name) || s.syscalls != nil)
}

// toolNames are the operations this composition advertises.
func (s *ContextProjectionOperations) toolNames() []string {
	names := []string{"get_file_excerpt", "get_query_result"}
	if s.rawLogs != nil {
		names = append(names, "get_logs")
	}
	if s.rawSyscalls != nil {
		names = append(names, "syscall_query")
	}
	if s.packetQueries != nil {
		names = append(names, "pcap_query")
	}
	if s.headers != nil {
		names = append(names, "get_http_headers")
	}
	if s.comparisons != nil {
		names = append(names, "compare_profiles")
	}
	if s.profiles != nil {
		names = append(names, "get_profile_summary")
	}
	if s.packets != nil {
		names = append(names, "get_pcap_summary")
	}
	if s.syscalls != nil {
		names = append(names, "get_syscall_summary", "get_syscall_events")
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
	case "get_logs":
		var in RawLogQueryOperationInput
		if json.Unmarshal(raw, &in) != nil {
			return noDispatch, ErrOperationDelivery
		}
		r, e := in.request()
		if e != nil {
			return s.refusal(record.ID, name, record.Until, syscallInvalidCursor, operationAuditInvalid, operationEffectNone, true)
		}
		input.RawLogs = r
	case "syscall_query":
		var in RawSyscallQueryOperationInput
		if json.Unmarshal(raw, &in) != nil {
			return noDispatch, ErrOperationDelivery
		}
		r, e := in.request()
		if e != nil {
			return s.refusal(record.ID, name, record.Until, syscallInvalidCursor, operationAuditInvalid, operationEffectNone, true)
		}
		input.RawSyscalls = r
	case "pcap_query":
		var in PacketQueryOperationInput
		if json.Unmarshal(raw, &in) != nil {
			return noDispatch, ErrOperationDelivery
		}
		input.PacketQuery = in.request()
	case "get_pcap_summary":
		var in PacketSummaryOperationInput
		if json.Unmarshal(raw, &in) != nil {
			return noDispatch, ErrOperationDelivery
		}
		input.Packet = value.PacketSummaryRequest{CaseID: in.CaseID, ArtifactID: in.ArtifactID}
	case "get_syscall_summary", "get_syscall_events":
		var in SyscallOperationInput
		if json.Unmarshal(raw, &in) != nil {
			return noDispatch, ErrOperationDelivery
		}
		selection, e := value.NormalizeSyscallSelection(in.CaseID, in.ArtifactID, syscallView(name), in.Cursor, in.Limit, in.Names, in.ErrorsOnly)
		if e != nil {
			failure, decision := syscallNotAvailable, operationAuditDenied
			if errors.Is(e, value.ErrInvalidCursor) {
				failure, decision = syscallInvalidCursor, operationAuditInvalid
			}
			return s.refusal(record.ID, name, record.Until, failure, decision, operationEffectNone, true)
		}
		input.Syscalls = value.SyscallQueryRequest{CaseID: in.CaseID, ArtifactID: in.ArtifactID, Selection: selection.Window()}
	case "compare_profiles":
		var in ProfileComparisonOperationInput
		if json.Unmarshal(raw, &in) != nil {
			return noDispatch, ErrOperationDelivery
		}
		selection, e := value.NormalizeProfileComparisonSelection(in.SampleType, in.Normalization, in.TopN)
		if e != nil {
			return noDispatch, ErrOperationDelivery
		}
		input.Comparison = value.ProfileComparisonRequest{CaseID: in.CaseID, ArtifactID: in.ArtifactID, BaselineCaseID: in.BaselineCaseID, BaselineArtifactID: in.BaselineArtifactID, Selection: selection}

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
	case "get_logs":
		d, err = s.rawLogs.Begin(ctx, current, i, input.RawLogs)
	case "syscall_query":
		d, err = s.rawSyscalls.Begin(ctx, current, i, input.RawSyscalls)
	case "pcap_query":
		d, err = s.packetQueries.Begin(ctx, current, i, input.PacketQuery)
	case "get_pcap_summary":
		d, err = s.packets.Begin(ctx, current, i, input.Packet)
	case "get_syscall_summary", "get_syscall_events":
		d, err = s.syscalls.Begin(ctx, current, i, input.Syscalls)
	case "compare_profiles":
		d, err = s.comparisons.Begin(ctx, current, i, input.Comparison)
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
	if d == nil && name == "get_logs" && analysisapp.RawLogQueryApprovalRequiredBeforeAdmission(err) {
		return s.refusal(record.ID, name, record.Until, OperationFailure{Code: "RawApprovalRequired", Message: "Independent approval must cover get_logs for this saved log artifact and your current registered client. Download approval does not cover this query.", Retryable: false}, operationAuditUnspecified, operationEffectNone, true)
	}
	if d == nil && name == "syscall_query" && analysisapp.RawSyscallQueryApprovalRequiredBeforeAdmission(err) {
		return s.refusal(record.ID, name, record.Until, OperationFailure{Code: "RawApprovalRequired", Message: "Independent approval must cover syscall_query for this saved argument artifact and your current registered client. Download approval does not cover this query.", Retryable: false}, operationAuditUnspecified, operationEffectNone, true)
	}
	if d == nil && name == "pcap_query" && analysisapp.PacketQueryApprovalRequiredBeforeAdmission(err) {
		return s.refusal(record.ID, name, record.Until, OperationFailure{Code: "RawApprovalRequired", Message: "Independent approval must cover pcap_query for this saved raw artifact and your current registered client. Download approval does not cover this query.", Retryable: false}, operationAuditUnspecified, operationEffectNone, true)
	}
	if d == nil && name == "pcap_query" {
		if invalid, known := analysisapp.PacketQueryFilterRefusedBeforeAdmission(err); known {
			failure := OperationFailure{Code: "NotAvailable", Message: "Packet filtering is not available with the current service conditions. Retry later.", Retryable: true}
			status := operationAuditUnspecified
			if invalid {
				failure = OperationFailure{Code: "InvalidInput", Message: "Use the supported bounded tcpdump/libpcap packet-filter subset. Names, protocol-offset predicates and unsupported instructions are unavailable.", Retryable: false}
				status = operationAuditInvalid
			}
			return s.refusal(record.ID, name, record.Until, failure, status, operationEffectNone, true)
		}
	}
	if d == nil && errors.Is(err, value.ErrBusy) && name == "get_http_headers" {
		// ADR-282: the live worker caps are full; the query was not admitted
		// or charged, and a later page request may succeed.
		return s.refusal(record.ID, name, record.Until, httpHeaderNotAvailable, operationAuditDenied, operationEffectNone, false)
	}
	if d == nil && name == "get_pcap_summary" && analysisapp.PacketSummaryUnavailableBeforeAdmission(err) {
		return s.refusal(record.ID, name, record.Until, packetSummaryNotAvailable, operationAuditUnspecified, operationEffectNone, true)
	}
	if d == nil && name == "get_profile_summary" && analysisapp.ProfileSummaryUnavailableBeforeAdmission(err) {
		// C18 proved no query admission was attempted. Access, missing/unsupported
		// source and provider failures share one nondisclosing result; audit and the
		// original final identity/deadline checks still precede delivery.
		return s.refusal(record.ID, name, record.Until, profileSummaryNotAvailable, operationAuditUnspecified, operationEffectNone, true)
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
	var reply OperationReply
	if d.Refusal() != analysisapp.ContextProjectionNoRefusal {
		reply, err = s.deliveryRefusal(record.ID, name, d)
	} else {
		reply.Body, err = s.serialize(call.requestID, name, d)
		reply.ValidUntil, reply.auditEffect = d.ValidUntil(), operationEffectAccepted
		if d.Effect() == analysisapp.ContextQueryReplayed {
			reply.auditEffect = operationEffectNone
		}
		if errors.Is(err, value.ErrRecordTooLarge) && d.RefuseOversizedResult() {
			reply, err = s.deliveryRefusal(record.ID, name, d)
		}
	}
	if err != nil {
		return OperationReply{}, stopped("query-output", ErrOperationDelivery)
	}
	if i.bind(ctx, d, int64(len(reply.Body))) != nil {
		clear(reply.Body)
		return OperationReply{}, stopped("query-bind", ErrOperationDelivery)
	}
	body := reply.Body
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
	if !d.Pending() && d.Tool() == "get_logs" {
		body, err := renderRawLogResult(requestID, name, d, times)
		if err != nil {
			return nil, err
		}
		if s.contracts.ValidateOutput(name, body) != nil {
			clear(body)
			return nil, ErrOperationDelivery
		}
		return body, nil
	}
	if !d.Pending() && d.Tool() == "syscall_query" {
		body, err := renderRawSyscallResult(requestID, name, d, times)
		if err != nil {
			return nil, err
		}
		if s.contracts.ValidateOutput(name, body) != nil {
			clear(body)
			return nil, ErrOperationDelivery
		}
		return body, nil
	}
	if !d.Pending() && syscallQueryOperation(d.Tool()) {
		body, err := renderSyscallResult(requestID, name, d, times)
		if err != nil {
			return nil, err
		}
		if s.contracts.ValidateOutput(name, body) != nil {
			clear(body)
			return nil, ErrOperationDelivery
		}
		return body, nil
	}
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

	case d.Tool() == "pcap_query":
		page, ok := d.PacketQuery()
		if !ok {
			return nil, ErrOperationDelivery
		}
		envelope.DataClass = "extract"
		if page.CaptureMode == "rawPackets" {
			envelope.DataClass = "raw"
		}
		artifactID, version := d.Provenance()
		envelope.Provenance = []any{httpHeaderProvenance{ArtifactID: artifactID, Digest: hash(version)}}
		envelope.Warnings = []string{packetQueryHandling}
		envelope.Truncated = page.RowLimitReached || page.ScanLimitReached || page.OutputLimitReached
		if envelope.Truncated {
			hint := "Narrow the packet filter, time interval or selected fields to inspect another bounded result."
			envelope.NarrowingHint = &hint
			envelope.Warnings = append(envelope.Warnings, "QueryLimit: "+hint)
		}
		envelope.Data = struct {
			contracts.PacketQueryPage
			queryViewTimes
		}{packetQueryPage(page), times}
		if name == "get_query_result" {
			envelope.Data = queryResult(d.Association().QueryID, d.Tool(), envelope, times)
			envelope.Provenance = []any{}
			envelope.Truncated = false
			envelope.NarrowingHint = nil
		}
	case d.Tool() == "compare_profiles":
		comparison, ok := d.ProfileComparison()
		baseline, incident, sourcesOK := d.ProfileComparisonSources()
		if !ok || !sourcesOK {
			return nil, ErrOperationDelivery
		}
		envelope.DataClass = "extract"
		envelope.Warnings = []string{profileComparisonHandling}
		envelope.Provenance = []any{httpHeaderProvenance{ArtifactID: baseline.ArtifactID, Digest: hash(baseline.Version)}}
		if baseline.ArtifactID != incident.ArtifactID || baseline.Version != incident.Version {
			envelope.Provenance = append(envelope.Provenance, httpHeaderProvenance{ArtifactID: incident.ArtifactID, Digest: hash(incident.Version)})
		}
		envelope.Data = struct {
			value.ProfileComparison
			CaseID                string `json:"case_id"`
			ArtifactID            string `json:"artifact_id"`
			BaselineCaseID        string `json:"baseline_case_id"`
			BaselineArtifactID    string `json:"baseline_artifact_id"`
			SourceVersion         string `json:"source_version"`
			BaselineSourceVersion string `json:"baseline_source_version"`
			queryViewTimes
		}{comparison, incident.CaseID, incident.ArtifactID, baseline.CaseID, baseline.ArtifactID, hash(incident.Version), hash(baseline.Version), times}
		if name == "get_query_result" {
			envelope.Data = queryResult(d.Association().QueryID, d.Tool(), envelope, times)
			envelope.Provenance = []any{}
		}

	case d.Tool() == "get_pcap_summary":
		summary, ok := d.PacketSummary()
		if !ok {
			return nil, ErrOperationDelivery
		}
		artifactID, version := d.Provenance()
		envelope.DataClass = "extract"
		envelope.Warnings = []string{packetSummaryHandling}
		envelope.Provenance = []any{httpHeaderProvenance{ArtifactID: artifactID, Digest: hash(version)}}
		envelope.Data = struct {
			value.PacketSummary
			queryViewTimes
		}{summary, times}
		if name == "get_query_result" {
			envelope.Data = queryResult(d.Association().QueryID, d.Tool(), envelope, times)
			envelope.Provenance = []any{}
		}
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
			// Keep the charged delivery for the same acknowledged size-refusal
			// lifecycle as a worker or complete profile envelope refusal.
			return nil, value.ErrRecordTooLarge
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
	if err == nil && len(body) > contracts.InvestigationOutputLimit && (d.Tool() == "get_profile_summary" || d.Tool() == "compare_profiles") {
		clear(body)
		return nil, value.ErrRecordTooLarge
	}
	if err != nil || len(body) > contracts.InvestigationOutputLimit || s.contracts.ValidateOutput(name, body) != nil {
		clear(body)
		return nil, ErrOperationDelivery
	}
	return body, nil
}

// A charged refusal retains the same prepared body, exact invocation, live
// guard and final cleanup owner. It must never become an unowned error reply.
func (s *ContextProjectionOperations) deliveryRefusal(requestID, name string, d *analysisapp.ContextProjectionDelivery) (OperationReply, error) {
	failure, decision := httpHeaderTooLarge, operationAuditDenied
	switch d.Refusal() {
	case analysisapp.ContextProjectionInvalidCursor:
		failure, decision = httpHeaderInvalidCursor, operationAuditInvalid
		if d.Tool() == "get_logs" {
			failure = OperationFailure{Code: "InvalidCursor", Message: "The cursor does not match this saved log view. Start again without a cursor.", Retryable: false}
		}
		if name == "get_query_result" {
			failure.Message = "The cursor is not valid for this saved evidence view. Start again without a cursor."
		}
		if syscallQueryOperation(name) || d.Tool() == "syscall_query" {
			failure = syscallInvalidCursor
		}
	case analysisapp.ContextProjectionIncompatibleProfiles:
		failure = profileComparisonIncompatible
	case analysisapp.ContextProjectionRecordTooLarge:
		if d.Tool() == "get_logs" {
			failure = OperationFailure{Code: "NotAvailable", Message: "This saved log fragment does not fit the response limit.", Retryable: false}
		}
		if name == "get_query_result" {
			failure.Message = "This saved evidence record does not fit the response limit."
		}
		if syscallQueryOperation(name) || d.Tool() == "syscall_query" {
			failure = syscallTooLarge
		}
		if d.Tool() == "get_profile_summary" {
			failure = profileSummaryTooLarge
		}
		if d.Tool() == "compare_profiles" {
			failure = profileComparisonTooLarge
		}
	default:
		return OperationReply{}, ErrOperationDelivery
	}
	return s.refusal(requestID, name, d.ValidUntil(), failure, decision, operationEffectAccepted, false)
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
	envelope := httpHeaderFailure(requestID, f)
	if f.Code == "RawApprovalRequired" {
		envelope.Data = struct {
			OperationFailure
			ResponsibleRole string `json:"responsible_role"`
		}{f, "approver"}
	}
	body, err := json.Marshal(envelope)
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

var profileSummaryNotAvailable = OperationFailure{Code: "NotAvailable", Message: "This profile summary is not available with your current access or service conditions. Check your access or try again later.", Retryable: true}

var profileSummaryTooLarge = OperationFailure{Code: "AnalysisUnavailable", Message: "This profile summary does not fit the response limit. Select fewer hotspots.", Retryable: false}

// WithProfileComparisons opts into the fixed two-source admission facet.
type ProfileComparisonQueryService interface {
	Begin(context.Context, identities.CurrentIdentity, analysisapp.ContextQueryInvocation, value.ProfileComparisonRequest) (*analysisapp.ContextProjectionDelivery, error)
}

func (s *ContextProjectionOperations) WithProfileComparisons(comparisons ProfileComparisonQueryService) (*ContextProjectionOperations, error) {
	if s == nil || comparisons == nil || s.comparisons != nil {
		return nil, ErrOperationsConfiguration
	}
	out := *s
	out.comparisons = comparisons
	return &out, nil
}

const profileComparisonHandling = "SensitiveDataHandling: Function names may contain user data. This comparison omits raw samples, labels, paths and addresses. Automatic deletion covers Asservat-managed copies; copies already delivered cannot be recalled."

var profileComparisonIncompatible = OperationFailure{Code: "IncompatibleProfiles", Message: "The selected sample types, units or acquisition modes cannot be compared with this normalization.", Retryable: false}
var profileComparisonTooLarge = OperationFailure{Code: "AnalysisUnavailable", Message: "This profile comparison does not fit the response limit. Select fewer functions.", Retryable: false}
