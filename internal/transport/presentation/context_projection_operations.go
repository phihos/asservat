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
)

// Initial admission and passive results are separate consumer capabilities.
// Both return the concrete C-18 owner; arbitrary result DTOs are insufficient.
type ContextExcerptService interface {
	BeginExcerpt(context.Context, identities.CurrentIdentity, string, value.ContextExcerptSelection) (*analysisapp.ContextProjectionDelivery, error)
}
type ContextQueryResults interface {
	GetQueryResult(context.Context, identities.CurrentIdentity, string, string) (*analysisapp.ContextProjectionDelivery, error)
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

// serves reports whether name is one of this composition's public tools.
func (s *ContextProjectionOperations) serves(name string) bool {
	return s != nil && queryOperation(name) && (name != "query_artifact" || s.packetQueries != nil || s.rawSyscalls != nil) && (name != "compare_profiles" || s.comparisons != nil)
}

// toolNames are the public tools this composition advertises.
func (s *ContextProjectionOperations) toolNames() []string {
	names := []string{"get_extract", "get_query_result"}
	if s.packetQueries != nil || s.rawSyscalls != nil {
		names = append(names, "query_artifact")
	}
	if s.comparisons != nil {
		names = append(names, "compare_profiles")
	}
	return names
}

// available reports whether the internal operation's facet is composed.
func (s *ContextProjectionOperations) available(op string) bool {
	switch op {
	case "get_logs":
		return s.rawLogs != nil
	case "syscall_query":
		return s.rawSyscalls != nil
	case "pcap_query":
		return s.packetQueries != nil
	case "get_http_headers":
		return s.headers != nil
	case "get_profile_summary":
		return s.profiles != nil
	case "get_pcap_summary":
		return s.packets != nil
	case "compare_profiles":
		return s.comparisons != nil
	case "get_syscall_summary", "get_syscall_events":
		return s.syscalls != nil
	}
	return op == "get_file_excerpt" || op == "get_query_result"
}

var capabilityUnavailable = OperationFailure{Code: "CapabilityUnavailable", Message: "This view or operation is not available in this installation.", Retryable: false}
var invalidCursor = OperationFailure{Code: "InvalidCursor", Message: "The cursor is not valid for this saved evidence view. Start again without a cursor.", Retryable: false}
var packetQueryInvalid = OperationFailure{Code: "InvalidInput", Message: "Use the supported bounded tcpdump/libpcap packet-filter subset, fields and frame-prefix range. Names, protocol-offset predicates and unsupported instructions are unavailable.", Retryable: false}

func (s *ContextProjectionOperations) CallWithContext(ctx context.Context, current identities.CurrentIdentity, call OperationCall, name string, raw json.RawMessage) (OperationReply, error) {
	noDispatch := OperationReply{auditNoDispatch: true, auditEffect: operationEffectNone}
	if s == nil || ctx == nil || ctx.Err() != nil || current == nil || call.requestID == "" ||
		!s.serves(name) || s.contracts.ValidateInput(name, raw) != nil {
		return noDispatch, stopped("query-call", ErrOperationDelivery)
	}
	// The audited wrapper bounds every call with its original deadline.
	until, bounded := ctx.Deadline()
	if !bounded {
		return noDispatch, stopped("query-call", ErrOperationDelivery)
	}
	requestID := call.requestID
	op, in, err := decodeProjection(name, raw)
	if err != nil {
		return noDispatch, ErrOperationDelivery
	}
	if !s.available(op) {
		return s.refusal(requestID, name, until, capabilityUnavailable, operationAuditUnspecified, operationEffectNone, true)
	}
	refuse := func(e error, other OperationFailure) (OperationReply, error) {
		if errors.Is(e, value.ErrInvalidCursor) {
			return s.refusal(requestID, name, until, invalidCursor, operationAuditInvalid, operationEffectNone, true)
		}
		return s.refusal(requestID, name, until, other, operationAuditDenied, operationEffectNone, true)
	}
	var d *analysisapp.ContextProjectionDelivery
	switch op {
	case "get_logs":
		sel, e := value.NormalizeLogSelection(in.CaseID, in.ArtifactID, in.Cursor, in.Limit)
		if e != nil {
			return refuse(value.ErrInvalidCursor, invalidCursor)
		}
		d, err = s.rawLogs.Begin(ctx, current, requestID, value.RawLogQueryRequest{CaseID: in.CaseID, ArtifactID: in.ArtifactID, GrantID: in.GrantID, IdempotencyKey: in.IdempotencyKey, Selection: sel.LogWindow})
	case "syscall_query", "get_syscall_summary", "get_syscall_events":
		view := map[string]value.SyscallView{"syscall_query": value.SyscallQueryView, "get_syscall_summary": value.SyscallSummaryView, "get_syscall_events": value.SyscallEventsView}[op]
		sel, e := value.NormalizeSyscallSelection(in.CaseID, in.ArtifactID, view, in.Cursor, in.Limit, in.Names, in.ErrorsOnly)
		if e != nil {
			return refuse(e, syscallNotAvailable)
		}
		if op == "syscall_query" {
			d, err = s.rawSyscalls.Begin(ctx, current, requestID, value.RawSyscallQueryRequest{CaseID: in.CaseID, ArtifactID: in.ArtifactID, GrantID: in.GrantID, IdempotencyKey: in.IdempotencyKey, Selection: sel.Window()})
		} else {
			d, err = s.syscalls.Begin(ctx, current, requestID, value.SyscallQueryRequest{CaseID: in.CaseID, ArtifactID: in.ArtifactID, Selection: sel.Window()})
		}
	case "pcap_query":
		// Packet results are one bounded page; no cursor is ever issued.
		if in.Cursor != "" {
			return refuse(value.ErrInvalidCursor, invalidCursor)
		}
		r := in.packetQuery()
		if !r.Valid() {
			return s.refusal(requestID, name, until, packetQueryInvalid, operationAuditInvalid, operationEffectNone, true)
		}
		d, err = s.packetQueries.Begin(ctx, current, requestID, r)
	case "get_pcap_summary":
		d, err = s.packets.Begin(ctx, current, requestID, value.PacketSummaryRequest{CaseID: in.CaseID, ArtifactID: in.ArtifactID})
	case "compare_profiles":
		sel, e := value.NormalizeProfileComparisonSelection(in.SampleType, in.Normalization, in.Limit)
		if e != nil {
			return noDispatch, ErrOperationDelivery
		}
		d, err = s.comparisons.Begin(ctx, current, requestID, value.ProfileComparisonRequest{CaseID: in.CaseID, ArtifactID: in.ArtifactID, BaselineCaseID: in.BaselineCaseID, BaselineArtifactID: in.BaselineArtifactID, Selection: sel})
	case "get_profile_summary":
		sel, e := value.NormalizeProfileSummarySelection(in.SampleType, in.Limit)
		if e != nil {
			return s.refusal(requestID, name, until, profileSummaryNotAvailable, operationAuditDenied, operationEffectNone, true)
		}
		d, err = s.profiles.Begin(ctx, current, requestID, value.ProfileSummaryRequest{CaseID: in.CaseID, ArtifactID: in.ArtifactID, Selection: sel})
	case "get_http_headers":
		sel, e := value.NormalizeHTTPHeaderSelection(in.CaseID, in.ArtifactID, in.Cursor, in.Limit)
		if e != nil {
			// A malformed cursor is judged before any lookup and names no
			// artifact fact; any other input refusal is the shared outcome.
			return refuse(e, httpHeaderNotAvailable)
		}
		d, err = s.headers.Begin(ctx, current, requestID, sel)
	case "get_file_excerpt":
		sel, e := value.NormalizeLineSelection(in.LineStart, in.Limit)
		if e != nil {
			return noDispatch, ErrOperationDelivery
		}
		d, err = s.excerpts.BeginExcerpt(ctx, current, requestID, value.ContextExcerptSelection{CaseID: in.CaseID, ArtifactID: in.ArtifactID, Selection: sel})
	default:
		d, err = s.results.GetQueryResult(ctx, current, requestID, in.QueryHandle)
	}
	// Any dispatched error may have spent query/read/control capacity. Closing
	// an accompanying handle is mandatory and never establishes no effect.
	transferred := false
	defer func() {
		if !transferred {
			if d != nil {
				cleanup, cancel := context.WithDeadline(context.WithoutCancel(ctx), d.CleanupUntil())
				_ = d.Close(cleanup)
				cancel()
			}
		}
	}()
	if d == nil && op == "get_logs" && analysisapp.RawLogQueryApprovalRequiredBeforeAdmission(err) {
		return s.refusal(requestID, name, until, OperationFailure{Code: "RawApprovalRequired", Message: "Independent approval must cover log queries for this saved log artifact and your current registered client. Download approval does not cover this query.", Retryable: false}, operationAuditUnspecified, operationEffectNone, true)
	}
	if d == nil && op == "syscall_query" && analysisapp.RawSyscallQueryApprovalRequiredBeforeAdmission(err) {
		return s.refusal(requestID, name, until, OperationFailure{Code: "RawApprovalRequired", Message: "Independent approval must cover syscall argument queries for this saved artifact and your current registered client. Download approval does not cover this query.", Retryable: false}, operationAuditUnspecified, operationEffectNone, true)
	}
	if d == nil && op == "pcap_query" && analysisapp.PacketQueryApprovalRequiredBeforeAdmission(err) {
		return s.refusal(requestID, name, until, OperationFailure{Code: "RawApprovalRequired", Message: "Independent approval must cover packet queries for this saved raw artifact and your current registered client. Download approval does not cover this query.", Retryable: false}, operationAuditUnspecified, operationEffectNone, true)
	}
	if d == nil && op == "pcap_query" {
		if invalid, known := analysisapp.PacketQueryFilterRefusedBeforeAdmission(err); known {
			failure := OperationFailure{Code: "NotAvailable", Message: "Packet filtering is not available with the current service conditions. Retry later.", Retryable: true}
			status := operationAuditUnspecified
			if invalid {
				failure = packetQueryInvalid
				status = operationAuditInvalid
			}
			return s.refusal(requestID, name, until, failure, status, operationEffectNone, true)
		}
	}
	if d == nil && op == "get_pcap_summary" && analysisapp.PacketSummaryUnavailableBeforeAdmission(err) {
		return s.refusal(requestID, name, until, packetSummaryNotAvailable, operationAuditUnspecified, operationEffectNone, true)
	}
	if d == nil && op == "get_profile_summary" && analysisapp.ProfileSummaryUnavailableBeforeAdmission(err) {
		// C18 proved no query admission was attempted. Access, missing/unsupported
		// source and provider failures share one nondisclosing result; audit and the
		// original final identity/deadline checks still precede delivery.
		return s.refusal(requestID, name, until, profileSummaryNotAvailable, operationAuditUnspecified, operationEffectNone, true)
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
		reply, err = s.deliveryRefusal(requestID, name, d)
	} else {
		reply.Body, err = s.serialize(requestID, name, d)
		reply.ValidUntil, reply.auditEffect = d.ValidUntil(), operationEffectAccepted
		if d.Effect() == analysisapp.ContextQueryReplayed {
			reply.auditEffect = operationEffectNone
		}
		if errors.Is(err, value.ErrRecordTooLarge) && d.RefuseOversizedResult() {
			reply, err = s.deliveryRefusal(requestID, name, d)
		}
	}
	if err != nil {
		return OperationReply{}, stopped("query-output", ErrOperationDelivery)
	}
	body := reply.Body
	reply, err = ownOperationReply(ctx, reply, &contextProjectionGuard{delivery: d, preparedUntil: reply.ValidUntil}, d.CleanupUntil(), nil)
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
	if !d.Pending() {
		render := map[string]func(string, string, *analysisapp.ContextProjectionDelivery, queryViewTimes) ([]byte, error){
			"get_logs": renderRawLogResult, "syscall_query": renderRawSyscallResult, "get_syscall_summary": renderSyscallResult, "get_syscall_events": renderSyscallResult,
		}[d.Tool()]
		if render != nil {
			body, err := render(requestID, name, d, times)
			if err != nil {
				return nil, err
			}
			if s.contracts.ValidateOutput(name, body) != nil {
				clear(body)
				return nil, ErrOperationDelivery
			}
			return body, nil
		}
	}
	envelope := OperationEnvelope{SchemaVersion: "mcp-result/v1", RequestID: requestID,
		DataClass: "metadata", Status: "ok", Warnings: []string{}, Provenance: []any{}}
	switch {
	case d.Pending():
		// The coordinator's after_revision wait sees one pending revision
		// until the result is ready.
		envelope.Status = "pending"
		envelope.Data = struct {
			QueryHandle string `json:"query_handle"`
			Revision    int    `json:"revision"`
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
			envelope.Data = queryResult(d.Association().QueryID, d.Tool(), envelope, times)
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
		failure, decision = invalidCursor, operationAuditInvalid
	case analysisapp.ContextProjectionIncompatibleProfiles:
		failure = profileComparisonIncompatible
	case analysisapp.ContextProjectionRecordTooLarge:
		failure = map[string]OperationFailure{"get_logs": {Code: "NotAvailable", Message: "This saved log fragment does not fit the response limit.", Retryable: false},
			"syscall_query": syscallTooLarge, "get_syscall_summary": syscallTooLarge, "get_syscall_events": syscallTooLarge,
			"get_profile_summary": profileSummaryTooLarge, "compare_profiles": profileComparisonTooLarge}[d.Tool()]
		if failure.Code == "" {
			failure = httpHeaderTooLarge
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
	}{queryID, publicTool(tool), inner, times}
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
func (g *contextProjectionGuard) Done() <-chan struct{}           { return g.delivery.Done() }
func (g *contextProjectionGuard) Close(ctx context.Context) error { return g.delivery.Close(ctx) }

// ProfileSummaryQueryService admits one closed aggregate through the existing
// query pipeline. Installing this optional facet is a separate qualification gate.
type ProfileSummaryQueryService interface {
	Begin(context.Context, identities.CurrentIdentity, string, value.ProfileSummaryRequest) (*analysisapp.ContextProjectionDelivery, error)
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
	Begin(context.Context, identities.CurrentIdentity, string, value.ProfileComparisonRequest) (*analysisapp.ContextProjectionDelivery, error)
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
