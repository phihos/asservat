package presentation

import (
	auditapp "asservat.local/asservat/internal/application/audit"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"
	"unicode/utf8"
)

// AuditedOperationsConfig is accepted installation composition.
type AuditedOperationsConfig struct {
	RootID string
	Now    func() time.Time
	NewID  func() string
	// Changes signals committed status changes by ID; nil serves
	// after_revision without waiting.
	Changes *Changes
}
type auditTarget interface {
	Operations
	CallWithContext(context.Context, identities.CurrentIdentity, OperationCall, string, json.RawMessage) (OperationReply, error)
}

// AuditRecorder appends one audit row (REQ-AUT-005).
type AuditRecorder interface {
	Record(context.Context, audit.Event) error
}

// AuditedOperations writes one `call` audit row per admitted operation before
// it returns output (REQ-AUT-005, ADR-330 D6). A failed row fails the call.
type AuditedOperations struct {
	config    AuditedOperationsConfig
	inner     auditTarget
	recorder  AuditRecorder
	mac       *auditapp.OperationMAC
	contracts *contracts.InvestigationContracts
	stopSlots chan struct{}
	// Timing receives a fixed operation name separately from stage durations.
	// No input, identity or result enters either argument.
	Timing func(event, timing string)
}

// callTiming marks stage ends of one audited call for Timing.
type callTiming struct {
	start, call, finish time.Time
}

func (t callTiming) report(event string, steps *auditapp.StepTimes, out func(string, string)) {
	if out == nil {
		return
	}
	line := ""
	if !t.call.IsZero() {
		line += "call" + durationBucket(t.call, t.start)
	}
	if !t.finish.IsZero() {
		line += " audit" + durationBucket(t.finish, t.call)
	}
	line += " total" + durationBucket(time.Now(), t.start)
	if s := steps.String(); s != "" {
		line += " [" + s + "]"
	}
	out(event, line)
}

// durationBucket keeps timing lines in a finite vocabulary.
func durationBucket(end, start time.Time) string {
	if end.IsZero() {
		return "@none"
	}
	switch d := end.Sub(start); {
	case d < 100*time.Millisecond:
		return "@<100ms"
	case d < 250*time.Millisecond:
		return "@<250ms"
	case d < 500*time.Millisecond:
		return "@<500ms"
	case d < time.Second:
		return "@<1s"
	case d < 2*time.Second:
		return "@<2s"
	case d < 3*time.Second:
		return "@<3s"
	default:
		return "@>=3s"
	}
}

func NewAuditedOperations(c AuditedOperationsConfig, inner *InvestigationOperations, recorder AuditRecorder, mac *auditapp.OperationMAC) (*AuditedOperations, error) {
	if !authorization.UUID(c.RootID) || c.Now == nil || c.NewID == nil || inner == nil || mac == nil || recorder == nil {
		return nil, ErrOperationsConfiguration
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		return nil, err
	}
	return &AuditedOperations{config: c, inner: inner, recorder: recorder, mac: mac, contracts: wire, stopSlots: make(chan struct{}, 4)}, nil
}
func (s *AuditedOperations) PublicOrigin() string {
	if s == nil {
		return ""
	}
	return s.inner.PublicOrigin()
}
func (s *AuditedOperations) ToolNames() []string {
	if s == nil {
		return nil
	}
	return s.inner.ToolNames()
}
func (s *AuditedOperations) Tool(n string) (contracts.InvestigationTool, bool) {
	if s == nil {
		return contracts.InvestigationTool{}, false
	}
	return s.inner.Tool(n)
}

// IngressRejectionKind is a closed pre-dispatch classification. A rejection is
// never a dispatched business operation, including a requested resolution.
type IngressRejectionKind uint8

const (
	IngressInvalid IngressRejectionKind = iota + 1
	IngressDenied
)

type IngressRejection struct {
	RequestedOperation string
	Input              []byte
	Kind               IngressRejectionKind
}

// RejectBeforeDispatch records a proven invocation rejection in the normal
// pool. The requested name/category and bounded input exist only under the keyed
// input digest. No business service is invoked. The returned original deadline
// must cap the final response check and socket write; it is not evidence authority.
func (s *AuditedOperations) RejectBeforeDispatch(ctx context.Context, current identities.CurrentIdentity, in IngressRejection) (time.Time, error) {
	if in.Kind != IngressInvalid && in.Kind != IngressDenied {
		return time.Time{}, auditapp.ErrUnavailable
	}
	reply, err := s.call(ctx, current, in.RequestedOperation, in.Input, in.Kind)
	if !reply.ValidUntil.IsZero() && (in.Kind == IngressInvalid && errors.Is(err, contracts.ErrInvestigationWire) || in.Kind == IngressDenied && errors.Is(err, identity.ErrDenied)) {
		return reply.ValidUntil, nil
	}
	return time.Time{}, auditapp.ErrUnavailable
}

// Call serves one operation. A status read with after_revision whose state
// still has that revision waits for a committed change of its ID (LISTEN/
// NOTIFY through Changes) or audit.StatusWait, then reads again; each read
// is its own audited call (REQ-INT-003, no polling).
func (s *AuditedOperations) Call(ctx context.Context, current identities.CurrentIdentity, name string, raw json.RawMessage) (OperationReply, error) {
	id, after := statusWait(name, raw)
	if s == nil || s.config.Changes == nil || id == "" {
		return s.call(ctx, current, name, raw, 0)
	}
	// Each read keeps its operation's own window; only the wait is longer.
	read := func() (OperationReply, error) {
		return s.call(ctx, identities.ShortenRequest(current, s.config.Now().Add(audit.OperationRequestWindow(name)), s.config.Now), name, raw, 0)
	}
	// Subscribe before the first read so no change between them is lost.
	changes := s.config.Changes.Subscribe([]string{id})
	defer changes.Close()
	reply, err := read()
	if err != nil || replyRevision(reply.Body) != after {
		return reply, err
	}
	wait := time.NewTimer(audit.StatusWait)
	defer wait.Stop()
	select {
	case <-changes.Ready():
	case <-wait.C:
	case <-ctx.Done():
		return reply, err
	}
	if ctx.Err() != nil {
		return reply, err
	}
	_ = reply.Close(ctx)
	clear(reply.Body)
	return read()
}

// statusWait returns the ID and after_revision of a status read that asks to
// wait; "" otherwise.
func statusWait(name string, raw json.RawMessage) (string, int64) {
	var in struct {
		CaptureID     string `json:"capture_id"`
		GrantID       string `json:"grant_id"`
		DownloadID    string `json:"download_id"`
		Action        string `json:"action"`
		AfterRevision int64  `json:"after_revision"`
	}
	if json.Unmarshal(raw, &in) != nil || in.AfterRevision < 1 {
		return "", 0
	}
	id := ""
	switch {
	case name == "get_capture":
		id = in.CaptureID
	case name == "get_grant":
		id = in.GrantID
	case name == "download_artifact" && in.Action == "status":
		id = in.DownloadID
	}
	if !authorization.UUID(id) {
		return "", 0
	}
	return id, in.AfterRevision
}

// replyRevision is the data.revision of an ok or pending result, else 0.
func replyRevision(body []byte) int64 {
	var out struct {
		Status string `json:"status"`
		Data   struct {
			Revision int64 `json:"revision"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &out) != nil || out.Status == "error" {
		return 0
	}
	return out.Data.Revision
}

func (s *AuditedOperations) call(ctx context.Context, current identities.CurrentIdentity, name string, raw json.RawMessage, rejection IngressRejectionKind) (OperationReply, error) {
	// Transport inputs are bounded before authentication and audit.
	if s == nil || ctx == nil || current == nil || ctx.Err() != nil || len(raw) > 32<<10 || len(name) > 8192 {
		return OperationReply{}, auditapp.ErrUnavailable
	}
	timing := callTiming{start: time.Now()}
	var steps *auditapp.StepTimes
	if s.Timing != nil {
		ctx, steps = auditapp.WithStepTimes(ctx)
	}
	event := ""
	defer func() {
		if event != "" {
			timing.report(event, steps, s.Timing)
		}
	}()
	initial, err := current.ResolveIdentity(ctx)
	checkedAt := s.config.Now()
	now := checkedAt.UTC().Truncate(time.Microsecond)
	if err != nil || !initial.Valid(checkedAt) {
		return OperationReply{}, stopped("identity", identity.ErrDenied)
	}
	// A download stop runs without the evidence-read scope check below.
	if rejection == 0 && name == "cancel_artifact_download" {
		if _, ok := s.inner.Tool(name); ok && s.contracts.ValidateInput(name, raw) == nil {
			select {
			case s.stopSlots <- struct{}{}:
				defer func() { <-s.stopSlots }()
			default:
				return OperationReply{}, auditapp.ErrUnavailable
			}
			requestID := s.config.NewID()
			reply, callErr := s.inner.CallWithContext(ctx, current, OperationCall{requestID: requestID}, name, raw)
			// REQ-AUT-005: the stop writes its call row like every other
			// operation, before any output leaves; the effect row is separate.
			row := audit.Event{ID: s.config.NewID(), OperationID: requestID, Kind: "call", Operation: name, Actor: initial.Principal, Status: "success", Reason: "prepared", Effect: "accepted", OutputBytes: int64(len(reply.Body))}
			if callErr != nil {
				row.Status, row.Reason, row.Effect, row.OutputBytes = "unavailable", "authority_unavailable", "unknown", 0
			}
			auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			e := s.recorder.Record(auditCtx, row)
			cancel()
			if e != nil {
				clear(reply.Body)
				return OperationReply{}, stoppedAt("audit", e, auditapp.ErrUnavailable)
			}
			return reply, callErr
		}
	}
	actorDigest, err := s.mac.Principal(initial.Principal)
	if err != nil {
		return OperationReply{}, auditapp.ErrUnavailable
	}
	format := "context-input/v1"
	if queryOperation(name) {
		format = "context-query-input/v1"
	}
	var normalized []byte
	downloadScopeDenied := false
	if rejection == 0 {
		if len(name) > 128 || !utf8.ValidString(name) {
			rejection = IngressInvalid
		} else if normalized, err = s.normalize(name, raw); err != nil {
			rejection = IngressInvalid
		} else if name != processingDiscoveryOperation && name != processingErasureStatusOperation && name != processingReportOperation && !slices.Contains(initial.Scopes, "evidence:read") {
			rejection = IngressDenied
		} else if (name == "prepare_artifact_download" || name == "get_artifact_download") && !slices.Contains(initial.Scopes, "evidence:download") {
			rejection, downloadScopeDenied = IngressDenied, true
		}
	}
	op := name
	if rejection != 0 {
		clear(normalized)
		op, format = "invalid_operation", "invalid-input/v1"
		// Encoding the name as bytes avoids replacing invalid UTF-8 with U+FFFD,
		// which would collapse distinct rejected inputs into one keyed digest.
		normalized, _ = json.Marshal(struct {
			Name     []byte
			Category IngressRejectionKind
			Length   int
		}{[]byte(name), rejection, len(raw)})
		normalized = append(normalized, raw...)
	}
	defer clear(normalized)
	if len(normalized) > 64<<10 {
		return OperationReply{}, auditapp.ErrUnavailable
	}
	inputDigest, err := s.mac.Digest(format, normalized)
	clear(normalized)
	if err != nil {
		return OperationReply{}, auditapp.ErrUnavailable
	}
	until := identity.Earlier(initial.ValidUntil, now.Add(audit.OperationRequestWindow(op)))
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	until = until.UTC().Truncate(time.Microsecond)
	requestID := s.config.NewID()
	// The intent value is the invocation description the live owners bind;
	// it is not stored.
	intent := audit.OperationIntent{ID: requestID, TraceID: requestID, RootID: s.config.RootID, Name: op, InputFormat: format, MACVersion: s.mac.Version(), AccountVersion: s.mac.AccountVersion(), Actor: initial.Principal, PrincipalDigest: actorDigest, InputDigest: inputDigest, CreatedAt: now, RequestUntil: until, WriteUntil: now.Add(30 * time.Second), RetainUntil: now.Add(time.Hour)}
	if !intent.Valid() {
		return OperationReply{}, auditapp.ErrUnavailable
	}
	ctx, cancel := context.WithDeadline(ctx, until)
	transferred := false
	defer func() {
		if !transferred {
			cancel()
		}
	}()
	event = op
	var reply OperationReply
	clearReply := func() {
		if reply.owner != nil {
			cleanup, stop := context.WithDeadline(context.WithoutCancel(ctx), intent.WriteUntil)
			_ = reply.Close(cleanup)
			stop()
		} else {
			clear(reply.Body)
		}
	}
	var callErr error
	effectPossible := false
	if rejection == IngressInvalid {
		callErr = contracts.ErrInvestigationWire
	} else if rejection == IngressDenied {
		callErr = identity.ErrDenied
	} else {
		reply, callErr = s.inner.CallWithContext(ctx, current, OperationCall{requestID: requestID}, name, raw)
		timing.call = time.Now()
		reply.boundCleanup(intent.WriteUntil)
		// Only a proven pre-dispatch rejection rules out an effect.
		effectPossible = !reply.auditNoDispatch
	}
	out, e := s.result(intent, reply, callErr, effectPossible)
	if e != nil {
		clearReply()
		reply = OperationReply{}
		callErr = auditapp.ErrUnavailable
		out, e = s.result(intent, reply, callErr, effectPossible)
		if e != nil {
			return OperationReply{}, stopped("audit-result", auditapp.ErrUnavailable)
		}
	}
	if s.Timing != nil && (ctx.Err() != nil || !timing.call.IsZero() && (callErr != nil || out.Status != "success")) {
		failed := event + "/service-failed"
		if reply.failureStep != "" {
			failed += "/" + reply.failureStep
		}
		timing.report(failed, steps, s.Timing)
	}
	// The row is written before any output leaves; a failed row fails the call.
	auditCtx, finishCancel := context.WithDeadline(context.WithoutCancel(ctx), intent.WriteUntil)
	e = s.recorder.Record(auditCtx, callEvent(s.config.NewID(), out))
	timing.finish = time.Now()
	finishCancel()
	if e != nil {
		clearReply()
		return OperationReply{}, stoppedAt("audit", e, auditapp.ErrUnavailable)
	}
	if e = reply.acknowledge(ctx, out); e != nil {
		clearReply()
		return OperationReply{}, stopped("result-acknowledgement", auditapp.ErrUnavailable)
	}
	if callErr != nil {
		clearReply()
		bound := OperationReply{ValidUntil: until}
		if errors.Is(callErr, identity.ErrDenied) {
			// A missing download scope is an ordinary audited refusal for the
			// client, not a service outage (native61/62).
			if downloadScopeDenied {
				if body, ok := s.deniedReply(name, requestID); ok {
					bound.Body = body
					return bound, nil
				}
			}
			return bound, identity.ErrDenied
		}
		if errors.Is(callErr, contracts.ErrInvestigationWire) {
			return bound, contracts.ErrInvestigationWire
		}
		return bound, stoppedAt("service", callErr, auditapp.ErrUnavailable)
	}
	if !s.config.Now().Before(reply.ValidUntil) {
		clearReply()
		return OperationReply{}, stopped("reply-expired", auditapp.ErrUnavailable)
	}
	reply.ValidUntil = identity.Earlier(reply.ValidUntil, until)
	if e = reply.CheckDisclosure(ctx); e != nil {
		clearReply()
		return OperationReply{}, stopped("final-disclosure", auditapp.ErrUnavailable)
	}
	if reply.owner != nil {
		reply.transfer(cancel, func() {}, intent.WriteUntil)
		transferred = true
	}
	return reply, nil
}

// callEvent is the `call` row of one invocation.
func callEvent(eventID string, out audit.OperationOutcome) audit.Event {
	in := out.Intent
	digest, output := in.InputDigest, out.OutputDigest
	return audit.Event{ID: eventID, OperationID: in.ID, Kind: "call", Operation: in.Name, Actor: in.Actor, InputDigest: &digest,
		Status: out.Status, Reason: out.Reason, Effect: out.Effect, CaseIDs: out.CaseIDs, ArtifactIDs: out.ArtifactIDs, CaptureIDs: out.CaptureIDs,
		OutputBytes: out.OutputBytes, OutputDigest: &output}
}

func sameAuditIdentity(a, b identity.Identity, now time.Time) bool {
	return a.Valid(now) && b.Valid(now) && a.Principal == b.Principal && a.Policy == b.Policy && sameAuditSet(a.Groups, b.Groups) && sameAuditSet(a.Scopes, b.Scopes)
}
func sameAuditSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, v := range a {
		if !slices.Contains(b, v) {
			return false
		}
	}
	return true
}
func (s *AuditedOperations) normalize(name string, raw []byte) ([]byte, error) {
	if s.contracts.ValidateInput(name, raw) != nil {
		return nil, contracts.ErrInvestigationWire
	}
	if liveOperation(name) {
		return normalizeLiveInput(name, raw)
	}
	if queryOperation(name) {
		return normalizeQueryInput(name, raw)
	}
	if name == "prepare_artifact_download" || name == "get_artifact_download" {
		var in ContextDownloadInput
		if json.Unmarshal(raw, &in) != nil {
			return nil, contracts.ErrInvestigationWire
		}
		return json.Marshal(in)
	}
	if name == "activate_policy" || name == "get_policy_status" || name == "deactivate_policy" {
		var in PolicyOperationInput
		if json.Unmarshal(raw, &in) != nil {
			return nil, contracts.ErrInvestigationWire
		}
		return json.Marshal(in)
	}
	if name == "create_share" || name == "list_shares" || name == "revoke_share" || name == "transfer_share" || name == "stop_future_sharing" {
		var in ShareOperationInput
		if json.Unmarshal(raw, &in) != nil {
			return nil, contracts.ErrInvestigationWire
		}
		return json.Marshal(in)
	}
	if name == "explain_access" {
		var in AccessOperationInput
		if json.Unmarshal(raw, &in) != nil {
			return nil, contracts.ErrInvestigationWire
		}
		return json.Marshal(in)
	}
	if name == "preview_access_change" {
		var in AccessPreviewInput
		if json.Unmarshal(raw, &in) != nil {
			return nil, contracts.ErrInvestigationWire
		}
		return json.Marshal(in)
	}
	if name == "request_raw_access" || name == "request_policy_grant" || name == "get_grant" || name == "list_reviews" || name == "decide_review" || name == "revoke_grant" {
		var in GrantOperationInput
		if json.Unmarshal(raw, &in) != nil {
			return nil, contracts.ErrInvestigationWire
		}
		return json.Marshal(in)
	}
	if name == processingReportOperation {
		query, err := processingReportQuery(raw)
		if err != nil {
			return nil, err
		}
		return json.Marshal(query)
	}
	if name == processingErasureStatusOperation {
		var input processingErasureStatusInput
		if json.Unmarshal(raw, &input) != nil {
			return nil, contracts.ErrInvestigationWire
		}
		return json.Marshal(input)
	}
	if name == processingDiscoveryOperation {
		var in struct {
			privacy.ProcessingDiscoveryQuery
			Cluster string `json:"cluster,omitempty"`
		}
		if json.Unmarshal(raw, &in) != nil {
			return nil, contracts.ErrInvestigationWire
		}
		return json.Marshal(in)
	}
	if name == "preview_retention_change" {
		var in RetentionPreviewInput
		if json.Unmarshal(raw, &in) != nil {
			return nil, contracts.ErrInvestigationWire
		}
		return json.Marshal(in)
	}
	if name == "get_case" {
		var in struct {
			CaseID string `json:"case_id"`
		}
		if json.Unmarshal(raw, &in) != nil {
			return nil, contracts.ErrInvestigationWire
		}
		return json.Marshal(in)
	}
	if audit.OperationLane(name) == "" {
		return nil, contracts.ErrInvestigationWire
	}
	var in ContextOperationInput
	if json.Unmarshal(raw, &in) != nil {
		return nil, contracts.ErrInvestigationWire
	}
	return json.Marshal(in)
}
func (s *AuditedOperations) result(in audit.OperationIntent, reply OperationReply, callErr error, effectPossible bool) (audit.OperationOutcome, error) {
	out := audit.OperationOutcome{Intent: in, Status: "unavailable", Reason: "authority_unavailable", Effect: "none", ClientReceipt: "unknown", MetadataUntil: in.RequestUntil, RecordedAt: s.config.Now().UTC().Truncate(time.Microsecond)}
	if effectPossible && (in.Name == "cancel_capture" || in.Name == "request_capture" || in.Name == "prepare_artifact_download" || in.Name == "activate_policy" || in.Name == "deactivate_policy" || in.Name == "create_share" || in.Name == "revoke_share" || in.Name == "transfer_share" || in.Name == "stop_future_sharing" || in.Name == "decide_review" || in.Name == "revoke_grant" || in.Name == "request_policy_grant" || in.Name == "request_raw_access" || liveOperation(in.Name) && in.Name != "list_recordings" || queryOperation(in.Name)) {
		out.Effect = "unknown"
	}
	if queryOperation(in.Name) {
		switch reply.auditEffect {
		case operationEffectNone:
			out.Effect = "none"
		case operationEffectAccepted:
			out.Effect = "accepted"
		case operationEffectUnknown:
			out.Effect = "unknown"
		}
	}
	domain := "operation-error/v1"
	body := []byte("unavailable")
	if callErr != nil {
		if errors.Is(callErr, identity.ErrDenied) {
			out.Status = "denied"
			out.Reason = "not_available"
			body = []byte("denied")
		}
		if errors.Is(callErr, contracts.ErrInvestigationWire) {
			out.Status = "invalid"
			out.Reason = "invalid_input"
			body = []byte("invalid")
		}
	} else {
		if len(reply.Body) > reply.preparedOutputLimit(in.Name) || len(reply.Body) == 0 {
			return out, auditapp.ErrUnavailable
		}
		if queryOperation(in.Name) && s.contracts.ValidateOutput(in.Name, reply.Body) != nil {
			return out, auditapp.ErrUnavailable
		}
		var envelope struct {
			RequestID string          `json:"request_id"`
			Status    string          `json:"status"`
			Data      json.RawMessage `json:"data"`
		}
		if json.Unmarshal(reply.Body, &envelope) != nil || envelope.RequestID != in.ID {
			return out, auditapp.ErrUnavailable
		}
		if queryOperation(in.Name) && (envelope.Status == "ok" || envelope.Status == "pending") {
			if reply.owner == nil || reply.auditEffect == operationEffectUnspecified {
				return out, auditapp.ErrUnavailable
			}
			out.Status, out.Reason = "success", "prepared"
		}
		domain = "mcp-result/v1"
		body = reply.Body
		out.OutputBytes = int64(len(body))
		out.MetadataUntil = identity.Earlier(in.RequestUntil, reply.ValidUntil)
		if envelope.Status == "error" {
			switch reply.auditDecision {
			case operationAuditDenied:
				out.Status, out.Reason = "denied", "not_available"
			case operationAuditInvalid:
				out.Status, out.Reason = "invalid", "invalid_input"
			}
		}
		if envelope.Status == "ok" {
			if liveOperation(in.Name) && in.Name != "list_recordings" {
				out.Effect = "accepted"
			}
			out.Status = "success"
			out.Reason = "prepared"
			var refs struct {
				CancellationRequested bool               `json:"cancellation_requested"`
				CaptureID             string             `json:"capture_id"`
				ArtifactID            string             `json:"artifact_id"`
				Acceptance            string             `json:"acceptance_id"`
				GrantID               string             `json:"grant_id"`
				DownloadID            string             `json:"download_id"`
				CaseID                string             `json:"case_id"`
				State                 string             `json:"state"`
				Case                  ContextCaseSummary `json:"case"`
				Artifacts             []struct {
					ID string `json:"artifact_id"`
				} `json:"artifacts"`
				Candidates []struct {
					ArtifactID string `json:"artifact_id"`
					CaptureID  string `json:"capture_id"`
					CaseID     string `json:"case_id"`
				} `json:"candidates"`
			}
			if json.Unmarshal(envelope.Data, &refs) != nil {
				return out, auditapp.ErrUnavailable
			}
			if in.Name == "cancel_capture" {
				out.Effect = "none"
				if refs.CancellationRequested {
					out.Effect = "accepted"
				}
			}
			if refs.CaptureID != "" {
				out.CaptureIDs = []string{refs.CaptureID}
			}
			if refs.CaseID != "" {
				out.CaseIDs = []string{refs.CaseID}
			} else if refs.Case.CaseID != "" {
				out.CaseIDs = []string{refs.Case.CaseID}
			}
			if refs.ArtifactID != "" {
				out.ArtifactIDs = append(out.ArtifactIDs, refs.ArtifactID)
			}
			if (in.Name == "activate_policy" || in.Name == "deactivate_policy") && refs.Acceptance != "" {
				out.Effect = "accepted"
			}
			if (in.Name == "request_raw_access" || in.Name == "request_policy_grant" || in.Name == "decide_review" || in.Name == "revoke_grant") && refs.GrantID != "" {
				// An acknowledged decision/revocation, including exact idempotent replay,
				// is an accepted logical mutation. Service uncertainty remains unknown.
				out.Effect = "accepted"
			}
			if in.Name == "prepare_artifact_download" && refs.DownloadID != "" {
				out.Effect = "accepted"
			}
			if in.Name == "create_share" || in.Name == "revoke_share" || in.Name == "transfer_share" || in.Name == "stop_future_sharing" {
				// ADR-232: the acknowledged share or revocation is the effect;
				// ADR-239: so is a policy sharing's Stop or revoke-all.
				var share struct {
					ShareID         string `json:"share_id"`
					SharingIntentID string `json:"sharing_intent_id"`
				}
				if json.Unmarshal(envelope.Data, &share) == nil && (share.ShareID != "" || share.SharingIntentID != "") {
					out.Effect = "accepted"
				}
			}
			for _, a := range refs.Artifacts {
				out.ArtifactIDs = append(out.ArtifactIDs, a.ID)
			}
			if in.Name == processingDiscoveryOperation {
				for _, candidate := range refs.Candidates {
					out.ArtifactIDs = append(out.ArtifactIDs, candidate.ArtifactID)
					if !slices.Contains(out.CaseIDs, candidate.CaseID) {
						out.CaseIDs = append(out.CaseIDs, candidate.CaseID)
					}
					if !slices.Contains(out.CaptureIDs, candidate.CaptureID) {
						out.CaptureIDs = append(out.CaptureIDs, candidate.CaptureID)
					}
				}
			}
			if queryOperation(in.Name) && in.Name != "get_query_result" {
				// ADR-282: a disclosed page names its source artifacts as provenance.
				var page struct {
					Provenance []struct {
						ArtifactID string `json:"artifactID"`
					} `json:"provenance"`
				}
				if json.Unmarshal(reply.Body, &page) != nil {
					return out, auditapp.ErrUnavailable
				}
				for _, p := range page.Provenance {
					out.ArtifactIDs = append(out.ArtifactIDs, p.ArtifactID)
				}
			}
			if in.Name == "request_capture" && refs.CaptureID != "" {
				out.Effect = "accepted"
			}
		}
	}
	var d artifact.Digest
	var err error
	if callErr == nil && reply.resultBound && !reply.browserSettings {
		d, err = s.mac.ResultBoundDigest(body)
	} else if callErr == nil && in.Name == "get_capture" && reply.browserSettings {
		d, err = s.mac.BrowserSettingsResultDigest(body)
	} else {
		d, err = s.mac.Digest(domain, body)
	}
	out.OutputDigest = d
	if err != nil || !out.Valid() {
		return out, auditapp.ErrUnavailable
	}
	return out, nil
}

// callStop names where an audited call stopped without a reply, for the
// transport's closed 503 report. It wraps the returned sentinel unchanged and
// appends the cause's own closed step, when it has one.
type callStop struct {
	step  string
	err   error
	cause error
}

func (e *callStop) Error() string { return e.err.Error() }
func (e *callStop) Unwrap() error { return e.err }
func (e *callStop) FixedStep() string {
	var nested interface{ FixedStep() string }
	if e.cause != nil && errors.As(e.cause, &nested) {
		return e.step + "/" + nested.FixedStep()
	}
	return e.step
}

func stopped(step string, err error) error { return &callStop{step: step, err: err} }
func stoppedAt(step string, cause, err error) error {
	return &callStop{step: step, err: err, cause: cause}
}

// deniedReply is the tool's ordinary NotAvailable envelope for a scope
// rejection; false when the tool's output contract cannot carry it.
func (s *AuditedOperations) deniedReply(name, requestID string) ([]byte, bool) {
	body, err := json.Marshal(OperationEnvelope{SchemaVersion: "mcp-result/v1", RequestID: requestID, DataClass: "metadata", Status: "error", Warnings: []string{}, Provenance: []any{}, Data: OperationFailure{Code: "NotAvailable", Message: "This operation is not available with your current access.", Retryable: false}})
	if err != nil || s.contracts.ValidateOutput(name, body) != nil {
		return nil, false
	}
	return body, true
}
