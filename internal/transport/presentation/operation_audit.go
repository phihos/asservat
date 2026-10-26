package presentation

import (
	auditapp "asservat.local/asservat/internal/application/audit"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"time"
	"unicode/utf8"
)

// These arguments are private accepted installation composition. This wrapper
// is not wired by bootstrap: protected keys, finite cleanup and capacity
// provisioning are still required before enablement.
type AuditedOperationsConfig struct {
	RootID                                                            string
	Retention                                                         time.Duration
	NormalConcurrency, ResolutionConcurrency, PerPrincipalConcurrency int
	NormalPerSecond, ResolutionPerSecond                              int
	Now                                                               func() time.Time
	NewID                                                             func() string
}
type auditRate struct {
	started time.Time
	used    int
}
type auditTarget interface {
	Operations
	CallWithContext(context.Context, identities.CurrentIdentity, OperationCall, string, json.RawMessage) (OperationReply, error)
}
type auditGate interface {
	Begin(context.Context, audit.OperationIntent) error
	Finish(context.Context, audit.OperationOutcome) error
}
type AuditedOperations struct {
	config    AuditedOperationsConfig
	inner     auditTarget
	audit     map[string]auditGate
	mac       *auditapp.OperationMAC
	contracts *contracts.InvestigationContracts
	lanes     map[string]chan struct{}
	stopSlots chan struct{}
	mu        sync.Mutex
	active    map[string]int
	rate      map[string]auditRate
	// Timing receives a fixed operation lane separately from stage durations.
	// No input, identity or result enters either argument.
	Timing func(event, timing string)
}

// callTiming marks stage ends of one audited call for Timing.
type callTiming struct {
	start, admitted, begin, call, finish time.Time
}

func (t callTiming) report(lane string, steps *auditapp.StepTimes, out func(string, string)) {
	if out == nil {
		return
	}
	line := "pre" + durationBucket(t.admitted, t.start) + " begin" + durationBucket(t.begin, t.admitted)
	if !t.call.IsZero() {
		line += " call" + durationBucket(t.call, t.begin)
	}
	if !t.finish.IsZero() {
		line += " finish" + durationBucket(t.finish, t.call)
	}
	line += " total" + durationBucket(time.Now(), t.start)
	if s := steps.String(); s != "" {
		line += " [" + s + "]"
	}
	out(lane, line)
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

func NewAuditedOperations(c AuditedOperationsConfig, inner *InvestigationOperations, normal, resolution auditapp.OperationAuditor, mac *auditapp.OperationMAC) (*AuditedOperations, error) {
	if normal.Journal == nil || normal.Acknowledgements == nil || normal.Objects == nil || normal.Now == nil || resolution.Journal == nil || resolution.Acknowledgements == nil || resolution.Objects == nil || resolution.Now == nil {
		return nil, ErrOperationsConfiguration
	}
	return newAuditedOperations(c, inner, normal, resolution, mac)
}

// NewHealthyAuditedOperations selects the positive-writer lifecycle for both
// independently backed lanes. Accepted policy/credentials still come from
// protected installation composition; this constructor enables no runtime.
// HealthyAuditGate is a configured healthy lane auditor: a fixed-policy
// auditor or the ADR-190 selecting auditor.
type HealthyAuditGate interface {
	auditGate
	Configured() bool
}

func NewHealthyAuditedOperations(c AuditedOperationsConfig, inner *InvestigationOperations, normal, resolution HealthyAuditGate, mac *auditapp.OperationMAC) (*AuditedOperations, error) {
	if !normal.Configured() || !resolution.Configured() {
		return nil, ErrOperationsConfiguration
	}
	return newAuditedOperations(c, inner, normal, resolution, mac)
}

func newAuditedOperations(c AuditedOperationsConfig, inner *InvestigationOperations, normal, resolution auditGate, mac *auditapp.OperationMAC) (*AuditedOperations, error) {
	if !authorization.UUID(c.RootID) || c.Retention < time.Minute || c.Retention > 3660*24*time.Hour || c.NormalConcurrency < 1 || c.NormalConcurrency > 64 || c.ResolutionConcurrency < 1 || c.ResolutionConcurrency > 16 || c.PerPrincipalConcurrency < 1 || c.PerPrincipalConcurrency > 16 || c.NormalPerSecond < 1 || c.NormalPerSecond > 10000 || c.ResolutionPerSecond < 1 || c.ResolutionPerSecond > 1000 || c.Now == nil || c.NewID == nil || inner == nil || mac == nil || normal == nil || resolution == nil {
		return nil, ErrOperationsConfiguration
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		return nil, err
	}
	return &AuditedOperations{config: c, inner: inner, audit: map[string]auditGate{"normal": normal, "resolution": resolution}, mac: mac, contracts: wire, stopSlots: make(chan struct{}, 4), lanes: map[string]chan struct{}{"normal": make(chan struct{}, c.NormalConcurrency), "resolution": make(chan struct{}, c.ResolutionConcurrency)}, active: map[string]int{}, rate: map[string]auditRate{}}, nil
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

// Each lane owns independent finite provider slots. Account maps exist only for
// admitted in-flight requests and therefore cannot grow beyond total slots.
func (s *AuditedOperations) acquire(lane string, principal artifact.Digest) (func(), bool) {
	slots := s.lanes[lane]
	select {
	case slots <- struct{}{}:
	default:
		return nil, false
	}
	key := lane + string(principal[:])
	s.mu.Lock()
	now := s.config.Now()
	r := s.rate[lane]
	limit := s.config.NormalPerSecond
	if lane == "resolution" {
		limit = s.config.ResolutionPerSecond
	}
	if r.started.IsZero() || !now.Before(r.started.Add(time.Second)) {
		r = auditRate{started: now}
	}
	if r.used >= limit || s.active[key] >= s.config.PerPrincipalConcurrency {
		s.mu.Unlock()
		<-slots
		return nil, false
	}
	r.used++
	s.rate[lane] = r
	s.active[key]++
	s.mu.Unlock()
	return func() {
		s.mu.Lock()
		s.active[key]--
		if s.active[key] == 0 {
			delete(s.active, key)
		}
		s.mu.Unlock()
		<-slots
	}, true
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

func (s *AuditedOperations) Call(ctx context.Context, current identities.CurrentIdentity, name string, raw json.RawMessage) (OperationReply, error) {
	return s.call(ctx, current, name, raw, 0)
}

func (s *AuditedOperations) call(ctx context.Context, current identities.CurrentIdentity, name string, raw json.RawMessage, rejection IngressRejectionKind) (OperationReply, error) {
	// Transport inputs are bounded before authentication/audit admission. Leave
	// room for the fixed MAC framing; never allocate from an unbounded name.
	if s == nil || ctx == nil || current == nil || ctx.Err() != nil || len(raw) > 32<<10 || len(name) > 8192 {
		return OperationReply{}, auditapp.ErrUnavailable
	}
	timing := callTiming{start: time.Now()}
	lane := ""
	var steps *auditapp.StepTimes
	if s.Timing != nil {
		ctx, steps = auditapp.WithStepTimes(ctx)
	}
	event := ""
	defer func() {
		if lane != "" {
			timing.report(event, steps, s.Timing)
		}
	}()
	initial, err := current.ResolveIdentity(ctx)
	checkedAt := s.config.Now()
	now := checkedAt.UTC().Truncate(time.Microsecond)
	// SQL precision only changes persisted boundaries. Flooring the live check
	// can put an otherwise current nanosecond observation in its "future".
	if err != nil || !initial.Valid(checkedAt) {
		return OperationReply{}, stopped("identity", identity.ErrDenied)
	}
	// Prepaid safe stop is its own immutable cancellation obligation. It has
	// no normal/resolution audit admission dependency and no evidence-read gate.
	// Invalid input remains the normal bounded rejection path below.
	if rejection == 0 && name == "cancel_artifact_download" {
		if _, ok := s.inner.Tool(name); ok && s.contracts.ValidateInput(name, raw) == nil {
			select {
			case s.stopSlots <- struct{}{}:
				defer func() { <-s.stopSlots }()
			default:
				return OperationReply{}, auditapp.ErrUnavailable
			}
			return s.inner.CallWithContext(ctx, current, OperationCall{requestID: s.config.NewID()}, name, raw)
		}
	}
	actorDigest, err := s.mac.Principal(initial.Principal)
	if err != nil {
		return OperationReply{}, auditapp.ErrUnavailable
	}
	// Determine rejection BEFORE choosing a lane. Invalid schemas and missing
	// read scope must not spend the protected resolution allowance.
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
		} else if !slices.Contains(initial.Scopes, "evidence:read") {
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
	if len(normalized) > 64<<10 || audit.OperationLane(op) == "" {
		return OperationReply{}, auditapp.ErrUnavailable
	}
	release, ok := s.acquire(audit.OperationLane(op), actorDigest)
	if !ok {
		return OperationReply{}, stopped("busy", auditapp.ErrUnavailable)
	}
	transferred := false
	defer func() {
		if !transferred {
			release()
		}
	}()
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
	intent := audit.OperationIntent{ID: requestID, TraceID: requestID, RootID: s.config.RootID, Name: op, InputFormat: format, MACVersion: s.mac.Version(), AccountVersion: s.mac.AccountVersion(), Actor: initial.Principal, PrincipalDigest: actorDigest, InputDigest: inputDigest, CreatedAt: now, RequestUntil: until, WriteUntil: now.Add(30 * time.Second), RetainUntil: now.Add(s.config.Retention).UTC().Truncate(time.Microsecond)}
	if !intent.Valid() {
		return OperationReply{}, auditapp.ErrUnavailable
	}
	ctx, cancel := context.WithDeadline(ctx, until)
	defer func() {
		if !transferred {
			cancel()
		}
	}()
	lane, timing.admitted = audit.OperationLane(op), time.Now()
	// Evidence reads get their own timing sequence, so a few reads among many
	// other normal-lane calls still reach the doubling report.
	event = lane
	if audit.OperationRequestWindow(op) > 5*time.Second {
		event = op
	}
	e := s.audit[lane].Begin(ctx, intent)
	timing.begin = time.Now()
	if e != nil {
		return OperationReply{}, stoppedAt("audit-begin", e, auditapp.ErrUnavailable)
	}
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
		// Recheck after blocking audit before any service work.
		fresh, e := current.ResolveIdentity(ctx)
		if e != nil || !sameAuditIdentity(initial, fresh, s.config.Now()) || ctx.Err() != nil {
			callErr = identity.ErrDenied
		} else {
			call := OperationCall{requestID: requestID}
			if queryOperation(name) {
				// The private owner exists only after this invocation's existing
				// Begin acknowledgement. Neither a DTO nor a public context value
				// can manufacture it; SQL still checks the acknowledged row.
				call.queryInvocation = newContextQueryInvocation(ctx, intent, s.mac, s.config.Now)
			}
			reply, callErr = s.inner.CallWithContext(ctx, current, call, name, raw)
			timing.call = time.Now()
			reply.boundCleanup(intent.WriteUntil)
			// Only a private, proven pre-dispatch rejection can rule out an
			// effect from this invocation. A service error or response timeout
			// cannot establish the original logical request's disposition.
			effectPossible = !reply.auditNoDispatch
		}
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
	// Once an outcome exists, completing its audit is allowed without reviving
	// request authority. This bounded synchronous completion never redispatches.
	auditCtx, finishCancel := context.WithDeadline(context.WithoutCancel(ctx), intent.WriteUntil)
	e = s.audit[audit.OperationLane(op)].Finish(auditCtx, out)
	timing.finish = time.Now()
	finishCancel()
	if e != nil {
		clearReply()
		return OperationReply{}, stoppedAt("audit-finish", e, auditapp.ErrUnavailable)
	}
	if e = reply.acknowledge(ctx, out); e != nil {
		clearReply()
		return OperationReply{}, stopped("result-acknowledgement", auditapp.ErrUnavailable)
	}
	final, e := current.ResolveIdentity(ctx)
	if e != nil || ctx.Err() != nil || !sameAuditIdentity(initial, final, s.config.Now()) || !s.config.Now().Before(until) {
		clearReply()
		if ctx.Err() != nil || !s.config.Now().Before(until) {
			return OperationReply{}, stopped("request-expired", identity.ErrDenied)
		}
		return OperationReply{}, stopped("final-identity", identity.ErrDenied)
	}
	if callErr != nil {
		// Acknowledged errors carry only the original delivery bound, no body or
		// evidence grant. Strict transports must preserve it through the write.
		clearReply()
		bound := OperationReply{ValidUntil: identity.Earlier(until, final.ValidUntil)}
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
		// The service's own closed stage, if any, names this refusal in the
		// transport report; the returned class is unchanged.
		return bound, stoppedAt("service", callErr, auditapp.ErrUnavailable)
	}
	if !s.config.Now().Before(reply.ValidUntil) {
		clearReply()
		return OperationReply{}, stopped("reply-expired", auditapp.ErrUnavailable)
	}
	reply.ValidUntil = identity.Earlier(reply.ValidUntil, identity.Earlier(until, final.ValidUntil))
	if e = reply.CheckDisclosure(ctx); e != nil {
		clearReply()
		return OperationReply{}, stopped("final-disclosure", auditapp.ErrUnavailable)
	}
	if reply.owner != nil {
		reply.transfer(cancel, release, intent.WriteUntil)
		transferred = true
	}
	return reply, nil
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
	if effectPossible && (in.Name == "request_capture" || in.Name == "resolve_capture_request" || in.Name == "prepare_artifact_download" || in.Name == "activate_policy" || in.Name == "deactivate_policy" || queryOperation(in.Name)) {
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
		if len(reply.Body) > audit.OperationOutputLimit || len(reply.Body) == 0 {
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
			out.Status = "success"
			out.Reason = "prepared"
			var refs struct {
				CaptureID  string             `json:"capture_id"`
				ArtifactID string             `json:"artifact_id"`
				Acceptance string             `json:"acceptance_id"`
				DownloadID string             `json:"download_id"`
				CaseID     string             `json:"case_id"`
				State      string             `json:"state"`
				Case       ContextCaseSummary `json:"case"`
				Artifacts  []struct {
					ID string `json:"artifact_id"`
				} `json:"artifacts"`
			}
			if json.Unmarshal(envelope.Data, &refs) != nil {
				return out, auditapp.ErrUnavailable
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
			if in.Name == "prepare_artifact_download" && refs.DownloadID != "" {
				out.Effect = "accepted"
			}
			for _, a := range refs.Artifacts {
				out.ArtifactIDs = append(out.ArtifactIDs, a.ID)
			}
			if in.Name == "request_capture" || in.Name == "resolve_capture_request" {
				if refs.CaptureID != "" {
					out.Effect = "accepted"
				} else if refs.State == "closed" {
					out.Effect = "none"
				}
			}
		}
	}
	d, err := s.mac.Digest(domain, body)
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
