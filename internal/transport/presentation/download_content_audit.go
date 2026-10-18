package presentation

import (
	"context"
	"encoding/json"
	"slices"
	"sync"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/application/evidence"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// NativeContentInput is a bounded normalized request, held only until its keyed
// audit digest is computed. Credentials and native representation facts do not
// belong here. It is not a public tool and does not enter tool discovery.
type NativeContentInput struct {
	DownloadID                           string
	IfMatch, IfNoneMatch, IfRange, Range []string
}

func (i NativeContentInput) valid() bool {
	if !authorization.UUID(i.DownloadID) {
		return false
	}
	total := 0
	for _, values := range [][]string{i.IfMatch, i.IfNoneMatch, i.IfRange, i.Range} {
		if len(values) > 16 {
			return false
		}
		for _, v := range values {
			if len(v) > 8192 {
				return false
			}
			total += len(v)
		}
	}
	return total <= 24<<10
}

type NativeContentAuditor struct {
	shared *AuditedOperations
	input  NativeContentInput
	until  time.Time
}

// NewNativeContentAuditor requires the exact healthy audit owner shared with
// browser/MCP calls. It spends that owner's normal slots/rate/account limits;
// there is no independent unbacked HTTP lane or long-running audit writer.
func NewNativeContentAuditor(shared *AuditedOperations, input NativeContentInput, until time.Time) (*NativeContentAuditor, error) {
	if shared == nil {
		return nil, auditapp.ErrUnavailable
	}
	// The normal lane must be certificate-verification backed: one healthy
	// auditor, or the installed per-profile selection (ADR-190), which builds
	// only configured healthy auditors.
	switch lane := shared.audit["normal"].(type) {
	case *auditapp.HealthyOperationAuditor:
		if !lane.Configured() {
			return nil, auditapp.ErrUnavailable
		}
	case *auditapp.SelectedOperationAuditor:
		if !lane.Configured() {
			return nil, auditapp.ErrUnavailable
		}
	default:
		return nil, auditapp.ErrUnavailable
	}
	return newNativeContentAuditor(shared, input, until)
}
func newNativeContentAuditor(shared *AuditedOperations, input NativeContentInput, until time.Time) (*NativeContentAuditor, error) {
	if shared == nil || shared.mac == nil || shared.config.Now == nil || !input.valid() || !shared.config.Now().Before(until) || until.After(shared.config.Now().Add(5*time.Second)) {
		return nil, auditapp.ErrUnavailable
	}
	input.IfMatch = slices.Clone(input.IfMatch)
	input.IfNoneMatch = slices.Clone(input.IfNoneMatch)
	input.IfRange = slices.Clone(input.IfRange)
	input.Range = slices.Clone(input.Range)
	return &NativeContentAuditor{shared: shared, input: input, until: until}, nil
}
func (s *NativeContentAuditor) BeginDownloadContent(ctx context.Context, current identities.CurrentIdentity, request evidence.DownloadResponseRequest) (evidence.DownloadContentAudit, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || current == nil || request.SessionID != s.input.DownloadID {
		return nil, auditapp.ErrUnavailable
	}
	owner := s.shared
	initial, err := current.ResolveIdentity(ctx)
	now := owner.config.Now()
	if err != nil || !initial.Valid(now) {
		return nil, identity.ErrDenied
	}
	initial.Groups = slices.Clone(initial.Groups)
	initial.Scopes = slices.Clone(initial.Scopes)
	principal, err := owner.mac.Principal(initial.Principal)
	if err != nil {
		return nil, err
	}
	release, ok := owner.acquire("normal", principal)
	if !ok {
		return nil, auditapp.ErrUnavailable
	}
	failed := true
	defer func() {
		if failed {
			release()
		}
	}()
	normalized, err := json.Marshal(s.input)
	if err != nil {
		return nil, auditapp.ErrUnavailable
	}
	defer clear(normalized)
	input, err := owner.mac.Digest("native-content-input/v1", normalized)
	if err != nil {
		return nil, err
	}
	until := identity.Earlier(s.until, identity.Earlier(initial.ValidUntil, request.HardUntil))
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	until = until.UTC().Truncate(time.Microsecond)
	id := owner.config.NewID()
	in := audit.OperationIntent{ID: id, TraceID: id, RootID: owner.config.RootID, Name: "download_artifact_content", InputFormat: "native-content-input/v1", MACVersion: owner.mac.Version(), AccountVersion: owner.mac.AccountVersion(), Actor: initial.Principal, PrincipalDigest: principal, InputDigest: input, CreatedAt: now.UTC().Truncate(time.Microsecond), RequestUntil: until, WriteUntil: until, RetainUntil: now.Add(owner.config.Retention).UTC().Truncate(time.Microsecond)}
	if !in.Valid() || !now.Before(until) {
		return nil, auditapp.ErrUnavailable
	}
	call, end := context.WithDeadline(ctx, until)
	defer end()
	if err = owner.audit["normal"].Begin(call, in); err != nil {
		return nil, auditapp.ErrUnavailable
	}
	if call.Err() != nil || !owner.config.Now().Before(until) {
		return nil, auditapp.ErrUnavailable
	}
	// The transfer performs a fresh check after this positive intent and again
	// after Finish; the handle never fabricates a fresh identity observation.
	failed = false
	return &nativeContentAudit{owner: owner, intent: in, release: release}, nil
}

type nativeContentAudit struct {
	mu               sync.Mutex
	owner            *AuditedOperations
	intent           audit.OperationIntent
	release          func()
	finished, closed bool
}

func (s *nativeContentAudit) Deadline() time.Time { return s.intent.RequestUntil }
func (s *nativeContentAudit) Finish(ctx context.Context, status evidence.DownloadContentStatus) (time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.finished || ctx == nil || ctx.Err() != nil || !status.Valid() || !s.owner.config.Now().Before(s.intent.WriteUntil) {
		return time.Time{}, auditapp.ErrUnavailable
	}
	s.finished = true // An uncertain provider result can never authorize another PUT.
	digest, err := s.owner.mac.Digest("native-content-result/v1", []byte(status))
	if err != nil {
		return time.Time{}, err
	}
	out := audit.OperationOutcome{Intent: s.intent, Status: "success", Reason: "prepared", Effect: "none", ClientReceipt: "unknown", OutputDigest: digest, OutputBytes: 0, MetadataUntil: s.intent.RequestUntil, RecordedAt: s.owner.config.Now().UTC().Truncate(time.Microsecond)}
	switch status {
	case evidence.DownloadContentInvalid:
		out.Status = "invalid"
		out.Reason = "invalid_input"
	case evidence.DownloadContentDenied:
		out.Status = "denied"
		out.Reason = "not_available"
	case evidence.DownloadContentUnavailable:
		out.Status = "unavailable"
		out.Reason = "authority_unavailable"
	}
	if !out.Valid() {
		return time.Time{}, auditapp.ErrUnavailable
	}
	call, end := context.WithDeadline(ctx, s.intent.WriteUntil)
	defer end()
	if err = s.owner.audit["normal"].Finish(call, out); err != nil || call.Err() != nil || !s.owner.config.Now().Before(s.intent.WriteUntil) {
		return time.Time{}, auditapp.ErrUnavailable
	}
	return s.intent.RequestUntil, nil
}
func (s *nativeContentAudit) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		s.release()
	}
}

var _ evidence.DownloadContentAuditor = (*NativeContentAuditor)(nil)
