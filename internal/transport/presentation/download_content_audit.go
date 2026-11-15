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
	"asservat.local/asservat/internal/domain/artifact"
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

// NewNativeContentAuditor writes the content GET's audit row through the
// recorder shared with browser and MCP calls.
func NewNativeContentAuditor(shared *AuditedOperations, input NativeContentInput, until time.Time) (*NativeContentAuditor, error) {
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
	if !now.Before(until) {
		return nil, auditapp.ErrUnavailable
	}
	return &nativeContentAudit{owner: owner, id: owner.config.NewID(), actor: initial.Principal, input: input, until: until}, nil
}

type nativeContentAudit struct {
	mu       sync.Mutex
	owner    *AuditedOperations
	id       string
	actor    identity.Principal
	input    artifact.Digest
	until    time.Time
	finished bool
}

func (s *nativeContentAudit) Deadline() time.Time { return s.until }

// Finish writes the GET's one audit row before any content leaves.
func (s *nativeContentAudit) Finish(ctx context.Context, status evidence.DownloadContentStatus) (time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.finished || ctx == nil || ctx.Err() != nil || !status.Valid() || !s.owner.config.Now().Before(s.until) {
		return time.Time{}, auditapp.ErrUnavailable
	}
	s.finished = true
	digest, err := s.owner.mac.Digest("native-content-result/v1", []byte(status))
	if err != nil {
		return time.Time{}, err
	}
	e := audit.Event{ID: s.owner.config.NewID(), OperationID: s.id, Kind: "call", Operation: "download_artifact_content", Actor: s.actor, InputDigest: &s.input, Status: "success", Reason: "prepared", OutputDigest: &digest}
	switch status {
	case evidence.DownloadContentInvalid:
		e.Status, e.Reason = "invalid", "invalid_input"
	case evidence.DownloadContentDenied:
		e.Status, e.Reason = "denied", "not_available"
	case evidence.DownloadContentUnavailable:
		e.Status, e.Reason = "unavailable", "authority_unavailable"
	}
	call, end := context.WithDeadline(ctx, s.until)
	defer end()
	if err = s.owner.recorder.Record(call, e); err != nil || call.Err() != nil {
		return time.Time{}, auditapp.ErrUnavailable
	}
	return s.until, nil
}
func (s *nativeContentAudit) Close() {}

var _ evidence.DownloadContentAuditor = (*NativeContentAuditor)(nil)
