package analysis

import (
	identities "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
)

type rawLogApprovalRefusal struct{ cause error }

func (e *rawLogApprovalRefusal) Error() string { return "raw logs approval required" }
func (e *rawLogApprovalRefusal) Unwrap() error { return e.cause }
func RawLogQueryApprovalRequiredBeforeAdmission(err error) bool {
	var e *rawLogApprovalRefusal
	return errors.As(err, &e)
}

type LogProjectionRouteReader interface {
	ResolveLogProjectionRoute(context.Context, string, string, identity.Identity, artifact.RecoveryProof) (value.ContextProjectionCandidate, error)
}

type RawLogReads struct {
	Service ContextProjectionService
	Routes  LogProjectionRouteReader
}

func (s ContextProjectionService) RawLogQueries() (RawLogReads, bool) {
	return RawLogReads{s, s.LogRoutes}, s.LogRoutes != nil
}
func RawLogQueryRequestDigest(r value.RawLogQueryRequest) artifact.Digest {
	b, e := json.Marshal(struct {
		Version string
		Request value.RawLogQueryRequest
	}{"logs-query-request/v1", r})
	if e != nil {
		return artifact.Digest{}
	}
	return sha256.Sum256(b)
}
func (s RawLogReads) Begin(ctx context.Context, current identities.CurrentIdentity, invocation ContextQueryInvocation, r value.RawLogQueryRequest) (*ContextProjectionDelivery, error) {
	if !r.Valid() || s.Routes == nil {
		return nil, value.ErrInvalid
	}
	return s.Service.begin(ctx, current, invocation, "get_logs", ContextQueryInput{RawLogs: r}, func(ctx context.Context, i identity.Identity, recovery artifact.RecoveryProof) (value.ContextProjectionCandidate, error) {
		c, e := s.Routes.ResolveLogProjectionRoute(ctx, r.CaseID, r.ArtifactID, i, recovery)
		if e != nil {
			return c, e
		}
		if c.NativeType != artifact.LogsArtifact || c.CaseID != r.CaseID || c.ArtifactID != r.ArtifactID || c.Logs != (value.LogWindow{}) {
			return value.ContextProjectionCandidate{}, value.ErrUnavailable
		}
		c.Logs, c.RawGrantID = r.Selection, r.GrantID
		if !c.Valid() {
			return value.ContextProjectionCandidate{}, value.ErrInvalid
		}
		return c, nil
	})
}
func (d *ContextProjectionDelivery) Logs() (value.LogPage, bool) {
	if d == nil || d.owner == nil {
		return value.LogPage{}, false
	}
	d.owner.mu.Lock()
	defer d.owner.mu.Unlock()
	if d.owner.closed || d.logs == nil || d.refusal != ContextProjectionNoRefusal {
		return value.LogPage{}, false
	}
	return value.CloneLogPage(*d.logs), true
}

func boundedRawLogResult(p value.LogPage, scope value.ContextProjectionScope) bool {
	if !p.ValidShape(scope.Logs.Selection(scope.CaseID, scope.ArtifactID), scope.Version, scope.PodUID) {
		return false
	}
	b, e := json.Marshal(p)
	return e == nil && len(b) <= value.LogQueryPageBytes
}

func (d *ContextProjectionDelivery) LogSelection() value.LogSelection {
	if d == nil || d.owner == nil {
		return value.LogSelection{}
	}
	d.owner.mu.Lock()
	defer d.owner.mu.Unlock()
	if d.owner.closed {
		return value.LogSelection{}
	}
	s := d.owner.query.Scope
	return s.Logs.Selection(s.CaseID, s.ArtifactID)
}
