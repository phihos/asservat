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

type rawSyscallApprovalRefusal struct{ cause error }

func (e *rawSyscallApprovalRefusal) Error() string { return "raw syscall approval required" }
func (e *rawSyscallApprovalRefusal) Unwrap() error { return e.cause }
func RawSyscallQueryApprovalRequiredBeforeAdmission(err error) bool {
	var e *rawSyscallApprovalRefusal
	return errors.As(err, &e)
}

type RawSyscallReads struct {
	Service ContextProjectionService
	Routes  SyscallProjectionRouteReader
}

func (s ContextProjectionService) RawSyscallQueries() (RawSyscallReads, bool) {
	return RawSyscallReads{s, s.SyscallRoutes}, s.SyscallRoutes != nil
}
func RawSyscallQueryRequestDigest(r value.RawSyscallQueryRequest) artifact.Digest {
	b, e := json.Marshal(struct {
		Version string
		Request value.RawSyscallQueryRequest
	}{"syscall-query-request/v1", r})
	if e != nil {
		return artifact.Digest{}
	}
	return sha256.Sum256(b)
}
func (s RawSyscallReads) Begin(ctx context.Context, current identities.CurrentIdentity, invocation ContextQueryInvocation, r value.RawSyscallQueryRequest) (*ContextProjectionDelivery, error) {
	if !r.Valid() || s.Routes == nil {
		return nil, value.ErrInvalid
	}
	return s.Service.begin(ctx, current, invocation, "syscall_query", ContextQueryInput{RawSyscalls: r}, func(ctx context.Context, i identity.Identity, recovery artifact.RecoveryProof) (value.ContextProjectionCandidate, error) {
		c, e := s.Routes.ResolveSyscallProjectionRoute(ctx, r.CaseID, r.ArtifactID, i, recovery)
		if e != nil {
			return c, e
		}
		if c.NativeType != artifact.SyscallArgumentsArtifact || c.CaseID != r.CaseID || c.ArtifactID != r.ArtifactID || c.Syscalls != (value.SyscallWindow{}) {
			return value.ContextProjectionCandidate{}, value.ErrUnavailable
		}
		c.Syscalls, c.RawGrantID = r.Selection, r.GrantID
		if !c.Valid() {
			return value.ContextProjectionCandidate{}, value.ErrInvalid
		}
		return c, nil
	})
}
func (d *ContextProjectionDelivery) SyscallQuery() (value.SyscallArgumentPage, bool) {
	if d == nil || d.owner == nil {
		return value.SyscallArgumentPage{}, false
	}
	d.owner.mu.Lock()
	defer d.owner.mu.Unlock()
	if d.owner.closed || d.syscallQuery == nil || d.refusal != ContextProjectionNoRefusal {
		return value.SyscallArgumentPage{}, false
	}
	return value.CloneSyscallArgumentPage(*d.syscallQuery), true
}

func boundedRawSyscallResult(p value.SyscallArgumentPage, scope value.ContextProjectionScope) bool {
	if !p.ValidShape(scope.Syscalls.Selection(scope.CaseID, scope.ArtifactID), scope.Version, scope.PodUID) {
		return false
	}
	b, e := json.Marshal(p)
	return e == nil && len(b) <= value.SyscallQueryPageBytes
}
