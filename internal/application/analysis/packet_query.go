package analysis

import (
	identities "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"strings"
)

type packetQueryApprovalRefusal struct{ cause error }

func (e *packetQueryApprovalRefusal) Error() string { return "raw packet approval required" }
func (e *packetQueryApprovalRefusal) Unwrap() error { return e.cause }
func PacketQueryApprovalRequiredBeforeAdmission(err error) bool {
	var e *packetQueryApprovalRefusal
	return errors.As(err, &e)
}

type packetQueryFilterRefusal struct{ err error }

func (e *packetQueryFilterRefusal) Error() string { return "packet query filter unavailable" }
func (e *packetQueryFilterRefusal) Unwrap() error { return e.err }

// This marker is issued only before C3/materialization or query admission.
func PacketQueryFilterRefusedBeforeAdmission(err error) (invalid, ok bool) {
	var e *packetQueryFilterRefusal
	if !errors.As(err, &e) {
		return false, false
	}
	return errors.Is(e.err, value.ErrInvalid), true
}

type PacketQueryCompiler interface {
	CompilePacketQueryFilter(context.Context, string) (value.PacketQueryProgram, error)
}
type ContextQueryInvocationLookup interface {
	LookupQueryInvocation(context.Context, identity.Principal, string, artifact.Digest) (value.ContextQuery, bool, error)
}
type PacketQueryReads struct {
	Service  ContextProjectionService
	Routes   ContextProjectionRouteReader
	Compiler PacketQueryCompiler
}

func (s ContextProjectionService) PacketQueries() (PacketQueryReads, bool) {
	return PacketQueryReads{s, s.PacketRoutes, s.PacketCompiler}, s.PacketRoutes != nil && s.PacketCompiler != nil
}

// PacketQueryRequestDigest binds original authored intent, independently of a
// later compiler build. No authored filter is retained in a query record.
func NormalizePacketQueryRequest(r value.PacketQueryRequest) value.PacketQueryRequest {
	r.PacketFilter = strings.Join(strings.Fields(r.PacketFilter), " ")
	r.Fields = slices.Clone(r.Fields)
	if r.StartTime != nil {
		t := r.StartTime.UTC()
		r.StartTime = &t
	}
	if r.EndTime != nil {
		t := r.EndTime.UTC()
		r.EndTime = &t
	}
	if r.TCPFlags != nil {
		v := *r.TCPFlags
		r.TCPFlags = &v
	}
	if r.FramePrefix != nil {
		v := *r.FramePrefix
		r.FramePrefix = &v
	}
	return r
}
func PacketQueryRequestDigest(r value.PacketQueryRequest) artifact.Digest {
	r = NormalizePacketQueryRequest(r)
	b, e := json.Marshal(struct {
		Version string
		Request value.PacketQueryRequest
	}{"packet-query-request/v1", r})
	if e != nil {
		return artifact.Digest{}
	}
	return sha256.Sum256(b)
}
func (s PacketQueryReads) Begin(ctx context.Context, current identities.CurrentIdentity, invocation ContextQueryInvocation, r value.PacketQueryRequest) (*ContextProjectionDelivery, error) {
	r = NormalizePacketQueryRequest(r)
	if len(r.PacketFilter) > 512 || !r.Valid() || s.Routes == nil || s.Compiler == nil {
		return nil, value.ErrInvalid
	}
	return s.Service.begin(ctx, current, invocation, "pcap_query", ContextQueryInput{PacketQuery: r}, func(ctx context.Context, i identity.Identity, recovery artifact.RecoveryProof) (value.ContextProjectionCandidate, error) {
		routes, ok := s.Routes.(ContextPacketProjectionRouteReader)
		if !ok {
			return value.ContextProjectionCandidate{}, value.ErrUnavailable
		}
		c, e := routes.ResolvePacketProjectionRoute(ctx, r.CaseID, r.ArtifactID, i, recovery)
		if e != nil {
			return c, e
		}
		p, e := s.Compiler.CompilePacketQueryFilter(ctx, r.PacketFilter)
		if e != nil {
			return value.ContextProjectionCandidate{}, &packetQueryFilterRefusal{e}
		}
		selection := r.Selection(p)
		if !selection.ValidFor(c.NativeType) {
			return value.ContextProjectionCandidate{}, value.ErrInvalid
		}
		c.PacketQuery, e = selection.Window()
		c.RawGrantID = r.GrantID
		if e != nil || !c.Valid() {
			return value.ContextProjectionCandidate{}, value.ErrInvalid
		}
		return c, nil
	})
}
func (d *ContextProjectionDelivery) PacketQuery() (value.PacketQueryResult, bool) {
	if d == nil || d.owner == nil {
		return value.PacketQueryResult{}, false
	}
	d.owner.mu.Lock()
	defer d.owner.mu.Unlock()
	if d.owner.closed || d.packetQuery == nil || d.refusal != ContextProjectionNoRefusal {
		return value.PacketQueryResult{}, false
	}
	return value.ClonePacketQueryResult(*d.packetQuery), true
}

// replayInitialQuery returns only the original handle; it neither observes a
// worker nor consumes another poll/read/grant use.
func (s ContextProjectionResults) replayInitialQuery(o *projectionRequest, q value.ContextQuery) (*ContextProjectionDelivery, error) {
	if !q.Valid() || q.Scope.RootID != s.RootID || q.Scope.Principal != o.initial.Principal || (!q.Scope.PacketQuery.Valid() && q.Scope.Syscalls.View != value.SyscallQueryView && !q.Scope.Logs.Valid()) || q.Scope.BeginTool() != o.request.Call.Tool {
		return nil, value.ErrUnavailable
	}
	o.query = q
	o.authorityMu.Lock()
	o.authority = nil
	o.authorityAttempted = false
	o.authorityError = nil
	o.authorityMu.Unlock()
	a, e := o.CheckCurrent(o.ctx)
	if e != nil {
		return nil, e
	}
	calls, ok := s.Ledger.(ContextQueryReplayCalls)
	if !ok {
		return nil, queryStepped("replay-registration", value.ErrUnavailable)
	}
	if e = calls.RegisterQueryReplayCall(o.ctx, q, o.request, a); e != nil {
		return nil, queryCollapsed("replay-registration", value.ErrUnavailable, e)
	}
	if e = s.Ledger.PermitQuery(o.ctx, q, o.request, a); e != nil {
		return nil, e
	}
	if _, e = o.CheckCurrent(o.ctx); e != nil {
		return nil, e
	}
	d := &ContextProjectionDelivery{owner: o, pending: true, effect: ContextQueryReplayed, observedAt: s.Now(), queryDeadline: identity.Earlier(q.Deadline, a.AccessUntil), cleanupUntil: identity.Earlier(q.CleanupUntil, o.request.Call.WriteUntil), association: ContextProjectionAssociation{ID: s.NewID(), QueryID: q.ID, OperationID: o.request.Call.ID, PacketQuery: q.Scope.PacketQuery, Syscalls: q.Scope.Syscalls, Logs: q.Scope.Logs}}
	if !authorization.UUID(d.association.ID) || !s.Now().Before(d.queryDeadline) || d.queryDeadline.IsZero() {
		return nil, value.ErrUnavailable
	}
	return d, nil
}
