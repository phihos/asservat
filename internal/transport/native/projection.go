package native

import (
	"context"
	"encoding/json"

	"asservat.local/asservat/internal/contracts"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
)

func (o *HubOperation) readProjection(ctx context.Context, s Stream) (query.ProjectionResult, error) {
	var zero query.ProjectionResult
	f, e := s.Receive(ctx)
	if e != nil {
		return zero, e
	}
	defer clear(f.Payload)
	m, e := contracts.DecodeNativeMetadata(f.Payload)
	if e != nil || f.Kind != contracts.NativeMetadataFrame || m.Format != o.command.Format || m.Reference != o.command.Reference || m.Nonce != o.command.Nonce {
		return zero, contracts.ErrNativeProtocol
	}
	r, e := decodeProjectionResult(m.Metadata, o.projectionScope)
	if e != nil {
		return zero, e
	}
	return r, nil
}

// headerPageReply is the httpHeaders projection payload (ADR-282): one page,
// or an invalid-cursor or too-large refusal that carries no record. Pod status
// keeps its historical payload, the bare DTO.
type headerPageReply struct {
	Page          *query.HTTPHeaderPage `json:",omitempty"`
	InvalidCursor bool                  `json:",omitempty"`
	TooLarge      bool                  `json:",omitempty"`
}

// syscallProjectionReply is a closed fixed-metadata result for exactly one
// saved source and view. These fields carry no raw arguments or authority.
// Unlike HTTP pages, the parser has already selected a byte-bounded prefix;
// the codec must preserve that exact selection rather than trim it again.
type syscallProjectionReply struct {
	NativeType    string
	View          query.SyscallView
	Version       artifact.Digest
	Summary       *query.SyscallSummaryPage `json:",omitempty"`
	Events        *query.SyscallEventPage   `json:",omitempty"`
	InvalidCursor bool                      `json:",omitempty"`
	TooLarge      bool                      `json:",omitempty"`
}

type profileComparisonReply struct {
	BaselineVersion, IncidentVersion artifact.Digest
	Comparison                       *query.ProfileComparison `json:",omitempty"`
	IncompatibleProfiles             bool                     `json:",omitempty"`
	TooLarge                         bool                     `json:",omitempty"`
}

// encodeProjectionResult is the worker's payload for the scope's result. A
// page sends the longest record prefix within HTTPHeaderPageWireBytes; its
// continuation starts at the first omitted record.
func encodeProjectionResult(r query.ProjectionResult, scope query.ContextProjectionScope) ([]byte, error) {
	if !r.Valid(scope) {
		return nil, contracts.ErrNativeProtocol
	}
	if scope.NativeType == artifact.PodStatusArtifact {
		b, e := json.Marshal(r.PodStatus)
		if e != nil || len(b) > query.ContextResultBytes {
			clear(b)
			return nil, contracts.ErrNativeProtocol
		}
		return b, nil
	}
	if scope.NativeType == artifact.PCAPNGArtifact || scope.NativeType == artifact.RawPCAPNGArtifact {
		b, e := json.Marshal(r.PacketSummary)
		if e != nil || len(b) > query.ContextResultBytes {
			clear(b)
			return nil, contracts.ErrNativeProtocol
		}
		return b, nil
	}
	if scope.NativeType == artifact.PprofArtifact {
		if scope.Comparison != (query.ProfileComparisonWindow{}) {
			reply := profileComparisonReply{BaselineVersion: scope.Comparison.Baseline.Version, IncidentVersion: scope.Version, Comparison: r.Comparison, IncompatibleProfiles: r.IncompatibleProfiles, TooLarge: r.TooLarge}
			b, e := json.Marshal(reply)
			if e != nil {
				clear(b)
				return nil, contracts.ErrNativeProtocol
			}
			if len(b) > query.ContextResultBytes {
				clear(b)
				// The complete authenticated result is valid, but its private
				// version envelope also spends the fixed result-byte allowance.
				// Retain a positively acknowledged, content-free size refusal.
				return json.Marshal(profileComparisonReply{BaselineVersion: scope.Comparison.Baseline.Version, IncidentVersion: scope.Version, TooLarge: true})
			}
			return b, nil
		}
		b, e := json.Marshal(r.Summary)
		if e != nil || len(b) > query.ProfileSummaryBytes {
			clear(b)
			return nil, contracts.ErrNativeProtocol
		}
		return b, nil
	}
	if scope.NativeType == artifact.SyscallRecordsArtifact || scope.NativeType == artifact.SyscallArgumentsArtifact {
		reply := syscallProjectionReply{NativeType: scope.NativeType, View: scope.Syscalls.View, Version: scope.Version, Summary: r.SyscallSummary, Events: r.SyscallEvents, InvalidCursor: r.InvalidCursor, TooLarge: r.TooLarge}
		if reply.Summary != nil && reply.Summary.Rows == nil || reply.Events != nil && reply.Events.Events == nil {
			return nil, contracts.ErrNativeProtocol
		}
		b, e := json.Marshal(reply)
		if e != nil || len(b) > query.ContextResultBytes {
			clear(b)
			return nil, contracts.ErrNativeProtocol
		}
		return b, nil
	}
	if r.InvalidCursor || r.TooLarge {
		return json.Marshal(headerPageReply{InvalidCursor: r.InvalidCursor, TooLarge: r.TooLarge})
	}
	page := r.Headers
	for n := len(page.Records); ; n-- {
		prefix := page
		prefix.Records = page.Records[:n]
		b, e := json.Marshal(headerPageReply{Page: &prefix})
		if e != nil {
			return nil, contracts.ErrNativeProtocol
		}
		if len(b) <= query.HTTPHeaderPageWireBytes {
			return b, nil
		}
		clear(b)
		if n <= 1 {
			// Valid records allow 32 values of 1 KiB, whose JSON escapes (the
			// canonical encoding escapes <, > and &) can exceed the bound;
			// refuse explicitly rather than as a retryable protocol error.
			return json.Marshal(headerPageReply{TooLarge: true})
		}
	}
}

// decodeProjectionResult accepts exactly the scope's payload, canonically
// encoded within its own bound, and returns a result valid for the scope.
func decodeProjectionResult(b []byte, scope query.ContextProjectionScope) (query.ProjectionResult, error) {
	var r query.ProjectionResult
	switch scope.NativeType {
	case artifact.PodStatusArtifact:
		if len(b) > query.ContextResultBytes || nativeDecode(b, &r.PodStatus) != nil {
			return query.ProjectionResult{}, contracts.ErrNativeProtocol
		}
	case artifact.PCAPNGArtifact, artifact.RawPCAPNGArtifact:
		var summary query.PacketSummary
		if nativeDecodeBounded(b, &summary, query.ContextResultBytes) != nil {
			return query.ProjectionResult{}, contracts.ErrNativeProtocol
		}
		r.PacketSummary = &summary
	case artifact.PprofArtifact:
		if scope.Comparison != (query.ProfileComparisonWindow{}) {
			var reply profileComparisonReply
			if nativeDecodeBounded(b, &reply, query.ContextResultBytes) != nil || reply.BaselineVersion != scope.Comparison.Baseline.Version || reply.IncidentVersion != scope.Version {
				return query.ProjectionResult{}, contracts.ErrNativeProtocol
			}
			r.Comparison, r.IncompatibleProfiles = reply.Comparison, reply.IncompatibleProfiles
			r.TooLarge = reply.TooLarge
			break
		}
		var summary query.ProfileSummary
		if len(b) > query.ProfileSummaryBytes || nativeDecode(b, &summary) != nil {
			return query.ProjectionResult{}, contracts.ErrNativeProtocol
		}
		r.Summary = &summary
	case artifact.SyscallRecordsArtifact, artifact.SyscallArgumentsArtifact:
		var reply syscallProjectionReply
		err := nativeDecodeBounded(b, &reply, query.ContextResultBytes)
		r.SyscallSummary, r.SyscallEvents = reply.Summary, reply.Events
		r.InvalidCursor, r.TooLarge = reply.InvalidCursor, reply.TooLarge
		if err != nil || reply.NativeType != scope.NativeType || reply.View != scope.Syscalls.View || reply.Version != scope.Version || reply.Summary != nil && reply.Summary.Rows == nil || reply.Events != nil && reply.Events.Events == nil {
			r.Clear()
			return query.ProjectionResult{}, contracts.ErrNativeProtocol
		}
	case artifact.HTTPHeadersArtifact:
		var reply headerPageReply
		if len(b) > query.HTTPHeaderPageWireBytes || nativeDecode(b, &reply) != nil || (reply.Page != nil) == (reply.InvalidCursor || reply.TooLarge) {
			return query.ProjectionResult{}, contracts.ErrNativeProtocol
		}
		if reply.Page != nil {
			r.Headers = *reply.Page
		}
		r.InvalidCursor, r.TooLarge = reply.InvalidCursor, reply.TooLarge
	}
	if !r.Valid(scope) {
		r.Clear()
		return query.ProjectionResult{}, contracts.ErrNativeProtocol
	}
	return r, nil
}

// Projection is a single-use bounded DTO handoff. It alone cannot acknowledge
// public delivery or complete the query batch; the caller retains that separate
// live request and its existing C-20 audit/closure obligations.
func (o *HubOperation) Projection(ctx context.Context) (query.ProjectionResult, error) {
	var zero query.ProjectionResult
	if o == nil || ctx == nil || o.command.Kind != string(value.NativeProjection) || !o.claim() {
		return zero, query.ErrUnavailable
	}
	select {
	case p := <-o.projection:
		if _, e := o.gate.Check(ctx); e != nil {
			p.Clear()
			return zero, e
		}
		return p, nil
	case <-ctx.Done():
		o.cancel()
		return zero, ctx.Err()
	case <-o.ctx.Done():
		return zero, query.ErrUnavailable
	}
}

// AcknowledgeProjection confirms consumption of the private fixed DTO, then
// joins its worker buffer and the exact stream. It grants no public disclosure.
// EOF/cancellation cannot supply this positive protocol result.
func (o *HubOperation) AcknowledgeProjection(ctx context.Context) error {
	if o == nil || ctx == nil || o.command.Kind != string(value.NativeProjection) {
		return query.ErrUnavailable
	}
	if e := o.submit(ctx, "approved", 0); e != nil {
		return e
	}
	select {
	case <-o.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
