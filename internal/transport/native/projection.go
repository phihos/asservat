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
	Summary       *query.SyscallSummaryPage  `json:",omitempty"`
	Events        *query.SyscallEventPage    `json:",omitempty"`
	Query         *query.SyscallArgumentPage `json:",omitempty"`
	InvalidCursor bool                       `json:",omitempty"`
	TooLarge      bool                       `json:",omitempty"`
}

// The saved-log page is selected and byte bounded by the canonical parser.
// Preserve its exact continuation; trimming here would lose source bytes.
type targetDiscoveryReply struct {
	Version       artifact.Digest
	Page          *query.TargetDiscoveryPage `json:",omitempty"`
	InvalidCursor bool                       `json:",omitempty"`
	TooLarge      bool                       `json:",omitempty"`
}

type logProjectionReply struct {
	Version       artifact.Digest
	Logs          *query.LogPage `json:",omitempty"`
	InvalidCursor bool           `json:",omitempty"`
	TooLarge      bool           `json:",omitempty"`
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
	if scope.NativeType == artifact.ProcessesArtifact {
		b, e := json.Marshal(targetDiscoveryReply{Version: scope.Version, Page: r.TargetDiscovery, InvalidCursor: r.InvalidCursor, TooLarge: r.TooLarge})
		if e != nil || len(b) > query.ContextResultBytes {
			clear(b)
			return nil, contracts.ErrNativeProtocol
		}
		return b, nil
	}
	if scope.NativeType == artifact.LogsArtifact {
		b, e := json.Marshal(logProjectionReply{Version: scope.Version, Logs: r.Logs, InvalidCursor: r.InvalidCursor, TooLarge: r.TooLarge})
		if e != nil || len(b) > query.ContextResultBytes {
			clear(b)
			return nil, contracts.ErrNativeProtocol
		}
		return b, nil
	}
	if scope.NativeType == artifact.PodStatusArtifact {
		b, e := json.Marshal(r.PodStatus)
		if e != nil || len(b) > query.ContextResultBytes {
			clear(b)
			return nil, contracts.ErrNativeProtocol
		}
		return b, nil
	}
	if scope.PacketQuery.Valid() {
		if r.PacketQuery == nil {
			return nil, contracts.ErrNativeProtocol
		}
		b, e := json.Marshal(packetQueryWire(*r.PacketQuery))
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
		reply := syscallProjectionReply{NativeType: scope.NativeType, View: scope.Syscalls.View, Version: scope.Version, Summary: r.SyscallSummary, Events: r.SyscallEvents, Query: r.SyscallQuery, InvalidCursor: r.InvalidCursor, TooLarge: r.TooLarge}
		if reply.Summary != nil && reply.Summary.Rows == nil || reply.Events != nil && reply.Events.Events == nil || reply.Query != nil && reply.Query.Events == nil {
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
	case artifact.ProcessesArtifact:
		var reply targetDiscoveryReply
		if nativeDecodeBounded(b, &reply, query.ContextResultBytes) != nil || reply.Version != scope.Version {
			return query.ProjectionResult{}, contracts.ErrNativeProtocol
		}
		r.TargetDiscovery, r.InvalidCursor, r.TooLarge = reply.Page, reply.InvalidCursor, reply.TooLarge
	case artifact.LogsArtifact:
		var reply logProjectionReply
		if nativeDecodeBounded(b, &reply, query.ContextResultBytes) != nil || reply.Version != scope.Version {
			return query.ProjectionResult{}, contracts.ErrNativeProtocol
		}
		r.Logs, r.InvalidCursor, r.TooLarge = reply.Logs, reply.InvalidCursor, reply.TooLarge
	case artifact.PodStatusArtifact:
		if len(b) > query.ContextResultBytes || nativeDecode(b, &r.PodStatus) != nil {
			return query.ProjectionResult{}, contracts.ErrNativeProtocol
		}
	case artifact.PCAPNGArtifact, artifact.RawPCAPNGArtifact:
		if scope.PacketQuery.Valid() {
			var page contracts.PacketQueryPage
			if nativeDecodeBounded(b, &page, query.ContextResultBytes) != nil {
				return query.ProjectionResult{}, contracts.ErrNativeProtocol
			}
			result := packetQueryDomain(page)
			r.PacketQuery = &result
			break
		}
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
		r.SyscallSummary, r.SyscallEvents, r.SyscallQuery = reply.Summary, reply.Events, reply.Query
		r.InvalidCursor, r.TooLarge = reply.InvalidCursor, reply.TooLarge
		if err != nil || reply.NativeType != scope.NativeType || reply.View != scope.Syscalls.View || reply.Version != scope.Version || reply.Summary != nil && reply.Summary.Rows == nil || reply.Events != nil && reply.Events.Events == nil || reply.Query != nil && reply.Query.Events == nil {
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

func packetQueryWire(r query.PacketQueryResult) contracts.PacketQueryPage {
	p := contracts.PacketQueryPage{CaptureMode: r.CaptureMode, Fields: make([]string, len(r.Fields)), Rows: make([][]contracts.PacketQueryCell, len(r.Rows)), ScannedBytes: r.ScannedBytes, ScannedPackets: r.ScannedPackets, RowLimitReached: r.RowLimitReached, ScanLimitReached: r.ScanLimitReached, OutputLimitReached: r.OutputLimitReached}
	for i, f := range r.Fields {
		p.Fields[i] = string(f)
	}
	for i, row := range r.Rows {
		p.Rows[i] = make([]contracts.PacketQueryCell, len(row))
		for j, c := range row {
			p.Rows[i][j] = contracts.PacketQueryCell{Text: c.Text, Number: c.Number}
		}
	}
	return p
}
func packetQueryDomain(p contracts.PacketQueryPage) query.PacketQueryResult {
	r := query.PacketQueryResult{CaptureMode: p.CaptureMode, Fields: make([]query.PacketQueryField, len(p.Fields)), Rows: make([][]query.PacketQueryCell, len(p.Rows)), ScannedBytes: p.ScannedBytes, ScannedPackets: p.ScannedPackets, RowLimitReached: p.RowLimitReached, ScanLimitReached: p.ScanLimitReached, OutputLimitReached: p.OutputLimitReached}
	for i, f := range p.Fields {
		r.Fields[i] = query.PacketQueryField(f)
	}
	for i, row := range p.Rows {
		r.Rows[i] = make([]query.PacketQueryCell, len(row))
		for j, c := range row {
			r.Rows[i][j] = query.PacketQueryCell{Text: c.Text, Number: c.Number}
		}
	}
	return r
}
