package objectstore

import (
	"context"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	"asservat.local/asservat/internal/application/evidence"
	query "asservat.local/asservat/internal/domain/analysis"
	value "asservat.local/asservat/internal/domain/authorization"
)

// ReadApprovedContext reuses the installed regional store and mTLS key client.
// AuthorityID is the exact query batch, independently classified and consumed
// by the key service. No metadata/download operation or byte response is used.
func (r *NativeContextReader) ReadApprovedContext(ctx context.Context, source evidence.NativeContextSource, o value.NativeOperation, scope query.ContextProjectionScope, until time.Time) (query.ProjectionResult, error) {
	var zero query.ProjectionResult
	if r == nil || ctx == nil || ctx.Err() != nil || o.Kind != value.NativeProjection || !o.CurrentValid(time.Now()) || o.Reference.InstallationID != r.scope.InstallationID || !scope.Valid() || scope.Comparison != (query.ProfileComparisonWindow{}) || o.Baseline != (value.NativeProjectionSource{}) || scope.Version != o.SourceVersion {
		return zero, &readRefusal{query.ErrUnavailable, &contextReadStage{"operation", query.ErrUnavailable}}
	}
	end, ok := ctx.Deadline()
	if !ok || end.After(until) || end.After(o.Until) || !time.Now().Before(end) {
		return zero, &readRefusal{query.ErrUnavailable, &contextReadStage{"deadline", query.ErrUnavailable}}
	}
	opener, e := kms.NewRemoteOpener(r.endpoint, r.scope, o.ParentID, r.client)
	if e != nil {
		return zero, &readRefusal{e, &contextReadStage{"key-client", e}}
	}
	defer opener.Close()
	reader, e := r.projectionReader()
	if e != nil {
		return zero, &readRefusal{e, &contextReadStage{"store", e}}
	}
	return reader.ReadProjectionNative(ctx, source, scope, opener, end)
}

// Retain the same startup-installed closed interpreters when constructing the
// per-operation reader. This creates no key authority or fallback interpreter.
func (r *NativeContextReader) projectionReader() (*ContextProjectionReader, error) {
	reader, err := NewContextProjectionReader(r.store)
	if err != nil {
		return nil, err
	}
	reader.pages = r.pages
	reader.summarize = r.summarize
	reader.syscalls = r.syscalls
	reader.compare = r.compare
	reader.packets = r.packets
	reader.queryPackets = r.queryPackets
	reader.querySyscalls = r.querySyscalls
	reader.queryLogs = r.queryLogs
	return reader, nil
}

// ServeHTTPHeaderPages installs the httpHeaders pager (ADR-282); without it
// this reader serves pod-status projections only.
func (r *NativeContextReader) ServeHTTPHeaderPages(p evidence.HTTPHeaderPager) {
	if r != nil {
		r.pages = p
	}
}

var _ evidence.NativeApprovedContextRead = (*NativeContextReader)(nil)

// ServeProfileSummaries installs the bounded pprof interpreter for approved reads.
func (r *NativeContextReader) ServeProfileSummaries(f evidence.ProfileSummarizer) {
	if r != nil {
		r.summarize = f
	}
}

// ServeSyscallProjections installs only the fixed saved metadata views. It
// neither permits native raw disclosure nor enables collection.
func (r *NativeContextReader) ServeSyscallProjections(f evidence.SyscallProjector) {
	if r != nil {
		r.syscalls = f
	}
}

// ServePacketSummaries installs only a fixed metadata PCAPNG interpreter.
func (r *NativeContextReader) ServePacketSummaries(f evidence.PacketSummarizer) {
	if r != nil {
		r.packets = f
	}
}

func (r *NativeContextReader) ServePacketQueries(f evidence.PacketQuerier) {
	if r != nil {
		r.queryPackets = f
	}
}

// ServeSyscallQueries installs only the approved recorded-argument interpreter.
func (r *NativeContextReader) ServeSyscallQueries(f evidence.SyscallQuerier) {
	if r != nil {
		r.querySyscalls = f
	}
}

// ServeLogQueries installs only the exact approved saved-log interpreter.
func (r *NativeContextReader) ServeLogQueries(f evidence.LogQuerier) {
	if r != nil {
		r.queryLogs = f
	}
}
