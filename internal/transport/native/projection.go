package native

import (
	"context"

	"asservat.local/asservat/internal/contracts"
	query "asservat.local/asservat/internal/domain/analysis"
	value "asservat.local/asservat/internal/domain/authorization"
)

func (o *HubOperation) readProjection(ctx context.Context, s Stream) (query.PodStatusProjection, error) {
	var zero query.PodStatusProjection
	f, e := s.Receive(ctx)
	if e != nil {
		return zero, e
	}
	defer clear(f.Payload)
	m, e := contracts.DecodeNativeMetadata(f.Payload)
	if e != nil || f.Kind != contracts.NativeMetadataFrame || m.Format != o.command.Format || m.Reference != o.command.Reference || m.Nonce != o.command.Nonce || len(m.Metadata) > query.ContextResultBytes {
		return zero, contracts.ErrNativeProtocol
	}
	var p query.PodStatusProjection
	if nativeDecode(m.Metadata, &p) != nil || !p.Valid() || p.NamespaceUID != o.projectionScope.NamespaceUID || p.PodUID != o.projectionScope.PodUID {
		return zero, contracts.ErrNativeProtocol
	}
	return p, nil
}

// Projection is a single-use bounded DTO handoff. It alone cannot acknowledge
// public delivery or complete the query batch; the caller retains that separate
// live request and its existing C-20 audit/closure obligations.
func (o *HubOperation) Projection(ctx context.Context) (query.PodStatusProjection, error) {
	var zero query.PodStatusProjection
	if o == nil || ctx == nil || o.command.Kind != string(value.NativeProjection) || !o.claim() {
		return zero, query.ErrUnavailable
	}
	select {
	case p := <-o.projection:
		if _, e := o.gate.Check(ctx); e != nil {
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
