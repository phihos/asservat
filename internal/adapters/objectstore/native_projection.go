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
func (r *NativeContextReader) ReadApprovedContext(ctx context.Context, source evidence.NativeContextSource, o value.NativeOperation, scope query.ContextProjectionScope, until time.Time) (query.PodStatusProjection, error) {
	var zero query.PodStatusProjection
	if r == nil || ctx == nil || ctx.Err() != nil || o.Kind != value.NativeProjection || !o.CurrentValid(time.Now()) || o.Reference.InstallationID != r.scope.InstallationID || !scope.Valid() || scope.Version != o.SourceVersion {
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
	reader, e := NewContextProjectionReader(r.store)
	if e != nil {
		return zero, &readRefusal{e, &contextReadStage{"store", e}}
	}
	return reader.ReadProjectionNative(ctx, source, scope, opener, end)
}

var _ evidence.NativeApprovedContextRead = (*NativeContextReader)(nil)
