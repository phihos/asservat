package evidence

import (
	"bytes"
	"context"
	"sync"

	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

// In-process spend is an additional fence; the mandatory query key provider
// independently performs durable, current one-use consumption before unwrap.
type projectionKeyOpener struct {
	read             *RegionalProjectionRead
	binding          value.ContextProjectionKeyBinding
	artifact         artifact.Binding
	mu               sync.Mutex
	spent, completed uint8
}

func (o *projectionKeyOpener) Open(ctx context.Context, sealed artifact.SealedKey, aad []byte) ([]byte, error) {
	if o == nil || ctx == nil || ctx.Err() != nil {
		return nil, value.ErrUnavailable
	}
	var role value.ContextProjectionKeyRole
	for _, candidate := range []value.ContextProjectionKeyRole{value.ContextProjectionDataKey, value.ContextProjectionIndexKey, value.ContextProjectionManifestKey} {
		expected, err := ArtifactKeyBinding(o.artifact, string(candidate))
		if err != nil {
			return nil, value.ErrUnavailable
		}
		matches := bytes.Equal(expected, aad)
		clear(expected)
		if matches {
			role = candidate
			break
		}
	}
	mask := role.Mask()
	if mask == 0 {
		return nil, value.ErrUnavailable
	}
	work, cancel := o.read.context(ctx)
	defer cancel()
	current, err := o.read.check(work)
	if err != nil || !sameProjectionAuthority(current, o.binding.Authority) {
		return nil, value.ErrUnavailable
	}
	if !o.binding.Valid(o.read.worker.query, o.read.worker.now()) {
		return nil, value.ErrUnavailable
	}
	o.mu.Lock()
	if o.spent&mask != 0 {
		o.mu.Unlock()
		return nil, value.ErrUnavailable
	}
	o.spent |= mask
	o.mu.Unlock()
	// The provider owns its input copy for this synchronous call. A failed or
	// unknown result never clears the local bit or the separate SQL bit.
	owned := bytes.Clone(aad)
	defer clear(owned)
	key, err := o.read.worker.keys.OpenProjectionKey(work, o.binding, role, sealed, owned)
	if err != nil || len(key) < 1 || len(key) > 4096 || work.Err() != nil {
		clear(key)
		return nil, value.ErrUnavailable
	}
	current, err = o.read.check(work)
	if err != nil || !sameProjectionAuthority(current, o.binding.Authority) {
		clear(key)
		return nil, value.ErrUnavailable
	}
	o.mu.Lock()
	o.completed |= mask
	o.mu.Unlock()
	return key, nil
}

func (o *projectionKeyOpener) complete() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.spent == 7 && o.completed == 7
}
