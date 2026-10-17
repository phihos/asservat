package objectstore

import (
	"context"
	"errors"

	"asservat.local/asservat/internal/domain/artifact"
)

// putControlAudit preserves a positive write receipt. Only a definite
// conditional-create conflict may enter the caller's existing semantic
// reconciliation path. An uncertain write never triggers a second effect or
// a lookup here. The caller still verifies the decrypted record and its
// original authority, and this helper supplies no writer-completion fact.
func (s *Store) putControlAudit(ctx context.Context, key string, ciphertext []byte, maximum int64) (Object, []byte, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || maximum < 1 || maximum > MaxSmallObject || len(ciphertext) < 1 || int64(len(ciphertext)) > maximum {
		return Object{}, nil, artifact.ErrInvalid
	}
	written, err := s.PutSmall(ctx, key, ciphertext)
	if errors.Is(err, ErrExists) {
		return s.readControlAudit(ctx, key, maximum)
	}
	if err != nil {
		return Object{}, nil, err
	}
	return s.readAcknowledgedControlAudit(ctx, written, maximum)
}
