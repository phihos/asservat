package objectstore

import (
	"context"
	"crypto/sha256"
	"hash"
	"io"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
)

// StoreSnapshot uses only a separately authenticated node outcome matching the
// prepared admission. It derives exact manifest expectations before encoding;
// the native stream is independently hashed before the first object write.
func (a *PreparedArtifact) StoreSnapshot(ctx context.Context, src io.Reader, started, completed time.Time, o artifact.SourceSnapshotOutcome) (artifact.Copies, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	e, err := artifact.ProjectSourceSnapshot(a.expectation, evidence.ContextExpectationDigest(a.expectation), o)
	acquiredFrom, acquiredUntil := artifact.SourceSnapshotAcquisition(o.SourceSnapshotCoverage)
	if err != nil || !started.Equal(acquiredFrom) || !completed.Equal(acquiredUntil) {
		return artifact.Copies{}, artifact.ErrInvalid
	}
	a.expectation = e
	retained := o.Retained
	a.snapshotRetained = &retained
	defer func() { a.snapshotRetained = nil }()
	checked := &snapshotNativeReader{src: src, hash: sha256.New(), expected: o.NativeSHA256, remaining: o.NativeBytes}
	copies, err := a.storeLocked(ctx, checked, started, completed)
	if err != nil {
		return artifact.Copies{}, err
	}
	if !checked.verified {
		return artifact.Copies{}, artifact.ErrIntegrity
	}
	return copies, nil
}

type snapshotNativeReader struct {
	src       io.Reader
	hash      hash.Hash
	expected  artifact.Digest
	remaining int64
	verified  bool
}

func (r *snapshotNativeReader) Read(p []byte) (int, error) {
	n, err := r.src.Read(p)
	if int64(n) > r.remaining {
		return 0, artifact.ErrIntegrity
	}
	r.remaining -= int64(n)
	if n > 0 {
		_, _ = r.hash.Write(p[:n])
	}
	if r.remaining == 0 && err == nil {
		var extra [1]byte
		extraN, extraErr := r.src.Read(extra[:])
		if extraN != 0 || extraErr != io.EOF {
			return n, artifact.ErrIntegrity
		}
		err = io.EOF
	}
	if err == io.EOF {
		var actual artifact.Digest
		copy(actual[:], r.hash.Sum(nil))
		if r.remaining != 0 || actual != r.expected {
			return n, artifact.ErrIntegrity
		}
		r.verified = true
	}
	return n, err
}
