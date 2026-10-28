package objectstore

import (
	"context"
	"errors"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore/framed"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
)

// FramedNativeSource serves exact native ranges of one stored artifact of any
// registered type (ADR-244) to the windowed response transfer (ADR-113). It
// belongs to the regional acquisition role: the commit and manifest were
// authenticated and matched to the independent expectation when it opened,
// its data/index keys were opened once, and each frame is authenticated before
// any of its bytes are returned. A whole-file response additionally ends with
// the verified native, data and index hashes. It decides no authorization:
// leases, windows, spend and audit stay with the transfer and its SQL facets.
type FramedNativeSource struct {
	mu        sync.Mutex
	owner     context.Context
	cancel    context.CancelFunc
	reader    *framed.Reader
	metadata  artifact.NativeDownloadMetadata
	readLimit int64
	cursor    *framed.Cursor
	start     int64 // first native offset of the cursor's selection
	next      int64 // next native offset to return
	carry     []byte
	final     bool
	full      bool
	busy      bool
	closed    bool
}

var _ evidence.NativeResponseSource = (*FramedNativeSource)(nil)

// nativeWindowReadLimit bounds the ciphertext one 64 MiB accounting window can
// read: at most nine frames (eight plus one unaligned boundary frame) and two
// index pages, each with its fixed cipher overhead.
const nativeWindowReadLimit = 9*(artifact.FrameBytes+artifact.CipherOverhead) + 2*(artifact.PageBytes+artifact.CipherOverhead)

// OpenNative opens one stored artifact for download until readUntil, which
// the caller bounds by the current disclosure authority; the source never
// outlives the artifact's ExpiresAt. Opening reads only the commit and
// manifest objects and opens the data and index keys.
func (v *ContextVerifier) OpenNative(ctx context.Context, e artifact.ContextExpectation, c artifact.Copies, readUntil time.Time) (*FramedNativeSource, error) {
	return v.openNative(ctx, ctx, e, c, readUntil)
}

// openNative separates a finite initial key/metadata phase from the original
// cursor owner. Canceling opening after acknowledgement never revives or ends
// a retained cursor; caller cancellation and readUntil still own that cursor.
func (v *ContextVerifier) openNative(ctx, opening context.Context, e artifact.ContextExpectation, c artifact.Copies, readUntil time.Time) (*FramedNativeSource, error) {
	until := minDeadline(readUntil, e.Registration.ExpiresAt)
	if v == nil || ctx == nil || opening == nil || !time.Now().Before(until) {
		return nil, artifact.ErrInvalid
	}
	call, stop := context.WithDeadline(opening, minDeadline(until, time.Now().Add(30*time.Second)))
	defer stop()
	reader, m, err := v.open(call, e, c, until)
	if err != nil {
		return nil, err
	}
	l := m.Layout
	t := e.Type()
	work, err := l.RangeReadWork(0, l.NativeBytes)
	if err != nil {
		return nil, err
	}
	limit := min(nativeWindowReadLimit, work.DataBytes+work.IndexBytes)
	owner, cancel := context.WithDeadline(ctx, until)
	return &FramedNativeSource{owner: owner, cancel: cancel, reader: reader, readLimit: limit, metadata: artifact.NativeDownloadMetadata{
		Filename: t.Filename(e.Registration.Location.ArtifactID), Format: t.Format, ETag: evidence.NativeETag(evidence.ContextCopiesDigest(c)), Coverage: t.CoverageFor(e.Lifecycle),
		Size: l.NativeBytes, SHA256: l.NativeSHA256, ReadUntil: e.Registration.ExpiresAt, DeleteBy: e.Registration.DeleteBy,
	}}, nil
}

// Describe returns the verified native facts, shortened to the current
// authority's access and deletion bounds, and the per-window read bound.
func (s *FramedNativeSource) Describe(ctx context.Context, _ artifact.DownloadSession, a artifact.DownloadAuthority) (artifact.NativeDownloadMetadata, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || ctx == nil || ctx.Err() != nil || s.owner.Err() != nil {
		return artifact.NativeDownloadMetadata{}, 0, artifact.ErrDownloadUnavailable
	}
	m := s.metadata
	m.ReadUntil = minDeadline(m.ReadUntil, a.AccessUntil)
	if !a.DeleteBy.IsZero() {
		m.DeleteBy = minDeadline(m.DeleteBy, a.DeleteBy)
	}
	return m, s.readLimit, nil
}

// ReadChunk returns exactly length bytes at offset. Calls are sequential and
// contiguous within one response; a gap or rewind is refused rather than
// silently re-read. ReadWork is the ciphertext this call read.
func (s *FramedNativeSource) ReadChunk(ctx context.Context, lease artifact.DownloadDeliveryLease, offset, length int64) (evidence.NativeResponseChunk, error) {
	if !lease.Allows(offset, length, time.Now()) {
		return evidence.NativeResponseChunk{}, artifact.ErrDownloadUnavailable
	}
	return s.read(ctx, offset, length)
}

// Metadata returns the facts authenticated by the manifest when the source
// opened, with the artifact's own access and deletion dates.
func (s *FramedNativeSource) Metadata() artifact.NativeDownloadMetadata {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.metadata
}

// ReadNext serves the regional download worker (ADR-248), whose admitted
// native operation and window key binding bound this source instead of a hub
// delivery lease: the same sequential, authenticated read as ReadChunk, at
// most one delivery chunk at a time. final reports the end-of-file check.
func (s *FramedNativeSource) ReadNext(ctx context.Context, offset, length int64) ([]byte, bool, error) {
	if length < 1 || length > artifact.DeliveryBytes {
		return nil, false, artifact.ErrInvalid
	}
	chunk, err := s.read(ctx, offset, length)
	if err != nil {
		clear(chunk.Bytes)
		return nil, false, err
	}
	return chunk.Bytes, chunk.FinalVerified, nil
}

func (s *FramedNativeSource) read(ctx context.Context, offset, length int64) (evidence.NativeResponseChunk, error) {
	var out evidence.NativeResponseChunk
	s.mu.Lock()
	if s.closed || s.busy || ctx == nil || offset < 0 || length < 0 || offset > s.metadata.Size || length > s.metadata.Size-offset {
		s.mu.Unlock()
		return out, artifact.ErrDownloadUnavailable
	}
	if ctx.Err() != nil || s.owner.Err() != nil {
		clear(s.carry)
		s.carry = nil
		s.closed = true
		s.mu.Unlock()
		return out, artifact.ErrDownloadUnavailable
	}
	if s.cursor == nil {
		cursor, err := s.reader.Cursor(s.owner, offset, s.metadata.Size-offset)
		if err != nil {
			s.mu.Unlock()
			return out, err
		}
		s.cursor, s.start, s.next = cursor, offset, offset
	}
	if offset != s.next {
		s.mu.Unlock()
		return out, artifact.ErrDownloadConflict
	}
	s.busy = true
	cursor := s.cursor
	carry, final, full := s.carry, s.final, s.full
	s.mu.Unlock()
	// Loading and authenticating the next 8 MiB frame discloses nothing and may
	// outlast the caller's short delivery lease: it is bounded by the source's
	// owner (the response) and stops on cancellation, not on the lease deadline.
	// The transfer writes the chunk only under a then-current lease.
	load, cancelLoad := context.WithCancel(s.owner)
	defer cancelLoad()
	stopWatch := context.AfterFunc(ctx, func() {
		if errors.Is(ctx.Err(), context.Canceled) {
			cancelLoad()
		}
	})
	defer stopWatch()
	var work int64
	var err error
	for int64(len(carry)) < length || length == 0 && !final {
		if final {
			err = artifact.ErrIntegrity
			break
		}
		var chunk framed.Chunk
		chunk, err = cursor.Next(load)
		work += chunk.Work.DataBytes + chunk.Work.IndexBytes
		if err != nil {
			break
		}
		carry = append(carry, chunk.Bytes...)
		clear(chunk.Bytes)
		final, full = chunk.Final, chunk.FullVerified
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.busy = false
	if err != nil || s.closed || errors.Is(ctx.Err(), context.Canceled) || s.owner.Err() != nil {
		clear(carry)
		s.carry = nil
		s.closed = true // an admitted failed read is terminal, as for the cursor
		out.ReadWork = work
		if err == nil {
			err = artifact.ErrDownloadUnavailable
		}
		return out, err
	}
	out.Bytes = append([]byte(nil), carry[:length]...)
	rest := copy(carry, carry[length:])
	clear(carry[rest:])
	s.carry, s.final, s.full = carry[:rest], final, full
	s.next += length
	out.ReadWork = work
	// Every returned frame was authenticated before delivery; the end of the
	// file additionally needs the cursor's final check, and a whole-file
	// selection its verified whole-file hashes.
	end := s.next == s.metadata.Size
	out.FinalVerified = !end || final && (s.start != 0 || full)
	return out, nil
}

// Close cancels and joins the cursor and drops the reader and keys.
func (s *FramedNativeSource) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.closed = true
	cursor := s.cursor
	s.cursor, s.reader = nil, nil
	if !s.busy { // an active read owns carry and clears it when it returns
		clear(s.carry)
		s.carry = nil
	}
	s.mu.Unlock()
	s.cancel()
	if cursor != nil {
		cursor.Close()
	}
}
