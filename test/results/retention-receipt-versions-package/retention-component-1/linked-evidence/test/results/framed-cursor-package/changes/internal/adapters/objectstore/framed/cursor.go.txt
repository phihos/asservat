package framed

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"hash"
	"io"
	"sync"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"github.com/klauspost/compress/zstd"
)

var (
	ErrCursorBusy   = errors.New("artifact cursor read already in progress")
	ErrCursorClosed = errors.New("artifact cursor closed")
)

// Chunk owns Bytes; the caller must clear it after use. Final means the exact
// selection is complete; FullVerified is true only for a complete native file
// whose native/data/index hashes all matched. Neither value confers authority.
// Work counts this call's requested ciphertext bytes before I/O and whole-frame
// native decode allowance before decoding, including failed/unknown attempts.
// A failure can return Work but never Bytes or a positive integrity disposition.
// It must not be interpreted as a refund or permission to repeat that work.
type Chunk struct {
	Bytes        []byte
	Work         artifact.FramedReadWork
	Final        bool
	FullVerified bool
}

// Cursor retains one authenticated page and one decoded frame. It performs no
// idle I/O, prefetch or additional key opening. Next calls are sequential; each
// call must supply its own current context, bounded by the original owner.
// An admitted failed call is terminal. Close cancels and joins any actual read;
// a CipherSource that fails to return on cancellation keeps Close waiting.
// Close cannot erase already returned bytes or keys owned by the Reader.
type Cursor struct {
	mu     sync.Mutex
	owner  context.Context
	cancel context.CancelFunc
	active chan struct{}
	closed bool
	failed error
	done   bool

	reader                          *Reader
	decoder                         *zstd.Decoder
	offset, size, delivered         int64
	full                            bool
	pageNext, frameNext             int
	frames                          []frame
	plain                           []byte
	frameAt, frameEnd               int64
	nativeHash, dataHash, indexHash hash.Hash
}

// Cursor selects an exact range without reading objects. Reader.Open already
// opened the data/index keys; each cursor uses those same local primitives.
// The caller separately admits read/decode work and enforces current authority.
func (r *Reader) Cursor(owner context.Context, offset, size int64) (*Cursor, error) {
	if r == nil || owner == nil {
		return nil, artifact.ErrInvalid
	}
	if _, err := r.layout.RangeReadWork(offset, size); err != nil {
		return nil, err
	}
	if err := cursorContextError(owner); err != nil {
		return nil, err
	}
	z, err := zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxWindow(uint64(artifact.FrameBytes)), zstd.WithDecoderMaxMemory(uint64(artifact.FrameBytes)), zstd.WithDecodeAllCapLimit(true))
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(owner)
	return &Cursor{owner: ctx, cancel: cancel, reader: r, decoder: z, offset: offset, size: size, full: offset == 0 && size == r.layout.NativeBytes,
		nativeHash: sha256.New(), dataHash: sha256.New(), indexHash: sha256.New()}, nil
}

func cursorContextError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if until, ok := ctx.Deadline(); ok && !time.Now().Before(until) {
		return context.DeadlineExceeded
	}
	return nil
}

// Next returns at most DeliveryBytes. A previously successful call's context
// cannot cancel a later call; both still share the original owner's deadline and
// cancellation. A canceled call rejected before admission does no work.
func (c *Cursor) Next(current context.Context) (out Chunk, err error) {
	if current == nil {
		return out, artifact.ErrInvalid
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return out, ErrCursorClosed
	}
	if c.active != nil {
		c.mu.Unlock()
		return out, ErrCursorBusy
	}
	if c.failed != nil {
		err = c.failed
		c.mu.Unlock()
		return out, err
	}
	if err = cursorContextError(c.owner); err != nil {
		c.failed = err
		c.release()
		c.mu.Unlock()
		return out, err
	}
	if err = cursorContextError(current); err != nil {
		c.mu.Unlock()
		return out, err
	}
	if c.done {
		c.mu.Unlock()
		return out, io.EOF
	}
	var ctx context.Context
	var cancel context.CancelFunc
	if until, ok := c.owner.Deadline(); ok {
		ctx, cancel = context.WithDeadline(current, until)
	} else {
		ctx, cancel = context.WithCancel(current)
	}
	joined := make(chan struct{})
	stop := context.AfterFunc(c.owner, func() { cancel(); close(joined) })
	c.active = make(chan struct{})
	c.mu.Unlock()
	defer func() {
		// Detach and join the cancellation callback before releasing this call.
		if !stop() {
			<-joined
		}
		c.mu.Lock()
		if c.closed {
			err = ErrCursorClosed
		} else if ownerErr := cursorContextError(c.owner); ownerErr != nil {
			err = ownerErr
		} else if callErr := cursorContextError(ctx); callErr != nil {
			err = callErr
		}
		cancel()
		if err != nil {
			clear(out.Bytes)
			out.Bytes, out.Final, out.FullVerified = nil, false, false
			c.failed = err
			c.release()
		} else if out.Final {
			c.done = true
			c.release()
		}
		close(c.active)
		c.active = nil
		c.mu.Unlock()
	}()
	return c.next(ctx)
}

func (c *Cursor) next(ctx context.Context) (out Chunk, err error) {
	if c.plain == nil {
		if err = c.loadFrame(ctx, &out.Work); err != nil {
			return out, err
		}
	}
	if err = cursorContextError(ctx); err != nil {
		return out, err
	}
	n := min(int64(artifact.DeliveryBytes), c.frameEnd-c.frameAt)
	out.Final = c.delivered+n == c.size
	if n < 0 || (n == 0 && c.size != 0) || c.delivered+n > c.size {
		return out, artifact.ErrIntegrity
	}
	if out.Final && c.full {
		l := c.reader.layout
		if !bytes.Equal(c.nativeHash.Sum(nil), l.NativeSHA256[:]) || !bytes.Equal(c.dataHash.Sum(nil), l.DataSHA256[:]) || !bytes.Equal(c.indexHash.Sum(nil), l.IndexSHA256[:]) {
			return out, artifact.ErrIntegrity
		}
		out.FullVerified = true
	}
	out.Bytes = append([]byte(nil), c.plain[c.frameAt:c.frameAt+n]...)
	c.frameAt += n
	c.delivered += n
	if c.frameAt == c.frameEnd {
		clear(c.plain)
		c.plain = nil
	}
	return out, nil
}

func (c *Cursor) loadFrame(ctx context.Context, work *artifact.FramedReadWork) error {
	l := c.reader.layout
	end := c.offset + c.size
	for {
		if err := cursorContextError(ctx); err != nil {
			return err
		}
		if c.frameNext == len(c.frames) {
			c.frames, c.frameNext = nil, 0
			if c.pageNext == len(l.Pages) {
				return artifact.ErrIntegrity
			}
			p := l.Pages[c.pageNext]
			c.pageNext++
			if !c.full && (p.NativeOffset >= end || p.NativeOffset+p.NativeBytes <= c.offset) {
				continue
			}
			work.Pages++
			work.IndexBytes += p.IndexBytes
			pg, cipher, err := c.reader.readPage(ctx, p)
			if err != nil {
				return err
			}
			if c.full {
				c.indexHash.Write(cipher)
			}
			c.frames, c.frameNext = pg.Frames, 0
		}
		f := c.frames[c.frameNext]
		c.frameNext++
		if !c.full && (f.NativeOffset >= end || f.NativeOffset+f.NativeBytes <= c.offset) {
			continue
		}
		if err := cursorContextError(ctx); err != nil {
			return err
		}
		work.Frames++
		work.DataBytes += f.DataBytes
		cipher, err := c.reader.data.ReadRange(ctx, f.DataOffset, f.DataBytes)
		if err != nil {
			return err
		}
		if err = cursorContextError(ctx); err != nil {
			return err
		}
		if int64(len(cipher)) != f.DataBytes || !checkHash(cipher, f.DataSHA256) {
			return artifact.ErrIntegrity
		}
		work.DecodedBytes += f.NativeBytes
		b, err := decrypt(c.reader.dataKey, cipher, aad(l.Binding, "data", f.Sequence, f.NativeOffset, f.NativeBytes, f.Codec), artifact.FrameBytes)
		if err != nil {
			return err
		}
		plain := b
		if f.Codec == "zstd" {
			plain, err = c.decoder.DecodeAll(b, make([]byte, 0, int(f.NativeBytes)))
			clear(b)
			if err != nil {
				clear(plain)
				return artifact.ErrIntegrity
			}
		}
		if int64(len(plain)) != f.NativeBytes || !checkHash(plain, f.NativeSHA256) {
			clear(plain)
			return artifact.ErrIntegrity
		}
		if err = cursorContextError(ctx); err != nil {
			clear(plain)
			return err
		}
		if c.full {
			c.nativeHash.Write(plain)
			c.dataHash.Write(cipher)
		}
		c.plain = plain
		c.frameAt = max(c.offset, f.NativeOffset) - f.NativeOffset
		c.frameEnd = min(end, f.NativeOffset+f.NativeBytes) - f.NativeOffset
		return nil
	}
}

// release is called only after any admitted synchronous read has returned and
// while mu is held. Returned Chunk buffers remain independently caller-owned.
func (c *Cursor) release() {
	clear(c.plain)
	c.plain, c.frames, c.reader = nil, nil, nil
	c.nativeHash, c.dataHash, c.indexHash = nil, nil, nil
	if c.decoder != nil {
		c.decoder.Close()
		c.decoder = nil
	}
}

func (c *Cursor) Close() {
	c.mu.Lock()
	c.closed = true
	c.cancel()
	active := c.active
	c.mu.Unlock()
	if active != nil {
		<-active
	}
	c.mu.Lock()
	c.release()
	c.mu.Unlock()
}
