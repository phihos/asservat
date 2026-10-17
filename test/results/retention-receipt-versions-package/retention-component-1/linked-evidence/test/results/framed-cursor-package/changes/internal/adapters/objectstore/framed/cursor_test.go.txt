package framed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"github.com/klauspost/compress/zstd"
)

func sumCursorWork(a *artifact.FramedReadWork, b artifact.FramedReadWork) {
	a.DataBytes += b.DataBytes
	a.IndexBytes += b.IndexBytes
	a.DecodedBytes += b.DecodedBytes
	a.Frames += b.Frames
	a.Pages += b.Pages
}

func TestCursorSequentialPullsKeepOneFrameAndOriginalKeys(t *testing.T) {
	ctx := context.Background()
	native := bytes.Repeat([]byte{53}, int(artifact.FrameBytes)+57)
	l, key, data, index := encode(t, native)
	k := &countingKeys{testKeys: key}
	r, err := Open(ctx, l, k, data, index)
	if err != nil {
		t.Fatal(err)
	}
	owner, cancelOwner := context.WithTimeout(ctx, time.Minute)
	defer cancelOwner()
	c, err := r.Cursor(owner, 0, l.NativeBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if data.reads != 0 || index.reads != 0 || k.unwraps != 2 {
		t.Fatal("cursor construction read objects or opened more keys")
	}
	var out []byte
	var work artifact.FramedReadWork
	for call := 0; ; call++ {
		current, cancel := context.WithTimeout(ctx, 5*time.Second)
		chunk, err := c.Next(current)
		cancel() // A completed call must not cancel the next successful pull.
		if err != nil || len(chunk.Bytes) > artifact.DeliveryBytes {
			t.Fatalf("pull %d: bytes=%d err=%v", call, len(chunk.Bytes), err)
		}
		if call > 0 && call < int(artifact.FrameBytes)/artifact.DeliveryBytes && chunk.Work != (artifact.FramedReadWork{}) {
			t.Fatalf("reread retained frame at pull %d: %+v", call, chunk.Work)
		}
		out = append(out, chunk.Bytes...)
		clear(chunk.Bytes)
		sumCursorWork(&work, chunk.Work)
		if chunk.Final {
			if !chunk.FullVerified {
				t.Fatal("full-file final hashes not verified")
			}
			break
		}
	}
	if !bytes.Equal(out, native) || data.reads != 2 || index.reads != 1 || k.unwraps != 2 {
		t.Fatalf("body/read/key mismatch: data=%d index=%d keys=%d", data.reads, index.reads, k.unwraps)
	}
	bound, err := l.RangeReadWork(0, l.NativeBytes)
	if err != nil || work != bound || work.DataBytes != data.bytes || work.IndexBytes != index.bytes {
		t.Fatalf("full work=%+v bound=%+v err=%v", work, bound, err)
	}
	if _, err := c.Next(ctx); !errors.Is(err, io.EOF) {
		t.Fatalf("completed cursor: %v", err)
	}
	if c.reader != nil || c.plain != nil || c.frames != nil || c.decoder != nil {
		t.Fatal("completed cursor retained frame/decoder/reader")
	}
}

func TestCursorFinalIntegrityAndPartialRangeClaims(t *testing.T) {
	native := bytes.Repeat([]byte{97}, 2*artifact.DeliveryBytes+29)
	original, key, data, index := encode(t, native)
	for _, name := range []string{"native", "data", "index"} {
		t.Run(name, func(t *testing.T) {
			l := original
			switch name {
			case "native":
				l.NativeSHA256[0] ^= 1
			case "data":
				l.DataSHA256[0] ^= 1
			case "index":
				l.IndexSHA256[0] ^= 1
			}
			r := open(t, l, key, data, index)
			c, err := r.Cursor(context.Background(), 0, l.NativeBytes)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			var delivered int
			for {
				chunk, err := c.Next(context.Background())
				if err != nil {
					if !errors.Is(err, artifact.ErrIntegrity) || len(chunk.Bytes) != 0 || chunk.Final || chunk.FullVerified {
						t.Fatalf("invalid failed final: %+v %v", chunk, err)
					}
					break
				}
				delivered += len(chunk.Bytes)
				clear(chunk.Bytes)
			}
			if delivered != 2*artifact.DeliveryBytes {
				t.Fatalf("last bytes escaped: %d", delivered)
			}
			if _, err := c.Next(context.Background()); !errors.Is(err, artifact.ErrIntegrity) {
				t.Fatal("failed cursor revived", err)
			}
			// Partial ranges cannot verify these whole-object hashes and must not
			// claim to have done so; selected frame authentication remains required.
			partial, err := r.Cursor(context.Background(), 7, 17)
			if err != nil {
				t.Fatal(err)
			}
			defer partial.Close()
			chunk, err := partial.Next(context.Background())
			if err != nil || !chunk.Final || chunk.FullVerified || !bytes.Equal(chunk.Bytes, native[7:24]) {
				t.Fatalf("partial claim: %+v %v", chunk, err)
			}
			clear(chunk.Bytes)
		})
	}
}

func TestCursorEmptyFileStillReturnsAuthenticatedFinal(t *testing.T) {
	l, k, d, i := encode(t, nil)
	c, err := open(t, l, k, d, i).Cursor(context.Background(), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	chunk, err := c.Next(context.Background())
	if err != nil || len(chunk.Bytes) != 0 || !chunk.Final || !chunk.FullVerified || chunk.Work.Frames != 1 || chunk.Work.Pages != 1 || d.reads != 1 || i.reads != 1 {
		t.Fatalf("empty result=%+v err=%v", chunk, err)
	}
}

type cursorHeldSource struct {
	*source
	entered, canceled, release chan struct{}
	until                      time.Time
	calls                      atomic.Int32
	released                   sync.Once
}

func (s *cursorHeldSource) unblock() { s.released.Do(func() { close(s.release) }) }
func (s *cursorHeldSource) ReadRange(ctx context.Context, off, n int64) ([]byte, error) {
	s.calls.Add(1)
	s.until, _ = ctx.Deadline()
	close(s.entered)
	<-ctx.Done()
	close(s.canceled)
	<-s.release // Simulate a source still unwinding after cancellation.
	// A provider can return bytes despite cancellation; the cursor must reject.
	return s.source.ReadRange(context.Background(), off, n)
}

func TestCursorCloseCancelsAndJoinsPendingRead(t *testing.T) {
	l, k, data, index := encode(t, []byte("synthetic cursor cancellation"))
	held := &cursorHeldSource{source: data, entered: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{})}
	r, err := Open(context.Background(), l, k, held, index)
	if err != nil {
		t.Fatal(err)
	}
	owner, stopOwner := context.WithTimeout(context.Background(), time.Minute)
	defer stopOwner()
	c, err := r.Cursor(owner, 0, l.NativeBytes)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { held.unblock(); c.Close() })
	finished := make(chan error, 1)
	go func() {
		chunk, err := c.Next(context.Background())
		if len(chunk.Bytes) != 0 || chunk.Final {
			finished <- errors.New("returned canceled plaintext")
			return
		}
		finished <- err
	}()
	select {
	case <-held.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("read not entered")
	}
	want, _ := owner.Deadline()
	if !held.until.Equal(want) {
		t.Fatalf("owner deadline lost: %s %s", held.until, want)
	}
	if _, err := c.Next(context.Background()); !errors.Is(err, ErrCursorBusy) {
		t.Fatal("concurrent read", err)
	}
	closed := make(chan struct{})
	go func() { c.Close(); close(closed) }()
	select {
	case <-held.canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("read not canceled")
	}
	select {
	case <-closed:
		t.Fatal("Close did not join actual source return")
	default:
	}
	held.unblock()
	select {
	case err := <-finished:
		if !errors.Is(err, ErrCursorClosed) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("read did not finish")
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not finish")
	}
	if _, err := c.Next(context.Background()); !errors.Is(err, ErrCursorClosed) || held.calls.Load() != 1 {
		t.Fatal("closed cursor reread", err)
	}
	c.Close()
}

func TestCursorCurrentCallExpiryCannotBeRenewedAfterAdmittedRead(t *testing.T) {
	l, k, data, index := encode(t, []byte("synthetic expired call"))
	held := &cursorHeldSource{source: data, entered: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{})}
	r, err := Open(context.Background(), l, k, held, index)
	if err != nil {
		t.Fatal(err)
	}
	c, err := r.Cursor(context.Background(), 0, l.NativeBytes)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { held.unblock(); c.Close() })
	current, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	type result struct {
		chunk Chunk
		err   error
	}
	finished := make(chan result, 1)
	go func() { chunk, err := c.Next(current); finished <- result{chunk, err} }()
	select {
	case <-held.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("read not entered")
	}
	want, _ := current.Deadline()
	if !held.until.Equal(want) {
		t.Fatal("current call deadline changed")
	}
	select {
	case <-held.canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("call expiry not delivered")
	}
	held.unblock()
	var got result
	select {
	case got = <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("expired source read did not finish")
	}
	if !errors.Is(got.err, context.DeadlineExceeded) || len(got.chunk.Bytes) != 0 || got.chunk.Work.DataBytes != l.DataBytes || got.chunk.Work.DecodedBytes != 0 {
		t.Fatalf("expired work escaped/reset: %+v %v", got.chunk, got.err)
	}
	if _, err := c.Next(context.Background()); !errors.Is(err, context.DeadlineExceeded) || held.calls.Load() != 1 {
		t.Fatal("fresh call revived expired cursor", err)
	}
}

func TestCursorCanceledOwnerDeniesRetainedFrameWithoutMoreIO(t *testing.T) {
	l, k, data, index := encode(t, bytes.Repeat([]byte{8}, 2*artifact.DeliveryBytes))
	owner, cancel := context.WithCancel(context.Background())
	c, err := open(t, l, k, data, index).Cursor(owner, 0, l.NativeBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	chunk, err := c.Next(context.Background())
	if err != nil || chunk.Final {
		t.Fatal(err)
	}
	clear(chunk.Bytes)
	cancel()
	if chunk, err := c.Next(context.Background()); !errors.Is(err, context.Canceled) || len(chunk.Bytes) != 0 || data.reads != 1 || index.reads != 1 {
		t.Fatal("owner canceled but retained plaintext escaped", err)
	}
}

func TestCursorCanceledCallBeforeAdmissionDoesNotConsume(t *testing.T) {
	l, k, data, index := encode(t, []byte("synthetic"))
	c, err := open(t, l, k, data, index).Cursor(context.Background(), 0, l.NativeBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Next(ctx); !errors.Is(err, context.Canceled) || data.reads != 0 || index.reads != 0 {
		t.Fatal("canceled admission worked", err)
	}
	chunk, err := c.Next(context.Background())
	if err != nil || !chunk.Final {
		t.Fatal("no-work rejection consumed cursor", err)
	}
	clear(chunk.Bytes)
}

// This sparse synthetic encrypted layout covers a page boundary without
// generating a 2 GiB file. Only the two selected frames have real ciphertext;
// unselected frames are structural placeholders, never full-file evidence.
func TestCursorRangeCrossesAuthenticatedIndexPageBoundary(t *testing.T) {
	ctx := context.Background()
	k := keys(t)
	e, err := Prepare(ctx, testBinding, k)
	if err != nil {
		t.Fatal(err)
	}
	z, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1), zstd.WithWindowSize(int(artifact.FrameBytes)))
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	l := artifact.Layout{Format: artifact.StorageFormat, Binding: testBinding, NativeBytes: artifact.FrameBytes*artifact.FramesPerPage + 13, DataKey: e.dataKey, IndexKey: e.indexKey}
	var data, index bytes.Buffer
	for pageNumber := 0; pageNumber < 2; pageNumber++ {
		count := artifact.FramesPerPage
		if pageNumber == 1 {
			count = 1
		}
		p := artifact.Page{Number: pageNumber, FirstFrame: pageNumber * artifact.FramesPerPage, FrameCount: count, NativeOffset: int64(pageNumber) * artifact.FrameBytes * artifact.FramesPerPage, DataOffset: int64(data.Len()), IndexOffset: int64(index.Len())}
		pg := page{Format: artifact.StorageFormat, Number: pageNumber}
		for j := 0; j < count; j++ {
			sequence := p.FirstFrame + j
			nativeBytes := min(artifact.FrameBytes, l.NativeBytes-int64(sequence)*artifact.FrameBytes)
			f := frame{Sequence: sequence, NativeOffset: int64(sequence) * artifact.FrameBytes, NativeBytes: nativeBytes, DataOffset: int64(data.Len()), DataBytes: 1, Codec: "identity", NativeSHA256: hashString(artifact.Digest{}), DataSHA256: hashString(artifact.Digest{})}
			if sequence >= artifact.FramesPerPage-1 {
				plain := bytes.Repeat([]byte{byte(sequence)}, int(nativeBytes))
				payload := plain
				if nativeBytes == artifact.FrameBytes {
					payload = z.EncodeAll(plain, nil)
					f.Codec = "zstd"
				}
				cipher, err := encrypt(e.data, payload, aad(l.Binding, "data", sequence, f.NativeOffset, nativeBytes, f.Codec))
				if err != nil {
					t.Fatal(err)
				}
				f.DataBytes, f.NativeSHA256, f.DataSHA256 = int64(len(cipher)), hashString(digest(plain)), hashString(digest(cipher))
				data.Write(cipher)
				clear(plain)
				clear(payload)
			} else {
				data.WriteByte(0)
			}
			pg.Frames = append(pg.Frames, f)
			p.NativeBytes += nativeBytes
			p.DataBytes += f.DataBytes
		}
		body, err := json.Marshal(pg)
		if err != nil {
			t.Fatal(err)
		}
		cipher, err := encrypt(e.index, body, aad(l.Binding, "index", p.Number, p.NativeOffset, p.NativeBytes, "json"))
		if err != nil {
			t.Fatal(err)
		}
		p.IndexBytes, p.IndexSHA256 = int64(len(cipher)), digest(cipher)
		index.Write(cipher)
		l.Pages = append(l.Pages, p)
	}
	l.DataBytes, l.IndexBytes = int64(data.Len()), int64(index.Len())
	d, i := &source{b: data.Bytes()}, &source{b: index.Bytes()}
	r := open(t, l, k, d, i)
	offset := artifact.FrameBytes*artifact.FramesPerPage - 7
	c, err := r.Cursor(ctx, offset, 15)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var out []byte
	var work artifact.FramedReadWork
	for {
		chunk, err := c.Next(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if chunk.FullVerified {
			t.Fatal("range claimed full-file integrity")
		}
		out = append(out, chunk.Bytes...)
		clear(chunk.Bytes)
		sumCursorWork(&work, chunk.Work)
		if chunk.Final {
			break
		}
	}
	want := append(bytes.Repeat([]byte{255}, 7), make([]byte, 8)...)
	bound, err := l.RangeReadWork(offset, 15)
	if err != nil || !bytes.Equal(out, want) || work.DataBytes > bound.DataBytes || work.IndexBytes != bound.IndexBytes || work.DecodedBytes != artifact.FrameBytes+13 || work.Frames != 2 || work.Pages != 2 || d.reads != 2 || i.reads != 2 {
		t.Fatalf("range=%v work=%+v bound=%+v err=%v", out, work, bound, err)
	}
}

type cursorUncertainSource struct {
	*source
	calls int
}

func (s *cursorUncertainSource) ReadRange(ctx context.Context, off, n int64) ([]byte, error) {
	s.calls++
	if s.calls == 1 {
		return nil, io.ErrUnexpectedEOF
	}
	return s.source.ReadRange(ctx, off, n)
}

func TestCursorUncertainReadRetainsAttemptAndCannotRetry(t *testing.T) {
	l, k, data, index := encode(t, []byte("synthetic unknown read"))
	uncertain := &cursorUncertainSource{source: data}
	r, err := Open(context.Background(), l, k, uncertain, index)
	if err != nil {
		t.Fatal(err)
	}
	c, err := r.Cursor(context.Background(), 0, l.NativeBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	chunk, err := c.Next(context.Background())
	if !errors.Is(err, io.ErrUnexpectedEOF) || len(chunk.Bytes) != 0 || chunk.Final || chunk.Work.DataBytes != l.DataBytes || chunk.Work.IndexBytes != l.IndexBytes || chunk.Work.DecodedBytes != 0 {
		t.Fatalf("unknown attempt: %+v err=%v", chunk, err)
	}
	repeated, err := c.Next(context.Background())
	if !errors.Is(err, io.ErrUnexpectedEOF) || uncertain.calls != 1 || index.reads != 1 || repeated.Work != (artifact.FramedReadWork{}) {
		t.Fatal("uncertain operation silently repeated", err)
	}
}
