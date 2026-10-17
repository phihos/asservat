package framed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sync/atomic"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/klauspost/compress/zstd"
	"github.com/tink-crypto/tink-go/v2/tink"
)

type frame struct {
	Sequence     int    `json:"sequence"`
	NativeOffset int64  `json:"nativeOffset"`
	NativeBytes  int64  `json:"nativeBytes"`
	DataOffset   int64  `json:"dataOffset"`
	DataBytes    int64  `json:"dataBytes"`
	Codec        string `json:"codec"`
	NativeSHA256 string `json:"nativeSHA256"`
	DataSHA256   string `json:"dataSHA256"`
}

type page struct {
	Format string  `json:"format"`
	Number int     `json:"number"`
	Frames []frame `json:"frames"`
}

type Encoder struct {
	binding           artifact.Binding
	data, index       tink.StreamingAEAD
	dataKey, indexKey artifact.SealedKey
	used              atomic.Bool
}

var _ evidence.StorageEncoder = (*Encoder)(nil)

// Prepare wraps both fresh keys before the source may be opened. An Encoder is
// single use, including after a failed write. Retries need a fresh attempt ID.
func Prepare(ctx context.Context, binding artifact.Binding, sealer evidence.KeySealer) (*Encoder, error) {
	if err := binding.Validate(); err != nil {
		return nil, err
	}
	if sealer == nil {
		return nil, artifact.ErrInvalid
	}
	e := &Encoder{binding: binding}
	var err error
	e.data, e.dataKey, err = newKey(ctx, sealer, aad(binding, "data-key", 0, 0, 0, "none"))
	if err != nil {
		return nil, err
	}
	e.index, e.indexKey, err = newKey(ctx, sealer, aad(binding, "index-key", 0, 0, 0, "none"))
	if err != nil {
		return nil, err
	}
	for _, k := range []artifact.SealedKey{e.dataKey, e.indexKey} {
		if len(k.Reference) < 1 || len(k.Reference) > 256 || len(k.Ciphertext) < 1 || len(k.Ciphertext) > 16384 {
			return nil, artifact.ErrInvalid
		}
	}
	return e, nil
}

func (e *Encoder) Encode(ctx context.Context, src io.Reader, data, index io.Writer, limit int64) (artifact.Layout, error) {
	if src == nil || data == nil || index == nil || limit < 0 || limit > artifact.MaxNativeBytes || !e.used.CompareAndSwap(false, true) {
		return artifact.Layout{}, artifact.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return artifact.Layout{}, err
	}
	l := artifact.Layout{Format: artifact.StorageFormat, Binding: e.binding, DataKey: e.dataKey, IndexKey: e.indexKey}
	nativeHash, dataHash, indexHash := sha256.New(), sha256.New(), sha256.New()
	data = io.MultiWriter(data, dataHash)
	index = io.MultiWriter(index, indexHash)
	z, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1), zstd.WithWindowSize(int(artifact.FrameBytes)), zstd.WithEncoderLevel(zstd.SpeedFastest), zstd.WithEncoderCRC(true))
	if err != nil {
		return artifact.Layout{}, err
	}
	defer z.Close()
	buf := make([]byte, artifact.FrameBytes)
	defer clear(buf)
	pg := page{Format: artifact.StorageFormat, Frames: make([]frame, 0, artifact.FramesPerPage)}
	flush := func() error {
		first, last := pg.Frames[0], pg.Frames[len(pg.Frames)-1]
		p := artifact.Page{Number: pg.Number, FirstFrame: first.Sequence, FrameCount: len(pg.Frames), NativeOffset: first.NativeOffset, NativeBytes: last.NativeOffset + last.NativeBytes - first.NativeOffset, DataOffset: first.DataOffset, DataBytes: last.DataOffset + last.DataBytes - first.DataOffset, IndexOffset: l.IndexBytes}
		b, err := json.Marshal(pg)
		if err != nil || int64(len(b)) > artifact.PageBytes {
			return artifact.ErrLimit
		}
		defer clear(b)
		c, err := encrypt(e.index, b, aad(e.binding, "index", p.Number, p.NativeOffset, p.NativeBytes, "json"))
		if err != nil {
			return err
		}
		if int64(len(c)) > artifact.PageBytes+artifact.CipherOverhead {
			return artifact.ErrLimit
		}
		p.IndexBytes, p.IndexSHA256 = int64(len(c)), digest(c)
		if err := writeAll(index, c); err != nil {
			return err
		}
		l.IndexBytes += int64(len(c))
		l.Pages = append(l.Pages, p)
		pg.Number++
		pg.Frames = pg.Frames[:0]
		return nil
	}
	for seq := 0; ; seq++ {
		if err := ctx.Err(); err != nil {
			return artifact.Layout{}, err
		}
		// At most one overflow byte is read to detect an over-limit producer;
		// it is never retained or emitted. Acquisition adapters have their own
		// stricter source/output bounds and cancellation obligations.
		n, readErr := io.ReadFull(src, buf[:min(artifact.FrameBytes, limit-l.NativeBytes+1)])
		if readErr != nil && !errors.Is(readErr, io.EOF) && !errors.Is(readErr, io.ErrUnexpectedEOF) {
			return artifact.Layout{}, readErr
		}
		if l.NativeBytes+int64(n) > limit {
			return artifact.Layout{}, artifact.ErrLimit
		}
		if n == 0 && seq != 0 {
			break
		}
		if seq >= artifact.MaxFrames {
			return artifact.Layout{}, artifact.ErrLimit
		}
		plain := buf[:n]
		nativeHash.Write(plain)
		compressed := z.EncodeAll(plain, nil)
		codec, payload := "identity", plain
		if len(compressed) < len(plain) {
			codec, payload = "zstd", compressed
		}
		c, err := encrypt(e.data, payload, aad(e.binding, "data", seq, l.NativeBytes, int64(n), codec))
		clear(compressed)
		if err != nil {
			return artifact.Layout{}, err
		}
		if int64(len(c)) > int64(n)+artifact.CipherOverhead {
			return artifact.Layout{}, artifact.ErrLimit
		}
		nh, ch := digest(plain), digest(c)
		f := frame{seq, l.NativeBytes, int64(n), l.DataBytes, int64(len(c)), codec, hex.EncodeToString(nh[:]), hex.EncodeToString(ch[:])}
		if err := writeAll(data, c); err != nil {
			return artifact.Layout{}, err
		}
		pg.Frames = append(pg.Frames, f)
		l.NativeBytes += int64(n)
		l.DataBytes += int64(len(c))
		if len(pg.Frames) == artifact.FramesPerPage {
			if err := flush(); err != nil {
				return artifact.Layout{}, err
			}
		}
		if readErr != nil {
			break
		}
	}
	if len(pg.Frames) != 0 {
		if err := flush(); err != nil {
			return artifact.Layout{}, err
		}
	}
	copy(l.NativeSHA256[:], nativeHash.Sum(nil))
	copy(l.DataSHA256[:], dataHash.Sum(nil))
	copy(l.IndexSHA256[:], indexHash.Sum(nil))
	if err := l.Validate(); err != nil {
		return artifact.Layout{}, err
	}
	return l, nil
}
