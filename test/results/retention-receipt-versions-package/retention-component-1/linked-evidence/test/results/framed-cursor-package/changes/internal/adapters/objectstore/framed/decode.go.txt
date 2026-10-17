package framed

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"io"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/tink-crypto/tink-go/v2/tink"
)

type Reader struct {
	layout            artifact.Layout
	data, index       evidence.CipherSource
	dataKey, indexKey tink.StreamingAEAD
}

// Open accepts only an authenticated committed layout obtained by the regional
// acquisition service after authorization. It does not confer read authority.
func Open(ctx context.Context, l artifact.Layout, keys evidence.KeyOpener, data, index evidence.CipherSource) (*Reader, error) {
	if err := l.Validate(); err != nil {
		return nil, err
	}
	if keys == nil || data == nil || index == nil {
		return nil, artifact.ErrInvalid
	}
	l.Pages = append([]artifact.Page(nil), l.Pages...)
	r := &Reader{layout: l, data: data, index: index}
	var err error
	r.dataKey, err = openKey(ctx, keys, l.DataKey, aad(l.Binding, "data-key", 0, 0, 0, "none"))
	if err != nil {
		return nil, err
	}
	r.indexKey, err = openKey(ctx, keys, l.IndexKey, aad(l.Binding, "index-key", 0, 0, 0, "none"))
	if err != nil {
		return nil, err
	}
	return r, nil
}

func checkHash(b []byte, h string) bool {
	v, err := hex.DecodeString(h)
	if err != nil || len(v) != 32 || hex.EncodeToString(v) != h {
		return false
	}
	x := digest(b)
	return bytes.Equal(x[:], v)
}

func (r *Reader) readPage(ctx context.Context, p artifact.Page) (page, []byte, error) {
	c, err := r.index.ReadRange(ctx, p.IndexOffset, p.IndexBytes)
	if err != nil {
		return page{}, nil, err
	}
	if err := cursorContextError(ctx); err != nil {
		return page{}, nil, err
	}
	if int64(len(c)) != p.IndexBytes || digest(c) != p.IndexSHA256 {
		return page{}, nil, artifact.ErrIntegrity
	}
	b, err := decrypt(r.indexKey, c, aad(r.layout.Binding, "index", p.Number, p.NativeOffset, p.NativeBytes, "json"), artifact.PageBytes)
	if err != nil {
		return page{}, nil, err
	}
	defer clear(b)
	// Canonicalize for strict syntax/duplicate/Unicode rejection, then use a
	// strict typed decoder. No attacker-controlled unbounded JSON tree.
	v := jsontext.Value(append([]byte(nil), b...))
	defer clear(v)
	if err := v.Canonicalize(); err != nil {
		return page{}, nil, artifact.ErrIntegrity
	}
	if pageFields(b) != nil {
		return page{}, nil, artifact.ErrIntegrity
	}
	var pg page
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&pg) != nil || pg.Format != artifact.StorageFormat || pg.Number != p.Number || len(pg.Frames) != p.FrameCount {
		return page{}, nil, artifact.ErrIntegrity
	}
	if d.Decode(new(any)) != io.EOF {
		return page{}, nil, artifact.ErrIntegrity
	}
	native, data := p.NativeOffset, p.DataOffset
	for i, f := range pg.Frames {
		if _, err := parseHash(f.NativeSHA256); err != nil {
			return page{}, nil, artifact.ErrIntegrity
		}
		if _, err := parseHash(f.DataSHA256); err != nil {
			return page{}, nil, artifact.ErrIntegrity
		}
		want := min(artifact.FrameBytes, r.layout.NativeBytes-native)
		if f.Sequence != p.FirstFrame+i || f.NativeOffset != native || f.NativeBytes != want || f.DataOffset != data || f.DataBytes < 1 || f.DataBytes > want+artifact.CipherOverhead || (f.Codec != "identity" && f.Codec != "zstd") || (want == 0 && f.Codec != "identity") || len(f.NativeSHA256) != 64 || len(f.DataSHA256) != 64 {
			return page{}, nil, artifact.ErrIntegrity
		}
		native += f.NativeBytes
		data += f.DataBytes
	}
	if native != p.NativeOffset+p.NativeBytes || data != p.DataOffset+p.DataBytes {
		return page{}, nil, artifact.ErrIntegrity
	}
	return pg, c, nil
}

// Read emits the exact native range. A full read additionally verifies whole
// data/index/native digests before its final batch. The application must reserve
// boundary-frame read/decode work and renew authority before every Send.
func (r *Reader) Read(ctx context.Context, offset, size int64, delivery evidence.Delivery) error {
	if delivery == nil {
		return artifact.ErrInvalid
	}
	cursor, err := r.Cursor(ctx, offset, size)
	if err != nil {
		return err
	}
	defer cursor.Close()
	for {
		chunk, err := cursor.Next(ctx)
		if err != nil {
			return err
		}
		if err = cursorContextError(ctx); err == nil {
			// Empty files still cross the application authorization/audit boundary.
			err = delivery.Send(ctx, chunk.Bytes)
		}
		clear(chunk.Bytes)
		if err != nil || chunk.Final {
			return err
		}
	}
}
