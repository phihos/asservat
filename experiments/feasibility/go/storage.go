// Package feasibility contains disposable experiments, not production storage code.
package feasibility

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/klauspost/compress/zstd"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/streamingaead"
	"github.com/tink-crypto/tink-go/v2/tink"
	"io"
	"os"
	"sync/atomic"
)

const MiB = 1 << 20
const MaxNative = 4 << 30 // experiment ceiling, not a product maximum
var ErrDenied = errors.New("delivery denied")

func hash(b []byte) string { x := sha256.Sum256(b); return hex.EncodeToString(x[:]) }
func primitive() (tink.StreamingAEAD, error) {
	k, e := keyset.NewHandle(streamingaead.AES256GCMHKDF1MBKeyTemplate())
	if e != nil {
		return nil, e
	}
	return streamingaead.New(k)
}

type Frame struct {
	NativeOffset, NativeBytes, CipherOffset, CipherBytes int64
	NativeSHA, CipherSHA                                 string
}
type Index struct {
	Format, ID               string
	NativeBytes, CipherBytes int64
	NativeSHA, CipherSHA     string
	Frames                   []Frame
}
type Bundle struct {
	ID, DataETag, IndexETag, IndexSHA string
	IndexBytes                        int64
	DataKey, IndexKey                 tink.StreamingAEAD
}
type Store struct {
	Client    *s3.Client
	Bucket    string
	ReadBytes atomic.Int64
}

func NewStore(endpoint, bucket string) *Store {
	c := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String(endpoint), UsePathStyle: true, Credentials: credentials.NewStaticCredentialsProvider("synthetic-only", "synthetic-only-secret", ""), RetryMaxAttempts: 1})
	return &Store{Client: c, Bucket: bucket}
}
func (s *Store) put(ctx context.Context, key string, b []byte) (string, error) {
	o, e := s.Client.PutObject(ctx, &s3.PutObjectInput{Bucket: &s.Bucket, Key: &key, Body: bytes.NewReader(b)})
	if e != nil {
		return "", e
	}
	return aws.ToString(o.ETag), nil
}
func (s *Store) get(ctx context.Context, key, etag string, start, n int64) ([]byte, error) {
	if start < 0 || n < 1 || n > 40*MiB {
		return nil, errors.New("range bound")
	}
	r := fmt.Sprintf("bytes=%d-%d", start, start+n-1)
	o, e := s.Client.GetObject(ctx, &s3.GetObjectInput{Bucket: &s.Bucket, Key: &key, Range: &r, IfMatch: &etag})
	if e != nil {
		return nil, e
	}
	defer o.Body.Close()
	b, e := io.ReadAll(io.LimitReader(o.Body, n+1))
	s.ReadBytes.Add(int64(len(b)))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) != n {
		return nil, errors.New("range length mismatch")
	}
	return b, nil
}
func (s *Store) multipart(ctx context.Context, key string, r io.Reader) (etag string, err error) {
	init, e := s.Client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: &s.Bucket, Key: &key})
	if e != nil {
		return "", e
	}
	done := false
	defer func() {
		if !done {
			_, _ = s.Client.AbortMultipartUpload(context.Background(), &s3.AbortMultipartUploadInput{Bucket: &s.Bucket, Key: &key, UploadId: init.UploadId})
		}
	}()
	var parts []types.CompletedPart
	buf := make([]byte, 8*MiB)
	for number := int32(1); ; number++ {
		n, e := io.ReadFull(r, buf)
		if e != nil && e != io.EOF && e != io.ErrUnexpectedEOF {
			return "", e
		}
		if n == 0 {
			break
		}
		p, err := s.Client.UploadPart(ctx, &s3.UploadPartInput{Bucket: &s.Bucket, Key: &key, UploadId: init.UploadId, PartNumber: &number, Body: bytes.NewReader(buf[:n])})
		if err != nil {
			return "", err
		}
		partNumber := number
		parts = append(parts, types.CompletedPart{ETag: p.ETag, PartNumber: &partNumber})
		if e != nil {
			break
		}
	}
	out, e := s.Client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{Bucket: &s.Bucket, Key: &key, UploadId: init.UploadId, MultipartUpload: &types.CompletedMultipartUpload{Parts: parts}})
	if e != nil {
		return "", e
	}
	done = true
	return aws.ToString(out.ETag), nil
}
func frameAAD(id string, i int, off int64) []byte {
	return []byte(fmt.Sprintf("experiment/v1/%s/frame/%d/native/%d", id, i, off))
}
func encrypt(a tink.StreamingAEAD, b, aad []byte) ([]byte, error) {
	var out bytes.Buffer
	w, e := a.NewEncryptingWriter(&out, aad)
	if e != nil {
		return nil, e
	}
	if _, e = w.Write(b); e != nil {
		return nil, e
	}
	if e = w.Close(); e != nil {
		return nil, e
	}
	return out.Bytes(), nil
}
func decrypt(a tink.StreamingAEAD, b, aad []byte, limit int64) ([]byte, error) {
	r, e := a.NewDecryptingReader(bytes.NewReader(b), aad)
	if e != nil {
		return nil, e
	}
	v, e := io.ReadAll(io.LimitReader(r, limit+1))
	if e != nil {
		return nil, e
	}
	if int64(len(v)) > limit {
		return nil, errors.New("decryption bound")
	}
	return v, nil
}
func (s *Store) Encode(ctx context.Context, id string, src io.Reader, chunk int, tempdir string) (bundle Bundle, idx Index, err error) {
	if chunk < 64*1024 || chunk > 32*MiB {
		return bundle, idx, errors.New("frame size bound")
	}
	bundle.ID = id
	bundle.DataKey, err = primitive()
	if err != nil {
		return
	}
	bundle.IndexKey, err = primitive()
	if err != nil {
		return
	}
	f, err := os.CreateTemp(tempdir, "cipher-only-*")
	if err != nil {
		return
	}
	defer os.Remove(f.Name())
	defer f.Close()
	idx = Index{Format: "experiment-independent-tink-frames/v1", ID: id}
	nativeHash, cipherHash := sha256.New(), sha256.New()
	buf := make([]byte, chunk)
	z, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1), zstd.WithEncoderLevel(zstd.SpeedFastest))
	if err != nil {
		return
	}
	defer z.Close()
	for i := 0; ; i++ {
		if err = ctx.Err(); err != nil {
			return
		}
		var n int
		n, err = io.ReadFull(src, buf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return
		}
		if n == 0 {
			err = nil
			break
		}
		err = nil
		if idx.NativeBytes+int64(n) > MaxNative || i >= 16384 {
			err = errors.New("artifact bound")
			return
		}
		p := buf[:n]
		nativeHash.Write(p)
		c, e := encrypt(bundle.DataKey, z.EncodeAll(p, nil), frameAAD(id, i, idx.NativeBytes))
		if e != nil {
			err = e
			return
		}
		if _, err = f.Write(c); err != nil {
			return
		}
		cipherHash.Write(c)
		idx.Frames = append(idx.Frames, Frame{idx.NativeBytes, int64(n), idx.CipherBytes, int64(len(c)), hash(p), hash(c)})
		idx.NativeBytes += int64(n)
		idx.CipherBytes += int64(len(c))
	}
	idx.NativeSHA = hex.EncodeToString(nativeHash.Sum(nil))
	idx.CipherSHA = hex.EncodeToString(cipherHash.Sum(nil))
	if len(idx.Frames) == 0 {
		err = errors.New("empty artifact outside experiment")
		return
	}
	if _, err = f.Seek(0, 0); err != nil {
		return
	}
	bundle.DataETag, err = s.multipart(ctx, id+"/data", f)
	if err != nil {
		return
	}
	b, err := json.Marshal(idx)
	if err != nil {
		return
	}
	if len(b) > MiB {
		err = errors.New("index bound")
		return
	}
	c, err := encrypt(bundle.IndexKey, b, []byte("experiment/v1/"+id+"/index"))
	if err != nil {
		return
	}
	bundle.IndexBytes = int64(len(c))
	bundle.IndexSHA = hash(c)
	bundle.IndexETag, err = s.put(ctx, id+"/index", c)
	return
}
func validateIndex(idx Index, id string) error {
	if idx.Format != "experiment-independent-tink-frames/v1" || idx.ID != id || len(idx.Frames) < 1 || len(idx.Frames) > 16384 || idx.NativeBytes > MaxNative {
		return errors.New("index identity/size")
	}
	var n, c int64
	for _, f := range idx.Frames {
		if f.NativeOffset != n || f.CipherOffset != c || f.NativeBytes < 1 || f.NativeBytes > 32*MiB || f.CipherBytes < 1 || f.CipherBytes > 40*MiB || len(f.NativeSHA) != 64 || len(f.CipherSHA) != 64 {
			return errors.New("invalid frame index")
		}
		n += f.NativeBytes
		c += f.CipherBytes
	}
	if n != idx.NativeBytes || c != idx.CipherBytes {
		return errors.New("index coverage")
	}
	return nil
}
func (s *Store) Open(ctx context.Context, b Bundle) (Index, error) {
	var idx Index
	if b.IndexBytes < 1 || b.IndexBytes > 2*MiB {
		return idx, errors.New("encrypted index bound")
	}
	c, e := s.get(ctx, b.ID+"/index", b.IndexETag, 0, b.IndexBytes)
	if e != nil {
		return idx, e
	}
	if hash(c) != b.IndexSHA {
		return idx, errors.New("index digest")
	}
	p, e := decrypt(b.IndexKey, c, []byte("experiment/v1/"+b.ID+"/index"), MiB)
	if e != nil {
		return idx, e
	}
	if !jsontext.Value(p).IsValid() {
		return idx, errors.New("invalid index JSON")
	}
	d := json.NewDecoder(bytes.NewReader(p))
	d.DisallowUnknownFields()
	if e = d.Decode(&idx); e != nil {
		return idx, e
	}
	return idx, validateIndex(idx, b.ID)
}
func (s *Store) Range(ctx context.Context, b Bundle, idx Index, start, end int64, w io.Writer, allow func(int) bool) error {
	if e := validateIndex(idx, b.ID); e != nil {
		return e
	}
	if start < 0 || end <= start || end > idx.NativeBytes {
		return errors.New("native range bound")
	}
	z, e := zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(64*MiB), zstd.WithDecoderMaxWindow(32*MiB), zstd.WithDecodeAllCapLimit(true))
	if e != nil {
		return e
	}
	defer z.Close()
	fullHash := sha256.New()
	for i, f := range idx.Frames {
		if f.NativeOffset >= end || f.NativeOffset+f.NativeBytes <= start {
			continue
		}
		if e = ctx.Err(); e != nil {
			return e
		}
		if !allow(0) {
			return ErrDenied
		}
		c, e := s.get(ctx, b.ID+"/data", b.DataETag, f.CipherOffset, f.CipherBytes)
		if e != nil {
			return e
		}
		if hash(c) != f.CipherSHA {
			return errors.New("cipher frame digest")
		}
		compressed, e := decrypt(b.DataKey, c, frameAAD(b.ID, i, f.NativeOffset), 40*MiB)
		if e != nil {
			return e
		}
		p, e := z.DecodeAll(compressed, make([]byte, 0, int(f.NativeBytes)))
		if e != nil {
			return e
		}
		if int64(len(p)) != f.NativeBytes || hash(p) != f.NativeSHA {
			return errors.New("native frame integrity")
		}
		lo, hi := max(start-f.NativeOffset, 0), min(end-f.NativeOffset, f.NativeBytes)
		out := p[lo:hi]
		for len(out) > 0 {
			if e = ctx.Err(); e != nil {
				return e
			}
			n := min(MiB, len(out))
			if !allow(n) {
				return ErrDenied
			}
			// Hold the final delivery batch until the whole-native digest is known.
			fullHash.Write(out[:n])
			finalBatch := f.NativeOffset+hi == end && len(out) == n
			if start == 0 && end == idx.NativeBytes && finalBatch && hex.EncodeToString(fullHash.Sum(nil)) != idx.NativeSHA {
				return errors.New("whole native checksum before final delivery")
			}
			written, e := w.Write(out[:n])
			if e != nil {
				return e
			}
			if written != n {
				return io.ErrShortWrite
			}
			out = out[n:]
		}
	}
	if start == 0 && end == idx.NativeBytes && hex.EncodeToString(fullHash.Sum(nil)) != idx.NativeSHA {
		return errors.New("whole native checksum")
	}
	return nil
}
