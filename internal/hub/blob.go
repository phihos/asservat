package hub

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// Blobs stores encrypted artifact bytes under opaque keys.
type Blobs interface {
	Put(ctx context.Context, key string, r io.Reader) error
	Get(ctx context.Context, key string) (io.ReadCloser, error)
	Delete(ctx context.Context, key string) error
}

// DirBlobs keeps blobs as files in one directory, for example a volume.
type DirBlobs string

func (d DirBlobs) Put(_ context.Context, key string, r io.Reader) error {
	f, err := os.Create(filepath.Join(string(d), key))
	if err != nil {
		return err
	}
	if _, err = io.Copy(f, r); err != nil {
		f.Close()
		os.Remove(f.Name())
		return err
	}
	return f.Close()
}

func (d DirBlobs) Get(_ context.Context, key string) (io.ReadCloser, error) {
	return os.Open(filepath.Join(string(d), key))
}

func (d DirBlobs) Delete(_ context.Context, key string) error {
	err := os.Remove(filepath.Join(string(d), key))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// S3Blobs keeps blobs in a bucket of an S3-compatible object store.
type S3Blobs struct {
	client *minio.Client
	bucket string
}

func NewS3Blobs(endpoint, bucket, accessKey, secretKey string, secure bool) (*S3Blobs, error) {
	c, err := minio.New(endpoint, &minio.Options{Creds: credentials.NewStaticV4(accessKey, secretKey, ""), Secure: secure})
	if err != nil {
		return nil, err
	}
	return &S3Blobs{client: c, bucket: bucket}, nil
}

// Check asks the server whether the bucket is there, for a hub that starts
// to say at once what every upload would otherwise fail on later.
func (s *S3Blobs) Check(ctx context.Context) error {
	exists, err := s.client.BucketExists(ctx, s.bucket)
	if err == nil && !exists {
		err = fmt.Errorf("the bucket %q does not exist", s.bucket)
	}
	return err
}

func (s *S3Blobs) Put(ctx context.Context, key string, r io.Reader) error {
	// The size is unknown while an agent still records: -1 streams multipart.
	_, err := s.client.PutObject(ctx, s.bucket, key, r, -1, minio.PutObjectOptions{})
	return err
}

func (s *S3Blobs) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	return s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
}

func (s *S3Blobs) Delete(ctx context.Context, key string) error {
	return s.client.RemoveObject(ctx, s.bucket, key, minio.RemoveObjectOptions{})
}

// Artifacts are encrypted before they reach the blob store: each one with its
// own random AES-256 key, which is stored wrapped by the hub's master key.
// The stream is a sequence of AES-GCM sealed chunks, each preceded by its
// length. The nonce counts chunks and the last chunk carries a marker as
// associated data, so reordered or truncated streams fail to open.

const chunkSize = 64 << 10

func chunkNonce(n uint64) []byte {
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], n)
	return nonce
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// wrapKey seals an artifact key with the master key.
func wrapKey(master, key []byte) ([]byte, error) {
	aead, err := newGCM(master)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, key, nil), nil
}

func unwrapKey(master, wrapped []byte) ([]byte, error) {
	aead, err := newGCM(master)
	if err != nil {
		return nil, err
	}
	if len(wrapped) < aead.NonceSize() {
		return nil, errors.New("wrapped key too short")
	}
	return aead.Open(nil, wrapped[:aead.NonceSize()], wrapped[aead.NonceSize():], nil)
}

// encrypt copies src to dst as sealed chunks.
func encrypt(dst io.Writer, src io.Reader, key []byte) error {
	aead, err := newGCM(key)
	if err != nil {
		return err
	}
	// Three buffers serve every chunk: this one, the next one, and the sealed one.
	buf, next, out := make([]byte, chunkSize), make([]byte, chunkSize), make([]byte, 0, chunkSize+aead.Overhead())
	n, err := io.ReadFull(src, buf)
	for i := uint64(0); ; i++ {
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return err
		}
		// Read ahead to learn whether this chunk is the last one.
		m, nextErr := 0, io.EOF
		if err == nil {
			m, nextErr = io.ReadFull(src, next)
		}
		last := nextErr == io.EOF
		sealed := aead.Seal(out[:0], chunkNonce(i), buf[:n], []byte{b2i(last)})
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(sealed)))
		if _, err := dst.Write(size[:]); err != nil {
			return err
		}
		if _, err := dst.Write(sealed); err != nil {
			return err
		}
		if last {
			return nil
		}
		buf, next, n, err = next, buf, m, nextErr
	}
}

// decrypt copies the opened chunks of src to dst.
func decrypt(dst io.Writer, src io.Reader, key []byte) error {
	aead, err := newGCM(key)
	if err != nil {
		return err
	}
	var size, nextSize [4]byte
	if _, err := io.ReadFull(src, size[:]); err != nil {
		return err
	}
	// One buffer serves every chunk, which is opened in place.
	buf := make([]byte, chunkSize+aead.Overhead())
	for i := uint64(0); ; i++ {
		n := binary.BigEndian.Uint32(size[:])
		if n > chunkSize+uint32(aead.Overhead()) {
			return errors.New("corrupt artifact")
		}
		sealed := buf[:n]
		if _, err := io.ReadFull(src, sealed); err != nil {
			return err
		}
		_, err := io.ReadFull(src, nextSize[:])
		last := err == io.EOF
		if err != nil && !last {
			return err
		}
		plain, err := aead.Open(sealed[:0], chunkNonce(i), sealed, []byte{b2i(last)})
		if err != nil {
			return errors.New("corrupt artifact")
		}
		if _, err := dst.Write(plain); err != nil {
			return err
		}
		if last {
			return nil
		}
		size = nextSize
	}
}

func b2i(b bool) byte {
	if b {
		return 1
	}
	return 0
}
