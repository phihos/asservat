// Package objectstore supplies a narrowly scoped S3 adapter. It never interprets
// an ETag as a digest and never hands an object URL to an end user.
package objectstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

var ErrStorage = errors.New("object storage refused or unavailable")
var ErrExists = errors.New("immutable object already exists")
var safeKey = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9/_-]{0,511}$`)

const MaxSmallObject = 16 << 20

// Object is a receipt, not a committed artifact or proof of whole-object hash.
type Object struct {
	Key, VersionID, ETag string
	Bytes                int64
	SHA256               artifact.Digest
}

type Store struct {
	client         *s3.Client
	bucket         string
	requireVersion bool
}

func New(endpoint, region, bucket string, credentials aws.CredentialsProvider, h *http.Client) (*Store, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || region == "" || bucket == "" || credentials == nil || h == nil {
		return nil, artifact.ErrInvalid
	}
	c := *h
	base := h.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	t, ok := base.(*http.Transport)
	if !ok || (t.TLSClientConfig != nil && t.TLSClientConfig.InsecureSkipVerify) {
		return nil, artifact.ErrInvalid
	}
	t = t.Clone()
	t.Proxy = nil
	c.Transport = boundedResponses{t}
	c.Timeout = 30 * time.Second
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("object redirects disabled") }
	s := s3.New(s3.Options{Region: region, BaseEndpoint: aws.String(endpoint), UsePathStyle: true, Credentials: credentials, HTTPClient: &c, RetryMaxAttempts: 1})
	return &Store{client: s, bucket: bucket}, nil
}

// NewVersionedAudit requires immutable, non-null versions for every returned
// audit receipt and pinned read. It does not prove backend IAM, versioning
// configuration, accounting, or deletion; installation must qualify those
// independently. Existing New callers retain their original backend contract.
func NewVersionedAudit(endpoint, region, bucket string, credentials aws.CredentialsProvider, h *http.Client) (*Store, error) {
	s, err := New(endpoint, region, bucket, credentials, h)
	if err != nil {
		return nil, err
	}
	s.requireVersion = true
	return s, nil
}

func (s *Store) acceptsVersion(version string) bool {
	return !s.requireVersion || version != "" && version != "null" && len(version) <= 1024
}

type boundedResponses struct{ base *http.Transport }

func (b boundedResponses) CloseIdleConnections() { b.base.CloseIdleConnections() }

// Close releases the adapter's cloned idle transport. The owning runtime must
// cancel and join active operations before closing its dependencies.
func (s *Store) Close() {
	if s != nil && s.client != nil {
		if c, ok := s.client.Options().HTTPClient.(interface{ CloseIdleConnections() }); ok {
			c.CloseIdleConnections()
		}
	}
}

type limitedBody struct {
	io.Reader
	io.Closer
}

func (b boundedResponses) RoundTrip(req *http.Request) (*http.Response, error) {
	r, err := b.base.RoundTrip(req)
	if err != nil {
		return r, err
	}
	limit := int64(MaxSmallObject + 1)
	q := req.URL.Query()
	if q.Has("versions") || q.Has("uploads") || q.Has("list-type") {
		limit = 2 << 20
	}
	r.Body = limitedBody{io.LimitReader(r.Body, limit), r.Body}
	return r, nil
}

// PutSmall is conditional creation for the first bounded context slice. Large
// streaming/multipart writes require the separate qualified upload adapter; this
// method deliberately refuses them rather than buffering an entire large file.
// The caller registers and charges the exact key before invoking this method.
func (s *Store) PutSmall(ctx context.Context, key string, ciphertext []byte) (Object, error) {
	if !safeKey.MatchString(key) || len(ciphertext) < 1 || len(ciphertext) > MaxSmallObject {
		return Object{}, artifact.ErrInvalid
	}
	d := artifact.Digest(sha256.Sum256(ciphertext))
	o, err := s.client.PutObject(ctx, &s3.PutObjectInput{Bucket: &s.bucket, Key: &key, Body: bytes.NewReader(ciphertext), ContentLength: aws.Int64(int64(len(ciphertext))), IfNoneMatch: aws.String("*"), ContentType: aws.String("application/octet-stream"), ChecksumSHA256: aws.String(base64.StdEncoding.EncodeToString(d[:]))})
	if err != nil {
		var response interface{ HTTPStatusCode() int }
		if errors.As(err, &response) && response.HTTPStatusCode() == http.StatusPreconditionFailed {
			return Object{}, ErrExists
		}
		return Object{}, ErrStorage // outcome may be uncertain: keep the reservation
	}
	if o.ETag == nil || *o.ETag == "" || !s.acceptsVersion(aws.ToString(o.VersionId)) {
		return Object{}, ErrStorage
	}
	return Object{key, aws.ToString(o.VersionId), *o.ETag, int64(len(ciphertext)), d}, nil
}

type PinnedSource struct {
	store  *Store
	object Object
}

var _ evidence.CipherSource = (*PinnedSource)(nil)

func (s *Store) Pin(o Object) (*PinnedSource, error) {
	if !safeKey.MatchString(o.Key) || o.Bytes < 1 || o.Bytes > artifact.MaxNativeBytes+int64(artifact.MaxFrames)*artifact.CipherOverhead || o.ETag == "" || len(o.ETag) > 1024 || len(o.VersionID) > 1024 || !s.acceptsVersion(o.VersionID) {
		return nil, artifact.ErrInvalid
	}
	return &PinnedSource{s, o}, nil
}

func (p *PinnedSource) ReadRange(ctx context.Context, offset, size int64) ([]byte, error) {
	o := p.object
	if offset < 0 || size < 1 || offset > o.Bytes || size > o.Bytes-offset || size > artifact.FrameBytes+artifact.CipherOverhead {
		return nil, artifact.ErrInvalid
	}
	r := fmt.Sprintf("bytes=%d-%d", offset, offset+size-1)
	q := &s3.GetObjectInput{Bucket: &p.store.bucket, Key: &o.Key, IfMatch: &o.ETag, Range: &r}
	if o.VersionID != "" {
		q.VersionId = &o.VersionID
	}
	v, err := p.store.client.GetObject(ctx, q)
	if err != nil {
		return nil, ErrStorage
	}
	defer v.Body.Close()
	if aws.ToString(v.ETag) != o.ETag || (o.VersionID != "" && aws.ToString(v.VersionId) != o.VersionID) || aws.ToInt64(v.ContentLength) != size || aws.ToString(v.ContentRange) != fmt.Sprintf("bytes %d-%d/%d", offset, offset+size-1, o.Bytes) {
		return nil, artifact.ErrIntegrity
	}
	b, err := io.ReadAll(io.LimitReader(v.Body, size+1))
	if err != nil || int64(len(b)) != size {
		return nil, artifact.ErrIntegrity
	}
	return b, nil
}

// Verify rereads the complete small object with the independently configured
// verifier's credentials. Large objects need streaming verification. It is not
// implemented with a HEAD/ETag checksum shortcut.
func (s *Store) Verify(ctx context.Context, o Object) error {
	if o.Bytes > MaxSmallObject {
		return artifact.ErrLimit
	}
	p, err := s.Pin(o)
	if err != nil {
		return err
	}
	h := sha256.New()
	for off := int64(0); off < o.Bytes; {
		n := min(artifact.FrameBytes, o.Bytes-off)
		b, err := p.ReadRange(ctx, off, n)
		if err != nil {
			return err
		}
		h.Write(b)
		off += n
	}
	if !bytes.Equal(h.Sum(nil), o.SHA256[:]) {
		return artifact.ErrIntegrity
	}
	return nil
}
