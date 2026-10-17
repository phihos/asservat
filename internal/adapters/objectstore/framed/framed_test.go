package framed

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/rand/v2"
	"os"
	"strconv"
	"strings"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/streamingaead"
	"github.com/tink-crypto/tink-go/v2/tink"
)

var testBinding = artifact.Binding{ClusterID: "00000000-0000-4000-8000-000000000001", ArtifactID: "00000000-0000-4000-8000-000000000002", AttemptID: "00000000-0000-4000-8000-000000000003", MediaType: "application/octet-stream"}

// Real Tink AEAD, ephemeral test-only key wrapping. Never a runtime fallback.
type testKeys struct {
	a    tink.AEAD
	fail bool
}

type countingKeys struct {
	*testKeys
	wraps, unwraps, maxKeyBytes int
}

func (k *countingKeys) Seal(ctx context.Context, b, ad []byte) (artifact.SealedKey, error) {
	k.wraps++
	k.maxKeyBytes = max(k.maxKeyBytes, len(b))
	if len(b) > 4096 {
		return artifact.SealedKey{}, errors.New("payload reached key service")
	}
	return k.testKeys.Seal(ctx, b, ad)
}
func (k *countingKeys) Open(ctx context.Context, s artifact.SealedKey, ad []byte) ([]byte, error) {
	k.unwraps++
	return k.testKeys.Open(ctx, s, ad)
}

func TestArtifactKeyCallsIndependentOfPayloadSize(t *testing.T) {
	for _, size := range []int{0, 4096, 2*int(artifact.FrameBytes) + 79} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			ctx := context.Background()
			k := &countingKeys{testKeys: keys(t)}
			encoder, err := Prepare(ctx, testBinding, k)
			if err != nil {
				t.Fatal(err)
			}
			manifest, err := PrepareManifest(ctx, testBinding, k)
			if err != nil {
				t.Fatal(err)
			}
			if k.wraps != 3 || k.unwraps != 0 {
				t.Fatal("key preparation must be three wrap-only operations")
			}
			native := bytes.Repeat([]byte{19}, size)
			var data, index bytes.Buffer
			layout, err := encoder.Encode(ctx, bytes.NewReader(native), &data, &index, int64(size))
			if err != nil {
				t.Fatal(err)
			}
			metadata, err := MarshalLayout(layout)
			if err != nil {
				t.Fatal(err)
			}
			cipher, sealed, err := manifest.Seal(ctx, metadata)
			if err != nil {
				t.Fatal(err)
			}
			if k.wraps != 3 || k.unwraps != 0 {
				t.Fatal("streaming or manifest write invoked the key service")
			}
			if k.maxKeyBytes == 0 || k.maxKeyBytes > 4096 {
				t.Fatal("key service received an unbounded keyset")
			}
			opened, err := OpenManifest(ctx, testBinding, k, sealed, cipher, artifact.Digest(sha256.Sum256(cipher)))
			if err != nil {
				t.Fatal(err)
			}
			restored, err := ParseLayout(opened, testBinding)
			if err != nil {
				t.Fatal(err)
			}
			reader, err := Open(ctx, restored, k, &source{b: data.Bytes()}, &source{b: index.Bytes()})
			if err != nil {
				t.Fatal(err)
			}
			if k.unwraps != 3 {
				t.Fatal("opening manifest/data/index must unwrap three keysets")
			}
			out := &destination{}
			if err := reader.Read(ctx, 0, int64(size), out); err != nil || !bytes.Equal(out.Bytes(), native) {
				t.Fatal("native readback", err)
			}
			if size > 4096 {
				out.Reset()
				if err := reader.Read(ctx, 4090, 16, out); err != nil {
					t.Fatal(err)
				}
			}
			if k.wraps != 3 || k.unwraps != 3 {
				t.Fatal("payload/frame/range reads invoked key service again")
			}
			t.Logf("nativeBytes=%d wraps=%d unwraps=%d largestKeysetBytes=%d", size, k.wraps, k.unwraps, k.maxKeyBytes)
		})
	}
}

func keys(t *testing.T) *testKeys {
	t.Helper()
	h, e := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if e != nil {
		t.Fatal(e)
	}
	a, e := aead.New(h)
	if e != nil {
		t.Fatal(e)
	}
	return &testKeys{a: a}
}
func (k *testKeys) Seal(ctx context.Context, b, ad []byte) (artifact.SealedKey, error) {
	if k.fail {
		return artifact.SealedKey{}, errors.New("KMS unavailable")
	}
	c, e := k.a.Encrypt(b, ad)
	return artifact.SealedKey{Reference: "test-only", Ciphertext: hex.EncodeToString(c)}, e
}
func (k *testKeys) Open(ctx context.Context, s artifact.SealedKey, ad []byte) ([]byte, error) {
	c, e := hex.DecodeString(s.Ciphertext)
	if e != nil {
		return nil, e
	}
	return k.a.Decrypt(c, ad)
}

type source struct {
	b            []byte
	reads, bytes int64
}

func (s *source) ReadRange(ctx context.Context, off, n int64) ([]byte, error) {
	if off < 0 || n < 1 || off > int64(len(s.b)) || n > int64(len(s.b))-off {
		return nil, io.ErrUnexpectedEOF
	}
	s.reads++
	s.bytes += n
	return append([]byte(nil), s.b[off:off+n]...), nil
}

type destination struct {
	bytes.Buffer
	calls, denyAt int
	maxBatch      int
}

func (d *destination) Send(ctx context.Context, b []byte) error {
	d.calls++
	if d.denyAt > 0 && d.calls >= d.denyAt {
		return errors.New("revoked")
	}
	d.maxBatch = max(d.maxBatch, len(b))
	_, err := d.Write(b)
	return err
}

func encode(t *testing.T, b []byte) (artifact.Layout, *testKeys, *source, *source) {
	t.Helper()
	k := keys(t)
	e, err := Prepare(context.Background(), testBinding, k)
	if err != nil {
		t.Fatal(err)
	}
	var d, i bytes.Buffer
	l, err := e.Encode(context.Background(), bytes.NewReader(b), &d, &i, int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	return l, k, &source{b: d.Bytes()}, &source{b: i.Bytes()}
}
func open(t *testing.T, l artifact.Layout, k *testKeys, d, i *source) *Reader {
	t.Helper()
	r, err := Open(context.Background(), l, k, d, i)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRoundTripAndRanges(t *testing.T) {
	for _, size := range []int{0, 1, 4000, int(artifact.FrameBytes), int(artifact.FrameBytes) + 27, int(artifact.FrameBytes)*2 + 79} {
		t.Run(strings.ReplaceAll(strconv.Itoa(size), " ", ""), func(t *testing.T) {
			b := make([]byte, size)
			for i := range b {
				b[i] = byte(i * 31)
			}
			l, k, data, index := encode(t, b)
			wire, err := MarshalLayout(l)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseLayout(wire, testBinding)
			if err != nil {
				t.Fatal(err)
			}
			r := open(t, parsed, k, data, index)
			out := &destination{}
			if err = r.Read(context.Background(), 0, int64(size), out); err != nil || !bytes.Equal(b, out.Bytes()) {
				t.Fatalf("full read: %v, bytes %d", err, out.Len())
			}
			if out.maxBatch > artifact.DeliveryBytes || out.calls == 0 {
				t.Fatal("batch/empty authority boundary")
			}
			if size > 1 {
				off := int64(size / 2)
				out = &destination{}
				if err := r.Read(context.Background(), off, 1, out); err != nil || !bytes.Equal(out.Bytes(), b[off:off+1]) {
					t.Fatalf("range: %v", err)
				}
			}
		})
	}
}

func TestCorruptionAndFinalBatch(t *testing.T) {
	for _, corrupt := range []string{"data", "index", "native-hash", "data-hash", "index-hash"} {
		t.Run(corrupt, func(t *testing.T) {
			b := bytes.Repeat([]byte("synthetic evidence only"), 150000)
			l, k, d, i := encode(t, b)
			switch corrupt {
			case "data":
				d.b[len(d.b)-1] ^= 1
			case "index":
				i.b[len(i.b)-1] ^= 1
			case "native-hash":
				l.NativeSHA256[0] ^= 1
			case "data-hash":
				l.DataSHA256[0] ^= 1
			case "index-hash":
				l.IndexSHA256[0] ^= 1
			}
			r := open(t, l, k, d, i)
			out := &destination{}
			if err := r.Read(context.Background(), 0, int64(len(b)), out); !errors.Is(err, artifact.ErrIntegrity) {
				t.Fatalf("want integrity error, got %v", err)
			}
			if out.Len() >= len(b) {
				t.Fatal("emitted complete Content-Length before final integrity")
			}
		})
	}
}

func TestAttemptBindingAndSingleUse(t *testing.T) {
	b := []byte("synthetic")
	l, k, d, i := encode(t, b)
	l.Binding.AttemptID = "00000000-0000-4000-8000-000000000004"
	if _, err := Open(context.Background(), l, k, d, i); err == nil {
		t.Fatal("accepted moved key")
	}
	e, err := Prepare(context.Background(), testBinding, k)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.Encode(context.Background(), bytes.NewReader(b), io.Discard, io.Discard, 2); !errors.Is(err, artifact.ErrLimit) {
		t.Fatalf("limit: %v", err)
	}
	if _, err = e.Encode(context.Background(), bytes.NewReader(b), io.Discard, io.Discard, 20); err == nil {
		t.Fatal("reused failed encoder")
	}
	k.fail = true
	if _, err = Prepare(context.Background(), testBinding, k); err == nil {
		t.Fatal("ignored KMS failure")
	}
}

func TestDeliveryRevocation(t *testing.T) {
	b := bytes.Repeat([]byte{7}, 3*artifact.DeliveryBytes)
	l, k, d, i := encode(t, b)
	r := open(t, l, k, d, i)
	out := &destination{denyAt: 2}
	if err := r.Read(context.Background(), 0, int64(len(b)), out); err == nil || out.Len() != artifact.DeliveryBytes {
		t.Fatalf("revoked delivery emitted %d: %v", out.Len(), err)
	}
}

type repeated struct{ n int64 }

func (r *repeated) Read(b []byte) (int, error) {
	if r.n == 0 {
		return 0, io.EOF
	}
	n := int(min(int64(len(b)), r.n))
	clear(b[:n])
	r.n -= int64(n)
	return n, nil
}

func TestPagedRangeBeyondTwoGiB(t *testing.T) {
	if testing.Short() {
		t.Skip("streaming pagination integration; normal gate runs it")
	}
	k := keys(t)
	e, err := Prepare(context.Background(), testBinding, k)
	if err != nil {
		t.Fatal(err)
	}
	var data, index bytes.Buffer
	n := artifact.FrameBytes*artifact.FramesPerPage + 73
	l, err := e.Encode(context.Background(), &repeated{n}, &data, &index, n)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Pages) != 2 || l.Pages[1].FirstFrame != 256 {
		t.Fatal("pagination not crossed")
	}
	d, i := &source{b: data.Bytes()}, &source{b: index.Bytes()}
	r := open(t, l, k, d, i)
	out := &destination{}
	if err := r.Read(context.Background(), n-20, 20, out); err != nil || !bytes.Equal(out.Bytes(), make([]byte, 20)) {
		t.Fatalf("tail range: %v", err)
	}
	if d.reads != 1 || i.reads != 1 || i.bytes != l.Pages[1].IndexBytes {
		t.Fatalf("unbounded seek: data reads %d, index reads %d", d.reads, i.reads)
	}
	t.Logf("native=%d data=%d index=%d tailDataRead=%d tailIndexRead=%d", n, l.DataBytes, l.IndexBytes, d.bytes, i.bytes)
}

func TestLayoutRejectsMalformedBounds(t *testing.T) {
	l, _, _, _ := encode(t, []byte("synthetic"))
	b, _ := MarshalLayout(l)
	for _, bad := range [][]byte{append(append([]byte(nil), b...), b...), bytes.Replace(b, []byte(`"nativeBytes":9`), []byte(`"nativeBytes":9.0`), 1), bytes.Replace(b, []byte(`"format":`), []byte(`"extra":1,"format":`), 1), bytes.Replace(b, []byte(`"format":`), []byte(`"nativeBytes":9,"format":`), 1)} {
		if _, err := ParseLayout(bad, testBinding); err == nil {
			t.Fatalf("accepted invalid layout %.80s", bad)
		}
	}
	l.Pages[0].DataBytes++
	if l.Validate() == nil {
		t.Fatal("accepted non-contiguous layout")
	}
}

func FuzzLayout(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"format":"asservat-framed/v1"}`))
	b, err := os.ReadFile("../../../../examples/manifest-framed.json")
	if err != nil {
		f.Fatal(err)
	}
	var fixture struct{ Encryption json.RawMessage }
	if json.Unmarshal(b, &fixture) != nil {
		f.Fatal("invalid fixture")
	}
	// Seed a complete valid layout matching this fuzz target's expected identity.
	var dto layoutDTO
	if json.Unmarshal(fixture.Encryption, &dto) != nil {
		f.Fatal("invalid fixture layout")
	}
	dto.Binding = bindingDTO{testBinding.ClusterID, testBinding.ArtifactID, testBinding.AttemptID, testBinding.MediaType}
	seed, err := json.Marshal(dto)
	if err != nil {
		f.Fatal(err)
	}
	if _, err := ParseLayout(seed, testBinding); err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Fuzz(func(t *testing.T, b []byte) {
		l, err := ParseLayout(b, testBinding)
		if err == nil && l.Validate() != nil {
			t.Fatal("parser bypassed domain bounds")
		}
	})
}

func TestPublishedContractFixture(t *testing.T) {
	b, err := os.ReadFile("../../../../examples/manifest-framed.json")
	if err != nil {
		t.Fatal(err)
	}
	var m struct{ Encryption json.RawMessage }
	if json.Unmarshal(b, &m) != nil {
		t.Fatal("invalid fixture")
	}
	expected := artifact.Binding{ClusterID: "00000000-0000-4000-8000-000000000001", ArtifactID: "00000000-0000-4000-8000-000000000093", AttemptID: "00000000-0000-4000-8000-000000000094", MediaType: "application/json"}
	l, err := ParseLayout(m.Encryption, expected)
	if err != nil {
		t.Fatal(err)
	}
	if l.NativeBytes != 4096 || l.DataBytes != 4352 {
		t.Fatal("fixture conversion drift")
	}
	for _, bad := range [][]byte{bytes.Replace(m.Encryption, []byte(`"number": 0,`), nil, 1), bytes.Replace(m.Encryption, []byte(`"number": 0`), []byte(`"number": null`), 1)} {
		if _, err := ParseLayout(bad, expected); err == nil {
			t.Fatal("accepted absent/null required zero field")
		}
	}
}

func TestIncompressibleFramesAndAuthenticatedCorruption(t *testing.T) {
	b := make([]byte, int(artifact.FrameBytes)+9000)
	random := rand.NewChaCha8([32]byte{17})
	if _, err := random.Read(b); err != nil {
		t.Fatal(err)
	}
	l, k, d, i := encode(t, b)
	r := open(t, l, k, d, i)
	out := &destination{}
	if err := r.Read(context.Background(), artifact.FrameBytes-99, 200, out); err != nil || !bytes.Equal(out.Bytes(), b[artifact.FrameBytes-99:artifact.FrameBytes+101]) {
		t.Fatalf("cross-frame native range: %v", err)
	}
	p := l.Pages[0]
	pg, _, err := r.readPage(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if pg.Frames[0].Codec != "identity" {
		t.Fatal("expanded compression was retained")
	}
	// Repair every non-secret checksum/directory field after corrupting a frame.
	// The remaining rejection must come from Tink authentication, not just SHA.
	d.b[0] ^= 1
	first := &pg.Frames[0]
	first.DataSHA256 = hashString(digest(d.b[first.DataOffset : first.DataOffset+first.DataBytes]))
	plain, err := json.Marshal(pg)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := encrypt(r.indexKey, plain, aad(l.Binding, "index", p.Number, p.NativeOffset, p.NativeBytes, "json"))
	if err != nil {
		t.Fatal(err)
	}
	i.b = cipher
	l.IndexBytes = int64(len(cipher))
	l.Pages[0].IndexBytes = int64(len(cipher))
	l.Pages[0].IndexSHA256 = digest(cipher)
	l.IndexSHA256 = digest(cipher)
	l.DataSHA256 = digest(d.b)
	r = open(t, l, k, d, i)
	out = &destination{}
	if err := r.Read(context.Background(), 0, l.NativeBytes, out); !errors.Is(err, artifact.ErrIntegrity) || out.Len() != 0 {
		t.Fatalf("unauthenticated frame escaped: %v, bytes %d", err, out.Len())
	}
}

func TestRejectOtherTinkSuiteBeforeObjectRead(t *testing.T) {
	l, k, d, i := encode(t, []byte("synthetic"))
	h, err := keyset.NewHandle(streamingaead.AES256GCMHKDF4KBKeyTemplate())
	if err != nil {
		t.Fatal(err)
	}
	var raw bytes.Buffer
	if err := insecurecleartextkeyset.Write(h, keyset.NewBinaryWriter(&raw)); err != nil {
		t.Fatal(err)
	}
	defer clear(raw.Bytes())
	l.DataKey, err = k.Seal(context.Background(), raw.Bytes(), aad(l.Binding, "data-key", 0, 0, 0, "none"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), l, k, d, i); !errors.Is(err, artifact.ErrIntegrity) || d.reads != 0 || i.reads != 0 {
		t.Fatalf("accepted unqualified suite: %v", err)
	}
}
