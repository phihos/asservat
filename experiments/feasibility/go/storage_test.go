package feasibility

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/klauspost/compress/zstd"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func setup(t *testing.T) *Store {
	t.Helper()
	endpoint := os.Getenv("ASSERVAT_TEST_S3")
	if endpoint == "" {
		t.Skip("requires disposable S3 fixture")
	}
	u, e := url.Parse(endpoint)
	if e != nil {
		t.Fatal(e)
	}
	a, e := netip.ParseAddr(u.Hostname())
	if e != nil || (!a.IsLoopback() && !a.IsPrivate()) || u.Scheme != "http" {
		t.Fatal("only explicit private disposable S3 fixture allowed")
	}
	s := NewStore(endpoint, fmt.Sprintf("asservat-%d", time.Now().UnixNano()))
	if _, e := s.Client.CreateBucket(context.Background(), &s3.CreateBucketInput{Bucket: &s.Bucket}); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		o, e := s.Client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &s.Bucket})
		if e != nil {
			t.Error(e)
			return
		}
		for _, x := range o.Contents {
			if _, e = s.Client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &s.Bucket, Key: x.Key}); e != nil {
				t.Error(e)
			}
		}
		if _, e = s.Client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &s.Bucket}); e != nil {
			t.Error(e)
		}
	})
	return s
}
func randomBytes(n int) []byte {
	p := make([]byte, n)
	r := rand.NewChaCha8([32]byte{42})
	for i := range p {
		p[i] = byte(r.Uint64())
	}
	return p
}
func capture(t *testing.T, s *Store, id string, p []byte, frame int) (Bundle, Index) {
	t.Helper()
	b, idx, e := s.Encode(context.Background(), id, bytes.NewReader(p), frame, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	return b, idx
}
func TestS3MultipartNativeRangesAndIntegrity(t *testing.T) {
	s := setup(t)
	ctx := context.Background()
	p := randomBytes(17*MiB + 71)
	b, idx := capture(t, s, "native", p, 8*MiB)
	got, e := s.Open(ctx, b)
	if e != nil || got.NativeSHA != hash(p) {
		t.Fatal(e)
	}
	for _, v := range [][2]int64{{0, int64(len(p))}, {0, 1}, {MiB + 11, 2 * MiB}, {8*MiB - 9, 8*MiB + 13}, {int64(len(p)) - 1, int64(len(p))}} {
		var out bytes.Buffer
		before := s.ReadBytes.Load()
		if e = s.Range(ctx, b, got, v[0], v[1], &out, func(int) bool { return true }); e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(out.Bytes(), p[v[0]:v[1]]) {
			t.Fatal("native bytes changed")
		}
		if v[1]-v[0] == 1 && s.ReadBytes.Load()-before >= idx.CipherBytes {
			t.Fatal("single-byte range reread whole object")
		}
	}
	var out bytes.Buffer
	if e = s.Range(cancelled(), b, got, 0, got.NativeBytes, &out, func(int) bool { return true }); !errors.Is(e, context.Canceled) || out.Len() != 0 {
		t.Fatal("cancel not honored", e)
	}
	for _, v := range [][2]int64{{-1, 1}, {0, 0}, {0, idx.NativeBytes + 1}} {
		if e = s.Range(ctx, b, got, v[0], v[1], io.Discard, func(int) bool { return true }); e == nil {
			t.Fatal("bad native range accepted")
		}
	}
	// Substitute authenticated-index identity and offset values; structure checks must reject them.
	bad := got
	bad.ID = "other"
	if validateIndex(bad, b.ID) == nil {
		t.Fatal("foreign index accepted")
	}
	bad = got
	bad.Frames = append([]Frame(nil), got.Frames...)
	bad.Frames[1].CipherOffset++
	if validateIndex(bad, b.ID) == nil {
		t.Fatal("gapped index accepted")
	}
	// Corrupt a ciphertext byte, keeping the test handle's ETag current to exercise cryptographic checks.
	raw, e := s.get(ctx, b.ID+"/data", b.DataETag, 0, idx.CipherBytes)
	if e != nil {
		t.Fatal(e)
	}
	raw[200] ^= 128
	b.DataETag, e = s.put(ctx, b.ID+"/data", raw)
	if e != nil {
		t.Fatal(e)
	}
	out.Reset()
	if e = s.Range(ctx, b, got, 0, 1, &out, func(int) bool { return true }); e == nil || out.Len() != 0 {
		t.Fatal("corrupt frame emitted")
	}
	ci, e := s.get(ctx, b.ID+"/index", b.IndexETag, 0, b.IndexBytes)
	if e != nil {
		t.Fatal(e)
	}
	ci[len(ci)/2] ^= 64
	b.IndexETag, e = s.put(ctx, b.ID+"/index", ci)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Open(ctx, b); e == nil {
		t.Fatal("corrupt index accepted")
	}
	t.Logf("17 MiB native object: multipart + exact full/range bytes, bounded reads, cancellation, invalid ranges, index/cipher corruption passed")
}
func TestAuthenticatedTLSDownloadResumeAndCutoff(t *testing.T) {
	s := setup(t)
	p := randomBytes(9*MiB + 19)
	b, _ := capture(t, s, "transfer", p, 8*MiB)
	g := &Grant{Remaining: 32 * MiB, Expires: time.Now().Add(time.Minute)}
	server := httptest.NewTLSServer(Handler(s, b, g))
	defer server.Close()
	client := server.Client()
	request := func(token, rng, version string) (int, []byte, error) {
		r, _ := http.NewRequest("GET", server.URL, nil)
		r.Header.Set("Authorization", token)
		r.Header.Set("Range", rng)
		r.Header.Set("If-Range", version)
		res, e := client.Do(r)
		if e != nil {
			return 0, nil, e
		}
		defer res.Body.Close()
		body, e := io.ReadAll(res.Body)
		return res.StatusCode, body, e
	}
	if status, _, _ := request("", "", ""); status != 403 {
		t.Fatal("unauthenticated download", status)
	}
	version := `"` + b.IndexSHA + `"`
	status, a, e := request("Bearer synthetic-human", "bytes=0-4194303", version)
	if status != 206 || e != nil {
		t.Fatal(status, e)
	}
	status, c, e := request("Bearer synthetic-human", "bytes=4194304-", version)
	if status != 206 || e != nil || !bytes.Equal(append(a, c...), p) {
		t.Fatal("resume mismatch", status, e)
	}
	if status, _, _ := request("Bearer synthetic-human", "bytes=0-1", `"changed"`); status != 412 {
		t.Fatal("If-Range mismatch accepted")
	}
	for _, rng := range []string{"bytes=0-1,4-5", "bytes=-1", "bytes=999999999999999999999999-", "bytes=4-2"} {
		if status, _, _ := request("Bearer synthetic-human", rng, version); status != 416 {
			t.Fatal("bad range accepted", rng, status)
		}
	}
	g.mu.Lock()
	spent := g.Spent
	g.MaxBatches = g.Batches + 1
	g.mu.Unlock()
	_, body, e := request("Bearer synthetic-human", "", version)
	if e == nil || len(body) > MiB || len(body) == len(p) {
		t.Fatal("midstream cutoff not surfaced", len(body), e)
	}
	g.mu.Lock()
	if g.Spent-spent != MiB {
		t.Error("uncertain bytes refunded or overdebited")
	}
	g.Revoked = true
	g.mu.Unlock()
	if status, _, _ := request("Bearer synthetic-human", "bytes=0-1", version); status != 403 {
		t.Fatal("revoked resume accepted")
	}
	g.mu.Lock()
	g.Revoked = false
	g.Expires = time.Now().Add(-time.Second)
	g.mu.Unlock()
	if status, _, _ := request("Bearer synthetic-human", "", version); status != 403 {
		t.Fatal("expired accepted")
	}
	t.Log("TLS native resume, If-Range, invalid/multiple ranges, cumulative bytes and 1 MiB cutoff tested with in-memory authority; SQL/OIDC integration not tested")
}
func TestDecoderExpansionBound(t *testing.T) {
	z, e := zstd.NewWriter(nil)
	if e != nil {
		t.Fatal(e)
	}
	encoded := z.EncodeAll(make([]byte, 8*MiB), nil)
	z.Close()
	d, e := zstd.NewReader(nil, zstd.WithDecoderMaxMemory(2*MiB), zstd.WithDecodeAllCapLimit(true))
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	if _, e = d.DecodeAll(encoded, make([]byte, 0, MiB)); e == nil {
		t.Fatal("decompression expansion not bounded")
	}
}
func TestStorageMeasurements(t *testing.T) {
	if os.Getenv("ASSERVAT_MEASURE") != "1" {
		t.Skip("explicit measurement run")
	}
	s := setup(t)
	type measurement struct {
		Dataset                                 string
		NativeMiB, FrameMiB                     int
		CipherBytes, IndexBytes, RangeReadBytes int64
		EncodeMS, FirstRangeMS, FullReadMS      float64
		HeapInUse                               uint64
	}
	var rows []measurement
	for _, kind := range []string{"compressible", "incompressible"} {
		p := make([]byte, 64*MiB)
		if kind == "compressible" {
			for i := range p {
				p[i] = byte(i % 251)
			}
		} else {
			p = randomBytes(len(p))
		}
		for _, frame := range []int{8, 16, 32} {
			start := time.Now()
			b, idx := capture(t, s, fmt.Sprintf("measure-%s-%d", kind, frame), p, frame*MiB)
			encode := time.Since(start)
			i, e := s.Open(context.Background(), b)
			if e != nil {
				t.Fatal(e)
			}
			before := s.ReadBytes.Load()
			start = time.Now()
			var out bytes.Buffer
			if e = s.Range(context.Background(), b, i, 49*MiB, 50*MiB, &out, func(int) bool { return true }); e != nil || !bytes.Equal(out.Bytes(), p[49*MiB:50*MiB]) {
				t.Fatal(e)
			}
			latency := time.Since(start)
			read := s.ReadBytes.Load() - before
			start = time.Now()
			if e = s.Range(context.Background(), b, i, 0, int64(len(p)), io.Discard, func(int) bool { return true }); e != nil {
				t.Fatal(e)
			}
			full := time.Since(start)
			var mem runtime.MemStats
			runtime.ReadMemStats(&mem)
			rows = append(rows, measurement{kind, 64, frame, idx.CipherBytes, b.IndexBytes, read, float64(encode.Microseconds()) / 1000, float64(latency.Microseconds()) / 1000, float64(full.Microseconds()) / 1000, mem.HeapInuse})
		}
	}
	out, e := json.MarshalIndent(rows, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	path := os.Getenv("ASSERVAT_MEASUREMENT_PATH")
	if path == "" {
		t.Fatal("measurement output path required")
	}
	if e = os.WriteFile(path, append(out, '\n'), 0600); e != nil {
		t.Fatal(e)
	}
}

func TestLargeStreamingArtifact(t *testing.T) {
	if os.Getenv("ASSERVAT_LARGE") != "1" {
		t.Skip("explicit 2 GiB bounded-disk experiment")
	}
	s := setup(t)
	ctx := context.Background()
	const size int64 = 2 << 30
	source := rand.NewChaCha8([32]byte{17})
	start := time.Now()
	b, idx, e := s.Encode(ctx, "large-stream", io.LimitReader(source, size), 8*MiB, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	encoded := time.Since(start)
	opened, e := s.Open(ctx, b)
	if e != nil {
		t.Fatal(e)
	}
	s.ReadBytes.Store(0)
	start = time.Now()
	var out bytes.Buffer
	if e = s.Range(ctx, b, opened, size-MiB, size, &out, func(int) bool { return true }); e != nil {
		t.Fatal(e)
	}
	resume := time.Since(start)
	read := s.ReadBytes.Load()
	expectedSource := rand.NewChaCha8([32]byte{17})
	if _, e = io.CopyN(io.Discard, expectedSource, size-MiB); e != nil {
		t.Fatal(e)
	}
	expected := make([]byte, MiB)
	if _, e = io.ReadFull(expectedSource, expected); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(out.Bytes(), expected) {
		t.Fatal("large high-offset resume mismatch")
	}
	start = time.Now()
	if e = s.Range(ctx, b, opened, 0, size, io.Discard, func(int) bool { return true }); e != nil {
		t.Fatal(e)
	}
	full := time.Since(start)
	report := map[string]any{"nativeBytes": size, "cipherBytes": idx.CipherBytes, "indexBytes": b.IndexBytes, "frames": len(idx.Frames), "frameMiB": 8, "encodeUploadSeconds": encoded.Seconds(), "lastMiBResumeSeconds": resume.Seconds(), "resumeCipherBytesRead": read, "fullVerifiedReadSeconds": full.Seconds(), "nativeSHA256": idx.NativeSHA, "limits": "Single local run, synthetic incompressible stream, ciphertext-only local staging; KMS, production commit and distributed relays not tested"}
	if v, e := os.ReadFile("/proc/self/status"); e == nil {
		for _, line := range strings.Split(string(v), "\n") {
			if strings.HasPrefix(line, "VmHWM:") {
				report["processVmHWM"] = line
			}
		}
	}
	data, _ := json.MarshalIndent(report, "", "  ")
	path := os.Getenv("ASSERVAT_LARGE_REPORT")
	if path == "" {
		t.Fatal("large report path required")
	}
	if e = os.WriteFile(path, append(data, '\n'), 0600); e != nil {
		t.Fatal(e)
	}
}

func TestConcurrentDisclosureBudget(t *testing.T) {
	g := &Grant{Remaining: 7 * MiB, Expires: time.Now().Add(time.Minute)}
	var wg sync.WaitGroup
	var accepted atomic.Int64
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if g.allow(MiB) {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 7 || g.Remaining != 0 || g.Spent != 7*MiB {
		t.Fatal("concurrent overspend")
	}
}

func TestInterruptedMultipartIsAborted(t *testing.T) {
	s := setup(t)
	_, e := s.multipart(context.Background(), "broken", &failReader{})
	if e == nil {
		t.Fatal("source failure ignored")
	}
	o, e := s.Client.ListMultipartUploads(context.Background(), &s3.ListMultipartUploadsInput{Bucket: &s.Bucket})
	if e != nil || len(o.Uploads) != 0 {
		t.Fatal("unfinished multipart retained", e)
	}
	if _, e = s.Client.HeadObject(context.Background(), &s3.HeadObjectInput{Bucket: &s.Bucket, Key: aws.String("broken")}); e == nil {
		t.Fatal("failed upload visible as object")
	}
}

type failReader struct{ done bool }

func (r *failReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, errors.New("injected source failure")
	}
	r.done = true
	return len(p), nil
}

func TestGadgetArtifactNativeDownload(t *testing.T) {
	path := os.Getenv("ASSERVAT_GADGET_PCAP")
	outpath := os.Getenv("ASSERVAT_DOWNLOADED_PCAP")
	if path == "" || outpath == "" {
		t.Skip("requires synthetic VM Gadget artifact paths")
	}
	p, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	s := setup(t)
	b, _ := capture(t, s, "gadget-native", p, 8*MiB)
	g := &Grant{Remaining: int64(len(p)), Expires: time.Now().Add(time.Minute)}
	server := httptest.NewTLSServer(Handler(s, b, g))
	defer server.Close()
	r, _ := http.NewRequest("GET", server.URL, nil)
	r.Header.Set("Authorization", "Bearer synthetic-human")
	res, e := server.Client().Do(r)
	if e != nil {
		t.Fatal(e)
	}
	defer res.Body.Close()
	out, e := io.ReadAll(res.Body)
	if e != nil || res.StatusCode != 200 || !bytes.Equal(p, out) {
		t.Fatal("native PCAP changed", e)
	}
	if e = os.WriteFile(outpath, out, 0600); e != nil {
		t.Fatal(e)
	}
	t.Logf("actual Gadget PCAPNG -> encrypted multipart S3 -> authenticated TLS native download: %d bytes SHA256 %s", len(p), hash(p))
}

func TestFinalChecksumFailureWithholdsLastBatch(t *testing.T) {
	s := setup(t)
	p := randomBytes(2*MiB + 9)
	b, idx := capture(t, s, "final-digest", p, 8*MiB)
	idx.NativeSHA = strings.Repeat("0", 64)
	var out bytes.Buffer
	if e := s.Range(context.Background(), b, idx, 0, idx.NativeBytes, &out, func(int) bool { return true }); e == nil {
		t.Fatal("wrong final digest accepted")
	}
	if int64(out.Len()) >= idx.NativeBytes {
		t.Fatal("all bytes emitted before final digest failure")
	}
	t.Logf("late whole-digest failure withheld final %d bytes", len(p)-out.Len())
}
