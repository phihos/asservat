package objectstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/diagnostics"
	"asservat.local/asservat/internal/adapters/objectstore/framed"
	"asservat.local/asservat/internal/adapters/objectstore/manifest"
	"asservat.local/asservat/internal/application/evidence"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/google/pprof/profile"
)

// Actual frame/manifest encryption and verification plus pinned TLS range reads.
// Provider keys, receipts and accepted source/authority are explicitly synthetic;
// this fixture cannot qualify SQL, S3, key grants or a deployed acquisition worker.
type profileEncryptedFixture struct {
	Source evidence.NativeContextSource
	Scope  query.ContextProjectionScope
}

func profileSummaryNative(t *testing.T) []byte {
	t.Helper()
	// Random omitted comment crosses the 8 MiB encrypted-frame boundary without
	// inventing oversized hotspot names or retaining the comment in the result.
	comment := make([]byte, 12<<20)
	if _, err := rand.Read(comment); err != nil {
		t.Fatal(err)
	}
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
	for i := range comment {
		comment[i] = alphabet[comment[i]&63]
	}
	fn := &profile.Function{ID: 1, Name: "synthetic.cpuWork"}
	loc := &profile.Location{ID: 1, Line: []profile.Line{{Function: fn}}}
	p := &profile.Profile{SampleType: []*profile.ValueType{{Type: "cpu", Unit: "nanoseconds"}}, PeriodType: &profile.ValueType{Type: "cpu", Unit: "nanoseconds"}, Period: 1, DurationNanos: 1000000000, Function: []*profile.Function{fn}, Location: []*profile.Location{loc}, Sample: []*profile.Sample{{Location: []*profile.Location{loc}, Value: []int64{7}}}, Comments: []string{string(comment)}}
	var b bytes.Buffer
	if err := p.Write(&b); err != nil {
		t.Fatal(err)
	}
	clear(comment)
	if b.Len() <= int(artifact.FrameBytes) {
		t.Fatal("fixture does not cross a frame")
	}
	return b.Bytes()
}

func prepareProfileEncryptedFixture(t *testing.T, dir string, native io.Reader, wrongWholeHash bool) profileEncryptedFixture {
	t.Helper()
	// Reuse the existing synthetic expectation constructor; its prepared context
	// handle is never stored or treated as profile authority.
	unused, e, _ := writerFixture(t, http.NotFoundHandler())
	unused.Close()
	e.NativeType, e.DataClass, e.ActionID = artifact.PprofArtifact, "raw", "a0123456789abcdef01234567"
	e.Profile = &artifact.GoProfileAcquisition{SourceRef: "synthetic-pprof", EndpointDigest: artifact.Digest{4}, Type: "cpu", Mode: "interval", DurationMillis: 1000}
	e.Registration.NativeLimit = artifact.MaxPprofBytes
	e.RequestedAgeSeconds, e.MaximumAgeSeconds = 3600, 7200
	e.Registration.ExpiresAt = e.Registration.AnchorAt.Add(time.Hour)
	e.Registration.DeleteBy = e.Registration.ExpiresAt.Add(time.Minute)
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	encoder, err := framed.Prepare(t.Context(), e.Binding(), contextWriterTestKeys{})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.Create(filepath.Join(dir, "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer data.Close()
	index, err := os.Create(filepath.Join(dir, "index"))
	if err != nil {
		t.Fatal(err)
	}
	defer index.Close()
	layout, err := encoder.Encode(t.Context(), native, data, index, e.Registration.NativeLimit)
	if err != nil {
		t.Fatal(err)
	}
	if err = data.Close(); err != nil {
		t.Fatal(err)
	}
	if err = index.Close(); err != nil {
		t.Fatal(err)
	}
	var copies artifact.Copies
	copies[0] = artifact.CopyReceipt{ETag: "\"pinned\"", Bytes: layout.DataBytes, SHA256: layout.DataSHA256}
	copies[1] = artifact.CopyReceipt{ETag: "\"pinned\"", Bytes: layout.IndexBytes, SHA256: layout.IndexSHA256}
	if wrongWholeHash {
		layout.NativeSHA256[0] ^= 1
	}
	contracts, err := manifest.New()
	if err != nil {
		t.Fatal(err)
	}
	plain, err := contracts.MarshalContext(e, layout, copies, e.TriggeredAt, e.TriggeredAt.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	metadata, err := framed.PrepareManifest(t.Context(), e.Binding(), contextWriterTestKeys{})
	if err != nil {
		t.Fatal(err)
	}
	cipher, key, err := metadata.Seal(t.Context(), plain)
	if err != nil {
		t.Fatal(err)
	}
	put := func(role int, b []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, artifact.Role(role)), b, 0600); err != nil {
			t.Fatal(err)
		}
		copies[role] = artifact.CopyReceipt{ETag: "\"pinned\"", Bytes: int64(len(b)), SHA256: sha256.Sum256(b)}
	}
	put(2, cipher)
	commit, err := contracts.MarshalCommit(e.Registration.Location, copies[2], key)
	if err != nil {
		t.Fatal(err)
	}
	put(3, commit)
	f := profileEncryptedFixture{Source: evidence.NativeContextSource{Expectation: e, Copies: copies}, Scope: testProjectionScope()}
	s := &f.Scope
	s.CaseID, s.CaptureID = e.CaseID, e.CaptureUID
	s.ArtifactID, s.ClusterID = e.Registration.Location.ArtifactID, e.Registration.Location.ClusterID
	s.NamespaceUID, s.WorkloadUID, s.PodUID = e.NamespaceUID, e.WorkloadUID, e.PodUID
	s.Version = evidence.ContextCopiesDigest(copies)
	s.NativeType, s.SourceFormat, s.DisplayVersion = artifact.PprofArtifact, artifact.PprofFormat, query.ProfileSummaryDisplayVersion
	s.Selection, s.SourceProjectionDigest, s.Profile = query.LineSelection{}, artifact.Digest{}, query.ProfileSummarySelection{SampleType: "cpu", TopN: 20}
	if !s.Valid() || !f.Source.Valid(s.Version) {
		t.Fatal("invalid synthetic scope/source")
	}
	encoded, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "fixture.json"), encoded, 0600); err != nil {
		t.Fatal(err)
	}
	return f
}

// openProfileEncryptedFixture reads only the exact four fixture objects, with
// real TLS and the existing product's bounded S3 HTTP range adapter.
func profileEncryptedVerifier(t *testing.T, dir string, f profileEncryptedFixture, block bool, observe ...func(string)) (*ContextVerifier, *projectionTestOpener, <-chan struct{}, func()) {
	t.Helper()
	entered, release := make(chan struct{}), make(chan struct{})
	var enteredOnce, releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prefix := "/fixture/" + f.Source.Expectation.Registration.Location.Prefix()
		role := strings.TrimPrefix(r.URL.Path, prefix)
		if r.Method != http.MethodGet || r.URL.Path != prefix+role || (role != "data" && role != "index" && role != "manifest" && role != "commit") {
			w.WriteHeader(404)
			return
		}
		if len(observe) > 0 {
			observe[0](role)
		}
		if block && role == "data" {
			enteredOnce.Do(func() { close(entered) })
			<-release
		}
		file, err := os.Open(filepath.Join(dir, role))
		if err != nil {
			w.WriteHeader(404)
			return
		}
		defer file.Close()
		stat, err := file.Stat()
		if err != nil {
			w.WriteHeader(500)
			return
		}
		var from, to int64
		if _, err = fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-%d", &from, &to); err != nil || from < 0 || to < from || to >= stat.Size() || r.Header.Get("If-Match") != "\"pinned\"" {
			w.WriteHeader(400)
			return
		}
		w.Header().Set("ETag", "\"pinned\"")
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", from, to, stat.Size()))
		w.Header().Set("Content-Length", strconv.FormatInt(to-from+1, 10))
		w.WriteHeader(206)
		_, _ = io.CopyN(w, io.NewSectionReader(file, from, to-from+1), to-from+1)
	}))
	t.Cleanup(func() { unblock(); server.Close() })
	store, err := New(server.URL, "us-east-1", "fixture", credentials.NewStaticCredentialsProvider("synthetic", "synthetic", ""), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	bound, err := store.ForCustody(f.Source.Expectation.Registration.StoreID)
	if err != nil {
		t.Fatal(err)
	}
	keys := &projectionTestOpener{}
	verifier, err := NewContextVerifier(bound, keys)
	if err != nil {
		t.Fatal(err)
	}
	return verifier, keys, entered, unblock
}

func openProfileEncryptedFixture(t *testing.T, owner context.Context, dir string, f profileEncryptedFixture, block bool) (*FramedNativeSource, <-chan struct{}, func()) {
	t.Helper()
	verifier, keys, entered, unblock := profileEncryptedVerifier(t, dir, f, block)
	until, _ := owner.Deadline()
	opened, err := verifier.OpenNative(owner, f.Source.Expectation, f.Source.Copies, until)
	if err != nil {
		t.Fatal(err)
	}
	if keys.calls != 3 {
		t.Fatal("key calls", keys.calls)
	}
	t.Cleanup(opened.Close)
	return opened, entered, unblock
}

func TestProfileSummaryEncryptedStream(t *testing.T) {
	native := profileSummaryNative(t)
	defer clear(native)
	for _, mode := range []string{"complete", "ciphertext", "whole-file-hash", "cancel", "close"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			f := prepareProfileEncryptedFixture(t, dir, bytes.NewReader(native), mode == "whole-file-hash")
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			opened, entered, unblock := openProfileEncryptedFixture(t, ctx, dir, f, mode == "cancel" || mode == "close")
			if mode == "ciphertext" {
				p, err := os.OpenFile(filepath.Join(dir, "data"), os.O_RDWR, 0)
				if err != nil {
					t.Fatal(err)
				}
				b := []byte{0}
				if _, err = p.ReadAt(b, 32); err != nil {
					t.Fatal(err)
				}
				b[0] ^= 1
				if _, err = p.WriteAt(b, 32); err != nil {
					t.Fatal(err)
				}
				p.Close()
			}
			type result struct {
				summary query.ProfileSummary
				err     error
			}
			done := make(chan result, 1)
			go func() {
				p, err := evidence.ReadProfileSummary(ctx, opened, f.Source, f.Scope, diagnostics.SummarizePprof)
				done <- result{p, err}
			}()
			if mode == "cancel" || mode == "close" {
				select {
				case <-entered:
				case <-ctx.Done():
					t.Fatal("read did not reach data")
				}
				if mode == "cancel" {
					cancel()
				} else {
					opened.Close()
				}
				unblock()
			}
			select {
			case got := <-done:
				if mode == "complete" {
					if got.err != nil || !got.summary.Valid(f.Scope.Profile) || got.summary.Total != 7 || len(got.summary.Top) != 1 || got.summary.Top[0].Function == nil || *got.summary.Top[0].Function != "synthetic.cpuWork" {
						t.Fatal("summary", got.err)
					}
				} else if got.err == nil || len(got.summary.Top) != 0 {
					t.Fatal("failed read disclosed summary", mode, got.err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("summary did not join")
			}
			opened.mu.Lock()
			closed, retained := opened.closed, len(opened.carry) > 0 || opened.reader != nil
			opened.mu.Unlock()
			if !closed || retained {
				t.Fatal("source retained plaintext/reader after result")
			}
		})
	}
}

// Explicit process modes keep all producer allocations outside the measured
// process. The files contain synthetic ciphertext and synthetic wrapped test
// keysets; they confer no product authority. Ordinary tests skip these modes.
func TestProfileSummaryEncryptedProcess(t *testing.T) {
	if dir := os.Getenv("ASSERVAT_PROFILE_STREAM_GENERATE"); dir != "" {
		input, err := os.Open(os.Getenv("ASSERVAT_PROFILE_STREAM_NATIVE"))
		if err != nil {
			t.Fatal(err)
		}
		defer input.Close()
		prepareProfileEncryptedFixture(t, dir, input, false)
		return
	}
	dir := os.Getenv("ASSERVAT_PROFILE_STREAM_FIXTURE")
	if dir == "" {
		t.Skip("explicit bounded-process component measurement")
	}
	b, err := os.ReadFile(filepath.Join(dir, "fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f profileEncryptedFixture
	if err = json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	started := time.Now()
	opened, _, _ := openProfileEncryptedFixture(t, ctx, dir, f, false)
	result, err := evidence.ReadProfileSummary(ctx, opened, f.Source, f.Scope, diagnostics.SummarizePprof)
	var usage syscall.Rusage
	if e := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); e != nil {
		t.Fatal(e)
	}
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	t.Logf("streamed summary: elapsed=%s peakRSSKiB=%d heapInuse=%d resultValid=%t refusal=%t", time.Since(started), usage.Maxrss, memory.HeapInuse, result.Valid(f.Scope.Profile), err != nil)
	if err != nil {
		t.Fatal(err)
	}
}
