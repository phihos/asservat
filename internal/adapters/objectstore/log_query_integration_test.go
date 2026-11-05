package objectstore

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/logs"
	"asservat.local/asservat/internal/application/evidence"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

// Only framing, TLS ranges, parsing and EOF are real here. Keys, publication
// receipts and accepted source/authority are synthetic, not installed permits.
func prepareLogEncryptedFixture(t *testing.T, dir, shape string, maximum, wrongHash bool) profileEncryptedFixture {
	t.Helper()
	unused, e, _ := writerFixture(t, http.NotFoundHandler())
	unused.Close()
	e.NativeType, e.DataClass, e.ActionID = artifact.LogsArtifact, "raw", "a0123456789abcdef01234567"
	e.ExecutionClass, e.NodeUID, e.NodeBootID = artifact.ContextAPIExecution, "", ""
	e.Registration.NativeLimit = artifact.LogNativeLimit
	e.RequestedAgeSeconds, e.MaximumAgeSeconds = 3600, 7200
	e.Registration.ExpiresAt = e.Registration.AnchorAt.Add(time.Hour)
	e.Registration.DeleteBy = e.Registration.ExpiresAt.Add(time.Minute)
	e.Logs = &artifact.LogCapture{ActionID: e.ActionID, BeforeMillis: 10000, TimeoutMillis: 10000, Streams: "combined", MaxNativeBytes: artifact.LogNativeLimit}
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	native, err := os.CreateTemp(dir, "synthetic-native-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { native.Close(); os.Remove(native.Name()) }()
	start, end, _ := e.Logs.Window(e.TriggeredAt)
	origins := uint16(1)
	if shape == "origins" {
		origins = artifact.LogMaxOrigins
	}
	encoder, err := logs.NewEncoder(t.Context(), native, artifact.LogHeader{Record: "header", Format: artifact.LogFormat, PodUID: e.PodUID, WindowStart: start, WindowEnd: end, Origins: origins}, e.Logs.MaxNativeBytes)
	if err != nil {
		t.Fatal(err)
	}
	var block [artifact.LogMaxFragmentBytes]byte
	for origin := uint16(0); origin < origins; origin++ {
		name, source := "app", "current"
		if origins > 1 {
			name = fmt.Sprintf("container-%02d", origin/2)
			if origin%2 == 1 {
				source = "previous"
			}
		}
		if err = encoder.BeginOrigin(artifact.LogOrigin{Record: "origin", OriginID: origin, ContainerKind: "regular", ContainerName: name, Source: source, Stream: "combined"}); err != nil {
			t.Fatal(err)
		}
		for count := 0; ; count++ {
			data := []byte("synthetic\n\n\xff\x00last")
			if maximum {
				if shape == "dense" {
					data = []byte{'\n'}
				} else {
					if _, err = rand.Read(block[:]); err != nil {
						t.Fatal(err)
					}
					const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
					for i := range block {
						block[i] = alphabet[block[i]&63]
					}
					block[len(block)-1] = 0xff
					data = block[:]
				}
			}
			_, err = encoder.Write(data)
			if errors.Is(err, artifact.ErrLimit) {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			if !maximum || count > 1_000_000 {
				if maximum {
					t.Fatal("unbounded fixture producer")
				}
				break
			}
		}
		fetchStart, fetchEnd := e.TriggeredAt.Add(37*time.Nanosecond), e.TriggeredAt.Add(73*time.Nanosecond)
		if err = encoder.EndOrigin(artifact.LogCoverage{FetchOutcome: "complete", FetchStartedAt: &fetchStart, FetchFinishedAt: &fetchEnd, Gaps: []string{"rotationUnknown"}}); err != nil {
			t.Fatal(err)
		}
	}
	if err = encoder.Close(); err != nil {
		t.Fatal(err)
	}
	stat, err := native.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = native.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	copies := prepareEncryptedProjectionSource(t, dir, native, e, wrongHash)
	f := profileEncryptedFixture{Source: evidence.NativeContextSource{Expectation: e, Copies: copies}, Scope: testProjectionScope()}
	s := &f.Scope
	s.CaseID, s.CaptureID, s.ArtifactID, s.ClusterID = e.CaseID, e.CaptureUID, e.Registration.Location.ArtifactID, e.Registration.Location.ClusterID
	s.NamespaceUID, s.WorkloadUID, s.PodUID = e.NamespaceUID, e.WorkloadUID, e.PodUID
	s.Version, s.NativeType, s.SourceFormat, s.DisplayVersion = evidence.ContextCopiesDigest(copies), artifact.LogsArtifact, artifact.LogFormat, query.LogQueryDisplayVersion
	s.Selection, s.SourceProjectionDigest = query.LineSelection{}, artifact.Digest{}
	s.Logs, s.RawGrantID = query.LogWindow{Limit: 100}, e.CaptureUID
	if !s.Valid() || !f.Source.Valid(s.Version) {
		t.Fatal("invalid synthetic logs scope/source")
	}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "fixture.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("synthetic logs shape=%s nativeBytes=%d origins=%d", shape, stat.Size(), origins)
	return f
}

func TestLogQueryEncryptedFullEOF(t *testing.T) {
	for _, wrongHash := range []bool{false, true} {
		dir := t.TempDir()
		f := prepareLogEncryptedFixture(t, dir, "small", false, wrongHash)
		verifier, keys, _, _ := profileEncryptedVerifier(t, dir, f, false)
		reader, err := NewContextProjectionReader(verifier.store)
		if err != nil {
			t.Fatal(err)
		}
		reader.ServeLogQueries(logs.QueryLogs)
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
		until, _ := ctx.Deadline()
		result, err := reader.ReadProjectionNative(ctx, f.Source, f.Scope, keys, until)
		cancel()
		if wrongHash {
			if err == nil || result.Logs != nil {
				t.Fatal("wrong authenticated whole hash disclosed logs")
			}
		} else if err != nil || result.Logs == nil || !result.Valid(f.Scope) || keys.calls != 3 {
			t.Fatal("framed logs query failed", err, keys.calls)
		}
		result.Clear()
	}
}

func TestLogQueryEncryptedProcess(t *testing.T) {
	if dir := os.Getenv("ASSERVAT_LOG_STREAM_GENERATE"); dir != "" {
		prepareLogEncryptedFixture(t, dir, os.Getenv("ASSERVAT_LOG_STREAM_SHAPE"), true, false)
		return
	}
	dir := os.Getenv("ASSERVAT_LOG_STREAM_FIXTURE")
	if dir == "" {
		t.Skip("explicit isolated-process component measurement")
	}
	b, err := os.ReadFile(filepath.Join(dir, "fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f profileEncryptedFixture
	if err = json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	verifier, keys, _, _ := profileEncryptedVerifier(t, dir, f, false)
	reader, err := NewContextProjectionReader(verifier.store)
	if err != nil {
		t.Fatal(err)
	}
	reader.ServeLogQueries(logs.QueryLogs)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	until, _ := ctx.Deadline()
	started := time.Now()
	result, err := reader.ReadProjectionNative(ctx, f.Source, f.Scope, keys, until)
	var usage syscall.Rusage
	if e := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); e != nil {
		t.Fatal(e)
	}
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	t.Logf("logs read elapsed=%s peakRSSKiB=%d heapInuse=%d threeKeys=%t valid=%t refusal=%t", time.Since(started), usage.Maxrss, memory.HeapInuse, keys.calls == 3, result.Valid(f.Scope), err != nil)
	for _, name := range []string{"memory.max", "memory.peak", "memory.current", "memory.swap.max", "memory.swap.current", "memory.events", "cpu.max", "cpu.stat"} {
		b, readErr := os.ReadFile("/sys/fs/cgroup/" + name)
		if readErr != nil {
			t.Fatal("resource measurement unavailable", name, readErr)
		}
		t.Logf("worker cgroup %s=%q", name, string(b))
	}
	if err != nil || !result.Valid(f.Scope) || keys.calls != 3 {
		t.Fatal(err)
	}
	result.Clear()
}
