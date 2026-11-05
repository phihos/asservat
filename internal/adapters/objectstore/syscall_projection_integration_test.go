package objectstore

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/syscalls"
	"asservat.local/asservat/internal/application/evidence"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

const syscallProjectionSecret = "synthetic-credential-only-for-projection-test"

// The largest process fixtures are generated separately from their measured
// reader. These expectations/keys/receipts are synthetic, never authority.
func prepareSyscallEncryptedFixture(t *testing.T, dir, kind string, maximum, malformed, wrongHash bool, sealers ...evidence.KeySealer) profileEncryptedFixture {
	t.Helper()
	unused, e, _ := writerFixture(t, http.NotFoundHandler())
	unused.Close()
	e.NativeType, e.DataClass, e.ActionID = artifact.SyscallRecordsArtifact, "metadata", "a0123456789abcdef01234567"
	e.ExecutionClass, e.NodeUID, e.NodeBootID = artifact.ContextNodeExecution, e.WorkloadUID, e.CaptureUID
	e.Registration.NativeLimit = artifact.RecordingNativeLimit
	e.RequestedAgeSeconds, e.MaximumAgeSeconds = 3600, 7200
	e.Registration.ExpiresAt = e.Registration.AnchorAt.Add(time.Hour)
	e.Registration.DeleteBy = e.Registration.ExpiresAt.Add(time.Minute)
	e.Recording = &artifact.Recording{Kind: "syscallTrace", Profile: "metadata", Composition: []byte("{}"), DurationMillis: 1000, MaxBytes: artifact.RecordingNativeLimit, Snaplen: artifact.RecordingSyscallSnaplen, Syscalls: &artifact.RecordingSyscalls{MaxEvents: 1000000, MaxEventsPerSecond: 100000, MaxTrackedThreads: 16}}
	duration := uint64(1)
	metadata := artifact.SyscallMetadataEvent{Identity: artifact.SyscallMetadataIdentity{PodUID: e.PodUID, ProcessRef: "synthetic-process", ThreadRef: "synthetic-thread"}, Syscall: "write", ABI: "x86_64", Timestamp: e.TriggeredAt.Format(time.RFC3339Nano), DurationNS: &duration, Outcome: "success"}
	var native bytes.Buffer
	appendLine := func(v any) {
		t.Helper()
		line, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		native.Write(line)
		native.WriteByte('\n')
	}
	var header artifact.ArgumentHeader
	if kind == "arguments" {
		e.NativeType, e.DataClass = artifact.SyscallArgumentsArtifact, "raw"
		e.Recording.Profile, e.Recording.Snaplen = "arguments", 0
		e.Recording.Syscalls.Names = []string{"write"}
		definitions, err := syscalls.ArgumentDefinitions([]string{"write"}, true, 128)
		if err != nil {
			t.Fatal(err)
		}
		e.Recording.Arguments = &artifact.RecordingArguments{ProgramDigest: artifact.Digest{1}, DefinitionDigest: artifact.Digest(syscalls.ArgumentDefinitionDigest(definitions)), AccountingRule: artifact.Digest{2}, MaxProbeBytes: 512, MaxBytesPerEvent: 128, MaxBytesPerSecond: 1 << 20, CaptureBuffers: true}
		a := e.Recording.Arguments
		header = artifact.ArgumentHeader{Record: "header", Format: syscalls.ArgumentNativeFormat, PodUID: e.PodUID, NodeUID: e.NodeUID, CollectorPodUID: e.CaptureUID, SessionID: e.CaptureUID, Fence: e.CaptureUID, BootID: e.NodeBootID, SourceEpoch: e.CaptureUID, EngineDigest: hex.EncodeToString(a.ProgramDigest[:]), DefinitionDigest: hex.EncodeToString(a.DefinitionDigest[:]), AccountingRule: hex.EncodeToString(a.AccountingRule[:]), Decoder: syscalls.ArgumentDecoderVersion, ABI: syscalls.ABI, StartedAt: e.TriggeredAt}
		appendLine(header)
	}
	count := 0
	for {
		var line []byte
		var err error
		if kind == "arguments" {
			suffix := "@" + header.BootID + "@" + header.SourceEpoch
			event := artifact.RawArgumentEvent{Identity: artifact.ArgumentIdentity{PodUID: e.PodUID, ProcessRef: "p:10:1" + suffix, ThreadRef: "t:11:1" + suffix}, Syscall: "write", ABI: syscalls.ABI, Timestamp: metadata.Timestamp, DurationNS: &duration, Outcome: "success", Arguments: []artifact.ArgumentValue{{Name: "fd", Value: "decimal:1"}, {Name: "count", Value: "decimal:43"}, {Name: "buffer", Value: "base64:" + base64.StdEncoding.EncodeToString([]byte(syscallProjectionSecret))}}}
			line, err = json.Marshal(artifact.ArgumentEventLine{Record: "event", Event: event})
		} else {
			if kind == "metadata-distinct" {
				metadata.Syscall = fmt.Sprintf("synthetic%050d", count)
			}
			line, err = json.Marshal(metadata)
		}
		if err != nil {
			t.Fatal(err)
		}
		if maximum && int64(native.Len()+len(line)+1024) > artifact.RecordingNativeLimit {
			break
		}
		native.Write(line)
		native.WriteByte('\n')
		count++
		if !maximum && count == 3 {
			break
		}
	}
	if kind == "arguments" {
		appendLine(artifact.ArgumentFooter{Record: "footer", EndedAt: e.TriggeredAt.Add(time.Second), Outcome: "completed", Retained: uint64(count), CoverageUnknown: true})
	}
	if malformed {
		native.WriteString("invalid-tail\n")
	}
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	copies := prepareEncryptedProjectionSource(t, dir, bytes.NewReader(native.Bytes()), e, wrongHash, sealers...)
	f := profileEncryptedFixture{Source: evidence.NativeContextSource{Expectation: e, Copies: copies}, Scope: testProjectionScope()}
	s := &f.Scope
	s.CaseID, s.CaptureID, s.ArtifactID, s.ClusterID = e.CaseID, e.CaptureUID, e.Registration.Location.ArtifactID, e.Registration.Location.ClusterID
	s.NamespaceUID, s.WorkloadUID, s.PodUID = e.NamespaceUID, e.WorkloadUID, e.PodUID
	s.Version, s.NativeType, s.SourceFormat, s.DisplayVersion = evidence.ContextCopiesDigest(copies), e.NativeType, e.Type().Format, query.SyscallSummaryView.DisplayVersion()
	s.Selection, s.SourceProjectionDigest = query.LineSelection{}, artifact.Digest{}
	s.Syscalls = query.SyscallWindow{View: query.SyscallSummaryView, Limit: 100}
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
	t.Logf("source=%s nativeBytes=%d records=%d", kind, native.Len(), count)
	clear(native.Bytes())
	return f
}

func TestSyscallProjectionEncryptedStream(t *testing.T) {
	for _, kind := range []string{"metadata-repeated", "arguments"} {
		for _, mode := range []string{"complete", "events", "ciphertext", "whole-hash", "malformed-tail", "cursor", "cursor-malformed", "cancel"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				dir := t.TempDir()
				f := prepareSyscallEncryptedFixture(t, dir, kind, false, mode == "malformed-tail" || mode == "cursor-malformed", mode == "whole-hash")
				ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
				defer cancel()
				verifier, keys, entered, unblock := profileEncryptedVerifier(t, dir, f, mode == "cancel")
				reader, err := NewContextProjectionReader(verifier.store)
				if err != nil {
					t.Fatal(err)
				}
				reader.ServeSyscallProjections(syscalls.ProjectSyscalls)
				if mode == "events" {
					f.Scope.Syscalls.View = query.SyscallEventsView
					f.Scope.DisplayVersion = query.SyscallEventsView.DisplayVersion()
				}
				if mode == "ciphertext" {
					p, err := os.OpenFile(filepath.Join(dir, "data"), os.O_RDWR, 0)
					if err != nil {
						t.Fatal(err)
					}
					b := []byte{0}
					_, _ = p.ReadAt(b, 32)
					b[0] ^= 1
					_, err = p.WriteAt(b, 32)
					p.Close()
					if err != nil {
						t.Fatal(err)
					}
				}
				if mode == "cursor" || mode == "cursor-malformed" {
					selection := f.Scope.Syscalls.Selection(f.Scope.CaseID, f.Scope.ArtifactID)
					selection, err = query.NormalizeSyscallSelection(f.Scope.CaseID, f.Scope.ArtifactID, selection.View, selection.Cursor(9, f.Scope.Version), 100, nil, false)
					if err != nil {
						t.Fatal(err)
					}
					f.Scope.Syscalls = selection.Window()
				}
				type answer struct {
					result query.ProjectionResult
					err    error
				}
				done := make(chan answer, 1)
				go func() {
					until, _ := ctx.Deadline()
					result, err := reader.ReadProjectionNative(ctx, f.Source, f.Scope, keys, until)
					done <- answer{result, err}
				}()
				if mode == "cancel" {
					select {
					case <-entered:
					case <-ctx.Done():
						t.Fatal("read did not reach data")
					}
					cancel()
					unblock()
				}
				select {
				case got := <-done:
					if mode == "complete" || mode == "events" {
						if got.err != nil || !got.result.Valid(f.Scope) || keys.calls != 3 {
							t.Fatal("summary", got.err, keys.calls)
						}
						if mode == "complete" && got.result.SyscallSummary.RecordCount != 3 || mode == "events" && (got.result.SyscallEvents.RecordCount != 3 || len(got.result.SyscallEvents.Events) != 3) {
							t.Fatal("record count changed")
						}
						body, _ := json.Marshal(got.result)
						for _, secret := range []string{syscallProjectionSecret, base64.StdEncoding.EncodeToString([]byte(syscallProjectionSecret)), "arguments", "decimal:"} {
							if bytes.Contains(body, []byte(secret)) {
								t.Fatal("raw value escaped", secret)
							}
						}
					} else if mode == "cursor" {
						if got.err != nil || !got.result.InvalidCursor || keys.calls != 3 {
							t.Fatal("cursor", got.err)
						}
					} else if got.err == nil || got.result.SyscallSummary != nil || got.result.SyscallEvents != nil || got.result.InvalidCursor {
						t.Fatal("failure disclosed result", mode, got.err)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("read did not join")
				}
			})
		}
	}
}

func TestSyscallProjectionEncryptedProcess(t *testing.T) {
	if dir := os.Getenv("ASSERVAT_SYSCALL_STREAM_GENERATE"); dir != "" {
		prepareSyscallEncryptedFixture(t, dir, os.Getenv("ASSERVAT_SYSCALL_STREAM_KIND"), true, false, false)
		return
	}
	dir := os.Getenv("ASSERVAT_SYSCALL_STREAM_FIXTURE")
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
	if view := os.Getenv("ASSERVAT_SYSCALL_STREAM_VIEW"); view == "events" {
		f.Scope.Syscalls.View = query.SyscallEventsView
		f.Scope.DisplayVersion = query.SyscallEventsView.DisplayVersion()
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	verifier, keys, _, _ := profileEncryptedVerifier(t, dir, f, false)
	reader, err := NewContextProjectionReader(verifier.store)
	if err != nil {
		t.Fatal(err)
	}
	reader.ServeSyscallProjections(syscalls.ProjectSyscalls)
	started := time.Now()
	until, _ := ctx.Deadline()
	result, err := reader.ReadProjectionNative(ctx, f.Source, f.Scope, keys, until)
	var usage syscall.Rusage
	if e := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); e != nil {
		t.Fatal(e)
	}
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	t.Logf("source=%s view=%s elapsed=%s peakRSSKiB=%d heapInuse=%d threeKeys=%t valid=%t refusal=%t", f.Source.Expectation.NativeType, f.Scope.Syscalls.View, time.Since(started), usage.Maxrss, memory.HeapInuse, keys.calls == 3, result.Valid(f.Scope), err != nil)
	if err != nil || !result.Valid(f.Scope) || keys.calls != 3 {
		t.Fatal(err)
	}
}
