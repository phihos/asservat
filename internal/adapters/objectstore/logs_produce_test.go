package objectstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	logcodec "asservat.local/asservat/internal/adapters/logs"
	"asservat.local/asservat/internal/domain/artifact"
)

type logsEOFReader struct {
	*bytes.Reader
	eof bool
}

func (r *logsEOFReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if errors.Is(err, io.EOF) {
		r.eof = true
	}
	return n, err
}

func TestLogsWriterRequiresActualJoinedEndAfterEOF(t *testing.T) {
	for _, mode := range []string{"joined", "source-failed", "end-before-fetch", "future-end"} {
		t.Run(mode, func(t *testing.T) {
			var puts atomic.Int32
			handle, e, _ := writerFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := puts.Add(1)
				if r.Method != http.MethodPut || r.Header.Get("If-None-Match") != "*" {
					t.Error("unbounded or repeated object effect")
				}
				_, _ = io.Copy(io.Discard, r.Body)
				w.Header().Set("ETag", fmt.Sprintf("\"synthetic-%d\"", n))
				w.WriteHeader(200)
			}))
			e.NativeType, e.DataClass, e.ActionID = artifact.LogsArtifact, "raw", "a0123456789abcdef01234567"
			e.Registration.NativeLimit = 1 << 20
			e.Logs = &artifact.LogCapture{ActionID: e.ActionID, BeforeMillis: 10000, Streams: "combined", TimeoutMillis: 10000, MaxNativeBytes: e.Registration.NativeLimit}
			store := handle.(*preparedContext).producer.store
			journal, _ := profileStreamFixture(t) // never used by this one-frame path
			producer, err := NewArtifactProducer(store, contextWriterTestKeys{}, journal, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := producer.Prepare(t.Context(), e, "")
			if err != nil {
				t.Fatal(err)
			}
			from := time.Now().UTC().Truncate(time.Microsecond)
			start, end, _ := e.Logs.Window(e.TriggeredAt)
			var native bytes.Buffer
			encoder, err := logcodec.NewEncoder(t.Context(), &native, artifact.LogHeader{Record: "header", Format: artifact.LogFormat, PodUID: e.PodUID, WindowStart: start, WindowEnd: end, Origins: 1}, e.Registration.NativeLimit)
			if err != nil {
				t.Fatal(err)
			}
			if err = encoder.BeginOrigin(artifact.LogOrigin{Record: "origin", OriginID: 0, ContainerKind: "regular", ContainerName: "app", Source: "current", Stream: "combined"}); err != nil {
				t.Fatal(err)
			}
			if _, err = encoder.Write([]byte("original synthetic log\n")); err != nil {
				t.Fatal(err)
			}
			fetched := time.Now().UTC().Truncate(time.Microsecond)
			if err = encoder.EndOrigin(artifact.LogCoverage{Record: "coverage", OriginID: 0, FetchOutcome: "complete", FetchStartedAt: &from, FetchFinishedAt: &fetched, Gaps: []string{"rotationUnknown"}}); err != nil {
				t.Fatal(err)
			}
			if err = encoder.Close(); err != nil {
				t.Fatal(err)
			}
			reader := &logsEOFReader{Reader: bytes.NewReader(native.Bytes())}
			callbacks := 0
			copies, err := prepared.StoreLogs(context.Background(), reader, from, func() (time.Time, error) {
				callbacks++
				if !reader.eof || puts.Load() != 0 {
					t.Error("acquisition end requested before EOF or final objects written before join")
				}
				switch mode {
				case "source-failed":
					return time.Time{}, artifact.ErrIntegrity
				case "end-before-fetch":
					return from.Add(-time.Microsecond), nil
				case "future-end":
					return time.Now().Add(time.Second), nil
				}
				return time.Now().UTC().Truncate(time.Microsecond), nil
			})
			if callbacks != 1 {
				t.Fatal("completion callback not called exactly once", callbacks, err)
			}
			if mode == "joined" {
				if err != nil || copies.Validate(e.Registration) != nil || puts.Load() != 4 {
					t.Fatal("joined logs did not retain exact four copies", err, puts.Load())
				}
			} else if err == nil || copies != (artifact.Copies{}) || puts.Load() != 0 {
				t.Fatal("unknown/future/failed acquisition published copies", err, puts.Load())
			}
			if _, err := prepared.StoreLogs(t.Context(), bytes.NewReader(native.Bytes()), from, func() (time.Time, error) { t.Error("used writer repeated completion"); return fetched, nil }); err == nil {
				t.Fatal("failed or complete attempt reused")
			}
		})
	}
}
