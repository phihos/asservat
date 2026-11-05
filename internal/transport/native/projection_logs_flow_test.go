package native_test

import (
	"context"
	"encoding/base64"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	native "asservat.local/asservat/internal/transport/native"
)

type logsProtocolReader struct {
	f       projectionProtocolFixture
	result  query.ProjectionResult
	calls   atomic.Int32
	block   bool
	entered chan struct{}
	joined  chan struct{}
}

func (r *logsProtocolReader) ReadApprovedContext(ctx context.Context, source evidence.NativeContextSource, operation value.NativeOperation, scope query.ContextProjectionScope, until time.Time) (query.ProjectionResult, error) {
	r.calls.Add(1)
	defer close(r.joined)
	close(r.entered)
	if !reflect.DeepEqual(source, r.f.source) || scope != r.f.scope || !operation.Equal(r.f.lease.Operation) || !until.Equal(operation.Until) {
		return query.ProjectionResult{}, contracts.ErrNativeProtocol
	}
	if r.block {
		<-ctx.Done()
		return query.ProjectionResult{}, ctx.Err()
	}
	out := r.result
	if out.Logs != nil {
		page := query.CloneLogPage(*out.Logs)
		out.Logs = &page
	}
	return out, nil
}

func TestNativeSavedLogsProtocolExactBytesACKAndJoinedCancellation(t *testing.T) {
	// Actual H2/mTLS transport and worker/hub state machines; source reading,
	// admission and completion authority are synthetic, not installed SQL proof.
	for _, mode := range []string{"page", "cursor-refusal", "wrong-pod", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			f := newProjectionProtocolFixture(t)
			e := &f.source.Expectation
			e.NativeType, e.DataClass, e.ActionID = artifact.LogsArtifact, "raw", "a0123456789abcdef01234567"
			e.Logs = &artifact.LogCapture{ActionID: e.ActionID, BeforeMillis: 1000, TimeoutMillis: 10000, Streams: "combined", MaxNativeBytes: e.Registration.NativeLimit}
			s := &f.scope
			s.NativeType, s.SourceFormat, s.DisplayVersion = artifact.LogsArtifact, artifact.LogFormat, query.LogQueryDisplayVersion
			s.Selection, s.SourceProjectionDigest = query.LineSelection{}, artifact.Digest{}
			s.Logs, s.RawGrantID = query.LogWindow{Limit: 10}, s.CaseID
			at := time.Now().UTC()
			page := query.LogPage{Version: s.Version, PodUID: s.PodUID, WindowStart: at.Add(-time.Second), WindowEnd: at, OriginCount: 1, CompleteOrigins: 1, GappedOrigins: 1, UnknownTimestampOrigins: 1, TotalFragments: 1, SourceBytes: 3, Entries: []query.LogEntry{{Origin: artifact.LogOrigin{Record: "origin", ContainerKind: "regular", ContainerName: "app", Source: "current", Stream: "combined"}, Line: 1, EndLine: true, Data: base64.StdEncoding.EncodeToString([]byte{0xff, 0, '\n'})}}}
			if !f.source.Valid(s.Version) || !s.Valid() || !page.ValidShape(s.Logs.Selection(s.CaseID, s.ArtifactID), s.Version, s.PodUID) {
				t.Fatal("invalid protocol fixture", e.Validate())
			}
			r := &logsProtocolReader{f: f, result: query.ProjectionResult{Logs: &page}, entered: make(chan struct{}), joined: make(chan struct{})}
			switch mode {
			case "cursor-refusal":
				r.result = query.ProjectionResult{InvalidCursor: true}
			case "wrong-pod":
				page.PodUID = "replacement"
			case "cancel":
				r.block = true
			}
			result, err := evidence.NewRegionalApprovedResult(f.ctx, f.target, r, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { result.Close(); _ = result.Wait(context.Background()) })
			var completed atomic.Int32
			op, client := f.operation(t, func(context.Context, value.NativeLease) error { completed.Add(1); return nil })
			stream, err := client.Open(f.ctx, f.hello)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = stream.Close() })
			done := make(chan projectionProtocolOutcome, 1)
			go func() {
				defer stream.Close()
				state, err := native.RunWorkerConversation(f.ctx, stream, f.hello, f.target, f.lease.Operation.WorkerPublicKey, result)
				done <- projectionProtocolOutcome{state, err}
			}()
			if mode == "cancel" {
				select {
				case <-r.entered:
				case <-f.ctx.Done():
					t.Fatal("reader did not start")
				}
				_ = op.Close()
			}
			got, err := op.Projection(f.ctx)
			positive := mode == "page" || mode == "cursor-refusal"
			if positive {
				if err != nil || !reflect.DeepEqual(got, r.result) {
					t.Fatal("logs exact result lost", err)
				}
				if err := op.AcknowledgeProjection(f.ctx); err != nil {
					t.Fatal("ACK", err)
				}
			} else if err == nil || got.Logs != nil {
				t.Fatal("invalid/cancelled logs disclosed")
			}
			out := projectionProtocolReceive(t, f.ctx, done)
			if positive {
				if out.err != nil || out.state.State != contracts.NativeJoined || completed.Load() != 1 {
					t.Fatal("positive join", out, completed.Load())
				}
			} else if out.err == nil || completed.Load() != 0 {
				t.Fatal("negative operation completed", out, completed.Load())
			}
			select {
			case <-r.joined:
			case <-f.ctx.Done():
				t.Fatal("reader did not join")
			}
			if r.calls.Load() != 1 {
				t.Fatal("source read repeated", r.calls.Load())
			}
		})
	}
}
