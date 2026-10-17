package evidence

import (
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"context"
	"sync/atomic"
	"testing"
	"time"
)

type nativeReadFixture struct {
	reads   atomic.Int32
	body    []byte
	entered chan struct{}
	fail    bool
}

func (f *nativeReadFixture) ReadNativeContext(ctx context.Context, s NativeContextSource, o value.NativeOperation, window string, end time.Time) ([]byte, error) {
	f.reads.Add(1)
	if f.entered != nil {
		close(f.entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if f.fail {
		return nil, artifact.ErrDownloadUnavailable
	}
	f.body = []byte(`{"synthetic":"pod-status"}`)
	return f.body, nil
}
func nativeResultFixture(t *testing.T) (*RegionalContextResult, *nativeReadFixture, NativeContextSource, value.NativeOperation) {
	f, _, request := downloadWorkerTest(t)
	id := f.s.ID
	now := time.Now()
	worker := value.WorkerCredentialTarget{InstallationID: id, SessionID: id, WorkerID: id, PodUID: id, CreatedAt: now, RunUntil: now.Add(time.Minute)}
	reader := &nativeReadFixture{}
	r, e := NewRegionalContextResult(context.Background(), worker, reader, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		r.Close()
		if e := r.Wait(context.Background()); e != nil {
			t.Error(e)
		}
	})
	source := NativeContextSource{Expectation: request.Expectation, Copies: request.Copies}
	o := nativeLeaseFixture().Operation
	o.Reference = value.NativeReference{InstallationID: id, SessionID: id, WorkerID: id, OperationID: id, Fence: 1}
	o.WorkerPodUID = id
	o.SourceVersion = ContextCopiesDigest(source.Copies)
	o.Processing.Location = source.Expectation.Registration.Location
	o.Path.TargetClusterID = o.Processing.Location.ClusterID
	o.Path.StoreID = source.Expectation.Registration.StoreID
	return r, reader, source, o
}
func TestNativeRegionalResultCommitGatesObserveAndNoRepeatedDecrypt(t *testing.T) {
	r, reader, source, o := nativeResultFixture(t)
	ctx, stop := context.WithDeadline(context.Background(), o.Until)
	defer stop()
	metadata, e := r.Prepare(ctx, o, source)
	if e != nil {
		t.Fatal(e)
	}
	if metadata.Size < 1 {
		t.Fatal("metadata missing")
	}
	for _, b := range reader.body {
		if b != 0 {
			t.Fatal("preparation payload retained")
		}
	}
	observe := o
	observe.Kind = value.NativeObserve
	observe.Reference.Fence++
	if _, e = r.Observe(ctx, observe); e == nil {
		t.Fatal("unacknowledged preparation disclosed")
	}
	if e = r.Commit(ctx, o); e != nil {
		t.Fatal(e)
	}
	if got, e := r.Observe(ctx, observe); e != nil || got != metadata {
		t.Fatal("committed metadata unavailable", e)
	}
	if _, e = r.Prepare(ctx, o, source); e == nil {
		t.Fatal("repeated native preparation")
	}
	if reader.reads.Load() != 1 {
		t.Fatal("observe retried decrypt")
	}
	response := o
	response.Kind = value.NativeResponse
	response.Reference.Fence += 2
	body, e := r.Read(ctx, response, source, o.ParentID, 0, metadata.Size)
	if e != nil || int64(len(body)) != metadata.Size {
		t.Fatal("paid content read", e)
	}
	clear(body)
	if reader.reads.Load() != 2 {
		t.Fatal("content must be a separate exact key operation")
	}
}
func TestNativeRegionalResultFailedReadCannotRetryAndCloseJoins(t *testing.T) {
	r, reader, source, o := nativeResultFixture(t)
	ctx, stop := context.WithDeadline(context.Background(), o.Until)
	defer stop()
	reader.fail = true
	if _, e := r.Prepare(ctx, o, source); e == nil {
		t.Fatal("failed read accepted")
	}
	reader.fail = false
	if _, e := r.Prepare(ctx, o, source); e == nil || reader.reads.Load() != 1 {
		t.Fatal("unknown read retried")
	}
	r, reader, source, o = nativeResultFixture(t)
	reader.entered = make(chan struct{})
	done := make(chan error, 1)
	go func() { _, e := r.Prepare(ctx, o, source); done <- e }()
	<-reader.entered
	r.Close()
	if e := r.Wait(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e := <-done; e == nil {
		t.Fatal("cancelled read retained metadata")
	}
}

func TestNativeRegionalObservationRejectsReplacementAndMissingResult(t *testing.T) {
	r, reader, source, o := nativeResultFixture(t)
	ctx, stop := context.WithDeadline(context.Background(), o.Until)
	defer stop()
	if _, e := r.Prepare(ctx, o, source); e != nil {
		t.Fatal(e)
	}
	if e := r.Commit(ctx, o); e != nil {
		t.Fatal(e)
	}
	observe := o
	observe.Kind = value.NativeObserve
	observe.Reference.Fence++
	for _, mutate := range []func(*value.NativeOperation){
		func(v *value.NativeOperation) { v.WorkerPodUID = "22222222-2222-4222-8222-222222222222" },
		func(v *value.NativeOperation) { v.WorkerPublicKey[0]++ },
		func(v *value.NativeOperation) { v.SourceVersion[0]++ },
		func(v *value.NativeOperation) { v.ParentID = "22222222-2222-4222-8222-222222222222" },
		func(v *value.NativeOperation) { v.Generation++ },
		func(v *value.NativeOperation) { v.Reference.WorkerID = "22222222-2222-4222-8222-222222222222" },
	} {
		wrong := observe
		mutate(&wrong)
		if _, e := r.Observe(ctx, wrong); e == nil {
			t.Fatal("replaced preparation/source/process observed")
		}
	}
	if reader.reads.Load() != 1 {
		t.Fatal("denied metadata observation retried a read")
	}
	response := o
	response.Kind = value.NativeResponse
	response.Reference.Fence++
	response.WorkerPublicKey[0]++
	if _, e := r.Read(ctx, response, source, o.ParentID, 0, 1); e == nil || reader.reads.Load() != 1 {
		t.Fatal("replacement process consumed a new read")
	}
	empty, never, _, _ := nativeResultFixture(t)
	if _, e := empty.Observe(ctx, observe); e == nil || never.reads.Load() != 0 {
		t.Fatal("missing process result silently reprepared")
	}
}
