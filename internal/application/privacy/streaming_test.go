package privacy

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

// In-memory journal using the real domain transitions.
type memoryJournal struct{ state artifact.StreamingState }

func (j *memoryJournal) AdvanceStreaming(_ context.Context, p artifact.StreamingPlan, x artifact.StreamingStep) (artifact.StreamingState, bool, error) {
	if x.Kind == artifact.StreamRelease {
		x.At = time.Now()
	}
	next, fresh, err := j.state.Advance(p, x)
	if err == nil {
		j.state = next
	}
	return next, fresh, err
}

type memoryObjects struct {
	failPart, failComplete bool
	parts, aborts          int
	absent                 bool
}

func (o *memoryObjects) CreateUpload(context.Context, artifact.Location) (string, error) {
	return "upload", nil
}
func (o *memoryObjects) UploadPart(_ context.Context, _ artifact.Location, _ string, p artifact.StreamingPart, _ []byte) (string, error) {
	o.parts++
	if o.failPart {
		return "", errors.New("uncertain")
	}
	return `"e"`, nil
}
func (o *memoryObjects) CompleteUpload(_ context.Context, _ artifact.Location, _ string, _ []artifact.StreamingPart, size int64, sum artifact.Digest) (artifact.CopyReceipt, error) {
	if o.failComplete {
		return artifact.CopyReceipt{}, errors.New("uncertain")
	}
	return artifact.CopyReceipt{VersionID: "v", ETag: `"f"`, Bytes: size, SHA256: sum}, nil
}
func (o *memoryObjects) AbortUpload(context.Context, artifact.Location, string) error {
	o.aborts++
	return nil
}
func (o *memoryObjects) UploadAbsent(context.Context, artifact.Location, string) (bool, error) {
	return o.absent, nil
}
func (o *memoryObjects) VerifyStreaming(context.Context, artifact.Location, artifact.CopyReceipt, int64) error {
	return nil
}

func streamingUnitPlan(native int64) artifact.StreamingPlan {
	at := time.Now().UTC().Truncate(time.Microsecond)
	return artifact.StreamingPlan{Registration: artifact.Registration{Location: artifact.Location{ClusterID: "10000000-0000-4000-8000-000000000001", ArtifactID: "10000000-0000-4000-8000-000000000002", AttemptID: "10000000-0000-4000-8000-000000000003"}, StoreID: "10000000-0000-4000-8000-000000000004", AllocationID: "10000000-0000-4000-8000-000000000005", PoolRevision: 1, AllocationRevision: 1, NativeLimit: native, AnchorAt: at, WriteUntil: at.Add(time.Minute), ExpiresAt: at.Add(time.Hour), DeleteBy: at.Add(2 * time.Hour)}, WriterEpoch: "10000000-0000-4000-8000-000000000006"}
}

func TestStreamingWriterNeverRetriesUncertainWork(t *testing.T) {
	ctx := context.Background()
	plan := streamingUnitPlan(20 << 20)
	journal, objects := &memoryJournal{}, &memoryObjects{failPart: true}
	w, err := NewStreamingWriter(ctx, plan, journal, objects)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.Write(ctx, make([]byte, artifact.StreamingPartBytes)); err == nil || objects.parts != 1 {
		t.Fatal("uncertain part not surfaced once", err)
	}
	if err = w.Write(ctx, []byte{1}); err == nil || objects.parts != 1 {
		t.Fatal("writer continued after an uncertain part")
	}
	// The claimed-but-unacknowledged part keeps its charge until abort is proven.
	objects.absent = false
	if err = ReleaseStreaming(ctx, plan, journal.state, journal, objects); err == nil || objects.aborts != 1 {
		t.Fatal("released without inventory absence", err)
	}
	objects.absent = true
	if err = ReleaseStreaming(ctx, plan, journal.state, journal, objects); err != nil || journal.state.ReleasedAt.IsZero() || !journal.state.Aborted {
		t.Fatal("proven abort release", err)
	}
	if _, err = NewStreamingWriter(ctx, plan, journal, objects); err == nil {
		t.Fatal("released journal reused")
	}
}

func TestStreamingWriterUncertainCompletionKeepsCharge(t *testing.T) {
	ctx := context.Background()
	plan := streamingUnitPlan(20 << 20)
	journal, objects := &memoryJournal{}, &memoryObjects{failComplete: true, absent: true}
	w, err := NewStreamingWriter(ctx, plan, journal, objects)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.Write(ctx, make([]byte, 9<<20)); err != nil {
		t.Fatal(err)
	}
	if _, err = w.Finish(ctx); err == nil || !journal.state.CompleteSpent || journal.state.Receipt != nil {
		t.Fatal("uncertain completion", err)
	}
	if err = ReleaseStreaming(ctx, plan, journal.state, journal, objects); err == nil || objects.aborts != 0 {
		t.Fatal("uncertain completion released or aborted", err)
	}
}

func TestStreamingWriterStopsAtPlanBound(t *testing.T) {
	ctx := context.Background()
	plan := streamingUnitPlan(9 << 20) // just above one frame
	journal, objects := &memoryJournal{}, &memoryObjects{}
	w, err := NewStreamingWriter(ctx, plan, journal, objects)
	if err != nil {
		t.Fatal(err)
	}
	over := make([]byte, plan.TemporaryBytes()+1)
	if err = w.Write(ctx, over); err == nil {
		if _, err = w.Finish(ctx); err == nil {
			t.Fatal("output beyond the plan's data ceiling accepted")
		}
	}
	if len(journal.state.Parts) > plan.PartLimit() {
		t.Fatal("parts beyond plan")
	}
}
