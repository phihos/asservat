package artifact

import (
	"errors"
	"testing"
	"time"
)

func streamingTestPlan(t *testing.T, native int64) StreamingPlan {
	t.Helper()
	at := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	return StreamingPlan{Registration: Registration{Location: Location{ClusterID: "10000000-0000-4000-8000-000000000001", ArtifactID: "10000000-0000-4000-8000-000000000002", AttemptID: "10000000-0000-4000-8000-000000000003"}, StoreID: "10000000-0000-4000-8000-000000000004", AllocationID: "10000000-0000-4000-8000-000000000005", PoolRevision: 1, AllocationRevision: 1, NativeLimit: native, AnchorAt: at, WriteUntil: at.Add(time.Minute), ExpiresAt: at.Add(time.Hour), DeleteBy: at.Add(2 * time.Hour)}, WriterEpoch: "10000000-0000-4000-8000-000000000006"}
}

func TestStreamingPlanBounds(t *testing.T) {
	p := streamingTestPlan(t, StreamingNativeLimit)
	if p.Validate() != nil || p.PartLimit() != StreamingMaxParts || p.TemporaryBytes() != p.Registration.Limits()[0] {
		t.Fatal("256 MiB plan", p.PartLimit(), p.TemporaryBytes())
	}
	for _, native := range []int64{FrameBytes, StreamingNativeLimit + 1} {
		if streamingTestPlan(t, native).Validate() == nil {
			t.Fatal("plan outside the streaming band accepted", native)
		}
	}
	noWriter := streamingTestPlan(t, 64<<20)
	noWriter.WriterEpoch = ""
	if noWriter.Validate() == nil {
		t.Fatal("plan without accepted writer accepted")
	}
}

func TestStreamingJournalOneUseClaims(t *testing.T) {
	p := streamingTestPlan(t, 20<<20)
	var s StreamingState
	step := func(x StreamingStep) (bool, error) {
		t.Helper()
		next, fresh, err := s.Advance(p, x)
		if err == nil {
			s = next
		}
		return fresh, err
	}
	if fresh, err := step(StreamingStep{Kind: StreamUpload, UploadID: "u"}); err == nil || fresh {
		t.Fatal("upload recorded before create claim")
	}
	if fresh, err := step(StreamingStep{Kind: StreamClaimCreate}); err != nil || !fresh {
		t.Fatal("create claim", err)
	}
	if fresh, err := step(StreamingStep{Kind: StreamClaimCreate}); err != nil || fresh {
		t.Fatal("create claim refreshed", err)
	}
	if _, err := step(StreamingStep{Kind: StreamUpload, UploadID: "upload-1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := step(StreamingStep{Kind: StreamUpload, UploadID: "upload-2"}); !errors.Is(err, ErrIntegrity) {
		t.Fatal("upload identity replaced", err)
	}
	part := func(n int, b int64) StreamingPart { return StreamingPart{Number: n, Bytes: b, SHA256: Digest{byte(n)}} }
	if fresh, err := step(StreamingStep{Kind: StreamClaimPart, Part: part(1, StreamingPartBytes)}); err != nil || !fresh {
		t.Fatal("part 1 claim", err)
	}
	if _, err := step(StreamingStep{Kind: StreamClaimPart, Part: part(2, StreamingPartBytes)}); err == nil {
		t.Fatal("next part claimed before previous acknowledgement")
	}
	if fresh, err := step(StreamingStep{Kind: StreamClaimPart, Part: part(1, StreamingPartBytes)}); err != nil || fresh {
		t.Fatal("exact part replay must not refresh", err)
	}
	changed := part(1, StreamingPartBytes)
	changed.SHA256 = Digest{9}
	if _, err := step(StreamingStep{Kind: StreamClaimPart, Part: changed}); !errors.Is(err, ErrIntegrity) {
		t.Fatal("part content replaced", err)
	}
	ack := part(1, StreamingPartBytes)
	ack.ETag = `"e1"`
	if _, err := step(StreamingStep{Kind: StreamAckPart, Part: ack}); err != nil {
		t.Fatal(err)
	}
	for _, x := range []StreamingPart{part(2, StreamingPartBytes), part(3, 4<<20)} {
		if _, err := step(StreamingStep{Kind: StreamClaimPart, Part: x}); err != nil {
			t.Fatal("claim", x.Number, err)
		}
		x.ETag = `"e"`
		if _, err := step(StreamingStep{Kind: StreamAckPart, Part: x}); err != nil {
			t.Fatal("ack", x.Number, err)
		}
	}
	if _, err := step(StreamingStep{Kind: StreamClaimPart, Part: part(4, 1)}); err == nil {
		t.Fatal("part after a short part accepted")
	}
	total := 2*StreamingPartBytes + 4<<20
	if fresh, err := step(StreamingStep{Kind: StreamClaimComplete, Bytes: total, SHA256: Digest{7}}); err != nil || !fresh {
		t.Fatal("complete claim", err)
	}
	if _, err := step(StreamingStep{Kind: StreamClaimComplete, Bytes: total, SHA256: Digest{8}}); !errors.Is(err, ErrIntegrity) {
		t.Fatal("completion expectation replaced", err)
	}
	if _, err := step(StreamingStep{Kind: StreamRelease, At: time.Now()}); err == nil {
		t.Fatal("temporary charge released without verified object or proven abort")
	}
	receipt := CopyReceipt{VersionID: "v1", ETag: `"final"`, Bytes: total, SHA256: Digest{7}}
	if _, err := step(StreamingStep{Kind: StreamAckComplete, Receipt: receipt}); err != nil {
		t.Fatal(err)
	}
	if _, err := step(StreamingStep{Kind: StreamRelease, At: time.Now()}); err != nil {
		t.Fatal("release after verified object", err)
	}
	if _, err := step(StreamingStep{Kind: StreamClaimCreate}); err == nil {
		t.Fatal("journal changed after release")
	}
}

func TestStreamingJournalAbortRelease(t *testing.T) {
	p := streamingTestPlan(t, 20<<20)
	s, _, _ := StreamingState{}.Advance(p, StreamingStep{Kind: StreamClaimCreate})
	s, _, _ = s.Advance(p, StreamingStep{Kind: StreamUpload, UploadID: "u"})
	if _, _, err := s.Advance(p, StreamingStep{Kind: StreamRelease, At: time.Now(), Aborted: true}); err != nil {
		t.Fatal("proven abort release", err)
	}
	over := StreamingState{CreateSpent: true, UploadID: "u"}
	for i := 1; i <= p.PartLimit()+1; i++ {
		over.Parts = append(over.Parts, StreamingPart{Number: i, Bytes: StreamingPartBytes, SHA256: Digest{1}, ETag: `"e"`})
	}
	if over.Validate(p) == nil {
		t.Fatal("parts beyond the plan accepted")
	}
}
