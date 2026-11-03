package objectstore

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
)

type profileMultipart struct {
	fail                      string
	creates, parts, completes int
}

func (o *profileMultipart) CreateUpload(context.Context, artifact.Location) (string, error) {
	o.creates++
	if o.fail == "create" {
		return "", errors.New("unknown")
	}
	return "u", nil
}
func (o *profileMultipart) UploadPart(_ context.Context, _ artifact.Location, _ string, _ artifact.StreamingPart, _ []byte) (string, error) {
	o.parts++
	if o.fail == "part" {
		return "", errors.New("unknown")
	}
	return "p", nil
}
func (o *profileMultipart) CompleteUpload(_ context.Context, _ artifact.Location, _ string, _ []artifact.StreamingPart, n int64, d artifact.Digest) (artifact.CopyReceipt, error) {
	o.completes++
	if o.fail == "complete" {
		return artifact.CopyReceipt{}, errors.New("unknown")
	}
	return artifact.CopyReceipt{VersionID: "v", ETag: "e", Bytes: n, SHA256: d}, nil
}
func (o *profileMultipart) AbortUpload(context.Context, artifact.Location, string) error {
	return errors.New("unexpected abort")
}
func (o *profileMultipart) UploadAbsent(context.Context, artifact.Location, string) (bool, error) {
	return true, nil
}
func (o *profileMultipart) VerifyStreaming(context.Context, artifact.Location, artifact.CopyReceipt, int64) error {
	return nil
}
func profileStreamFixture(t *testing.T) (*profileStreamingJournal, artifact.StreamingPlan) {
	t.Helper()
	const id = "00000000-0000-4000-8000-000000000001"
	now := time.Now().UTC().Truncate(time.Microsecond)
	r := artifact.Registration{Location: artifact.Location{ClusterID: id, ArtifactID: id, AttemptID: id}, StoreID: id, AllocationID: id, PoolRevision: 1, AllocationRevision: 1, NativeLimit: 16 << 20, AnchorAt: now, WriteUntil: now.Add(time.Minute), ExpiresAt: now.Add(time.Hour), DeleteBy: now.Add(2 * time.Hour)}
	j, err := newProfileStreamingJournal(artifact.ContextExpectation{Profile: &artifact.GoProfileAcquisition{}, Registration: r}, id, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return j, j.plan
}
func TestProfileStreamingNeverRepeatsUnknownEffectsOrReleasesCharges(t *testing.T) {
	for _, failure := range []string{"create", "part", "complete", ""} {
		t.Run(failure, func(t *testing.T) {
			j, plan := profileStreamFixture(t)
			objects := &profileMultipart{fail: failure}
			ctx := context.Background()
			writer, err := privacy.NewStreamingWriter(ctx, plan, j, objects)
			if failure == "create" {
				if err == nil {
					t.Fatal("unknown create accepted")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				err = writer.Write(ctx, make([]byte, 9<<20))
				if failure == "part" {
					if err == nil {
						t.Fatal("unknown part accepted")
					}
				} else {
					if err != nil {
						t.Fatal(err)
					}
					_, err = writer.FinishStored(ctx)
					if (err != nil) != (failure == "complete") {
						t.Fatal("complete result", err)
					}
				}
				beforeParts, beforeComplete := objects.parts, objects.completes
				if err := writer.Write(ctx, []byte{1}); err == nil {
					t.Fatal("finished or failed writer reused")
				}
				if _, err := writer.FinishStored(ctx); err == nil {
					t.Fatal("finish repeated")
				}
				if objects.parts != beforeParts || objects.completes != beforeComplete {
					t.Fatal("unknown effect repeated")
				}
			}
			if _, err := privacy.NewStreamingWriter(ctx, plan, j, objects); err == nil || objects.creates != 1 {
				t.Fatal("attempt reconstructed")
			}
			if _, _, err := j.AdvanceStreaming(ctx, plan, artifact.StreamingStep{Kind: artifact.StreamRelease, At: time.Now(), Aborted: true}); err == nil || !j.state.ReleasedAt.IsZero() {
				t.Fatal("volatile state released durable charge")
			}
		})
	}
}
func TestProfileStreamingRefusesReplacementAndExpiredContext(t *testing.T) {
	for _, change := range []string{"epoch", "attempt", "registration", "cancelled", "expired"} {
		t.Run(change, func(t *testing.T) {
			j, plan := profileStreamFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch change {
			case "epoch":
				plan.WriterEpoch = "22222222-2222-4222-8222-222222222222"
			case "attempt":
				plan.Registration.Location.AttemptID = "22222222-2222-4222-8222-222222222222"
			case "registration":
				plan.Registration.NativeLimit++
			case "cancelled":
				cancel()
			case "expired":
				j.now = func() time.Time { return plan.Registration.WriteUntil }
			}
			if _, fresh, err := j.AdvanceStreaming(ctx, plan, artifact.StreamingStep{Kind: artifact.StreamClaimCreate}); err == nil || fresh || j.state.CreateSpent {
				t.Fatal("unbound effect", err)
			}
		})
	}
}

func TestOneShotProfileFactoryRestrictsArtifactAndBoundPlan(t *testing.T) {
	handle, e, _ := writerFixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("unexpected object effect during preparation") }))
	store := handle.(*preparedContext).producer.store
	const epoch = "00000000-0000-4000-8000-000000000001"
	if _, err := PrepareOneShotProfileArtifact(t.Context(), store, contextWriterTestKeys{}, e, epoch, time.Now); err == nil {
		t.Fatal("pod status selected profile completion")
	}
	e.Profile = &artifact.GoProfileAcquisition{SourceRef: "pprof", EndpointDigest: artifact.Digest{1}, Type: "cpu", Mode: "interval", DurationMillis: 10000}
	e.NativeType, e.DataClass, e.ActionID = artifact.PprofArtifact, "raw", "a0123456789abcdef01234567"
	e.Registration.NativeLimit = 16 << 20
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, badEpoch := range []string{"", "not-an-epoch"} {
		if _, err := PrepareOneShotProfileArtifact(t.Context(), store, contextWriterTestKeys{}, e, badEpoch, time.Now); err == nil {
			t.Fatal("unbound profile", badEpoch)
		}
	}
	prepared, err := PrepareOneShotProfileArtifact(t.Context(), store, contextWriterTestKeys{}, e, epoch, time.Now)
	if err != nil || !prepared.storedOnly {
		t.Fatal("protected profile factory", err)
	}
	journal, ok := prepared.producer.journal.(*profileStreamingJournal)
	if !ok || !journal.plan.Equal(prepared.plan) || journal.plan.WriterEpoch != epoch {
		t.Fatal("profile lost private exact journal")
	}
	generic, err := NewArtifactProducer(store, contextWriterTestKeys{}, journal, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	ordinary, err := generic.Prepare(t.Context(), e, epoch)
	if err != nil || ordinary.storedOnly {
		t.Fatal("generic producer selected receipt-only mode", err)
	}
	e.Registration.NativeLimit = artifact.FrameBytes
	if _, err := PrepareOneShotProfileArtifact(t.Context(), store, contextWriterTestKeys{}, e, epoch, time.Now); err == nil {
		t.Fatal("small path accepted multipart plan")
	}
}

func TestArtifactStoreDiagnosticDoesNotExposeCause(t *testing.T) {
	secret := errors.New("synthetic backend credential or evidence")
	err := artifactStoreError{"multipart-complete", secret}
	if !errors.Is(err, secret) || err.Error() != "artifact store refused at multipart-complete" || err.FixedStep() != "multipart-complete" {
		t.Fatal("unsafe store diagnostic")
	}
}
