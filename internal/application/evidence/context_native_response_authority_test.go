package evidence

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

// Warm immutable native facts are synthetic; the response, request owner,
// authority handoff and both attachment reads are the real C14 composition.
func TestContextNativeResponseCheckedMetadataDoesNotReconstructAuthority(t *testing.T) {
	f, sql, runtime, expected := warmContextRuntimeFixture(t)
	source, err := NewContextNativeResponse(t.Context(), runtime)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	original := f.a
	got, _, err := source.describeChecked(t.Context(), f, f.s, original)
	if err != nil || got != expected || sql.reads != 2 || f.count("current-authority") != 0 {
		t.Fatal("checked metadata repeated full authority or skipped SQL", err, sql.reads, f.count("current-authority"))
	}
	if f.a != original {
		t.Fatal("handoff changed the producer's authority")
	}
	// The direct interface remains a fresh full check for other consumers.
	direct, err := NewContextNativeResponse(t.Context(), runtime)
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Close()
	if _, _, err := direct.DescribeCurrent(t.Context(), f, f.s, original); err != nil || f.count("current-authority") != 1 {
		t.Fatal("direct metadata bypassed fresh authority", err, f.count("current-authority"))
	}
}

func TestContextNativeResponseCheckedChunkStillReachesCurrentSQL(t *testing.T) {
	f, sql, runtime, _ := warmContextRuntimeFixture(t)
	source, err := NewContextNativeResponse(t.Context(), runtime)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if _, _, err := source.describeChecked(t.Context(), f, f.s, f.a); err != nil {
		t.Fatal(err)
	}
	// An already-checked response must reach the retained SQL fence without
	// consulting the duplicate full authorizer. This source denies at SQL and
	// intentionally performs no native exchange, key operation or byte read.
	f.failure = "current-authority"
	denied := &boundWorkerAttachments{contextAttachmentFixture: sql, err: artifact.ErrDownloadUnavailable}
	runtime.config.Workers = denied
	lease := artifact.DownloadDeliveryLease{ResponseID: f.s.ID, WindowID: f.s.ID, OwnerID: f.s.ID, Generation: 1, Sequence: 1, Offset: 0, Length: 1, StartedAt: f.now, Until: f.a.ValidUntil, Authority: f.a}
	if !lease.Valid(f.now) {
		t.Fatal("synthetic delivery lease invalid")
	}
	before := sql.reads
	chunk, err := source.readChunkChecked(t.Context(), f, lease, 0, 1)
	if err == nil || len(chunk.Bytes) != 0 || sql.reads != before+1 || f.count("current-authority") != 0 {
		t.Fatal("checked chunk reconstructed authority or bypassed current SQL", err, sql.reads, f.count("current-authority"))
	}
}

func TestContextNativeResponseCheckedAuthorityPreservesOriginalCutoffs(t *testing.T) {
	// The identity cutoff is the coordinator's: it narrows ValidUntil before
	// the handoff, which never reads identity again (ADR-312).
	for _, cutoff := range []string{"caller", "session", "authority"} {
		t.Run(cutoff, func(t *testing.T) {
			f, sql, runtime, metadata := warmContextRuntimeFixture(t)
			original := f.a
			short := f.now.Add(time.Second)
			ctx := t.Context()
			switch cutoff {
			case "caller":
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, short)
				defer cancel()
			case "session":
				f.s.Deadline = short
				// Make this an originally short session/worker fixture. Merely
				// changing a session after priming its immutable metadata key
				// correctly refuses a mismatched original worker/key instead.
				f.enrollment.Worker.Intent.RunUntil = short
				sql.value.Intent = f.enrollment.Worker.Intent
				key, err := contextMetadataKey(f.s, sql.value, original)
				if err != nil || !key.valid() {
					t.Fatal("short original fixture", err)
				}
				runtime.metadata.close()
				runtime.metadata = newContextNativeMetadata(func() time.Time { return f.now })
				_, release, err := runtime.metadata.get(ctx, key, true, false, func(context.Context) (artifact.NativeDownloadMetadata, error) { return metadata, nil })
				if err != nil {
					t.Fatal("short original metadata", err)
				}
				release()
			case "authority":
				original.ValidUntil = short
			}
			reads := 0
			runtime.config.Workers = initialAuthorityAttachment{ContextDownloadAttachments: sql, before: func(call context.Context, a artifact.DownloadAuthority) {
				reads++
				until, ok := call.Deadline()
				if !ok || until.After(short) || a.ValidUntil.After(short) || a.CheckedAt != original.CheckedAt || a.DecisionDigest != original.DecisionDigest {
					t.Error("handoff replaced an original cutoff or decision")
				}
			}}
			source, err := NewContextNativeResponse(ctx, runtime)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			if _, _, err := source.describeChecked(ctx, f, f.s, original); err != nil || reads != 2 || f.count("current-authority") != 0 {
				t.Fatal("bounded handoff failed or reconstructed authority", err, reads, f.count("current-authority"))
			}
		})
	}
}

// The handoff consumes the coordinator's authority without reading identity
// (ADR-312); a changed identity after the coordinator's check cannot stop it.
func TestContextNativeResponseCheckedAuthorityRejectsChangedScope(t *testing.T) {
	for _, change := range []string{"scope", "expired", "cancelled"} {
		t.Run(change, func(t *testing.T) {
			f, sql, runtime, _ := warmContextRuntimeFixture(t)
			a := f.a
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			source, err := NewContextNativeResponse(ctx, runtime)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			switch change {
			case "scope":
				a.Scope.ArtifactID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
			case "expired":
				a.ValidUntil = f.now
			case "cancelled":
				cancel()
			}
			if _, _, err := source.describeChecked(ctx, f, f.s, a); err == nil || sql.reads != 0 {
				t.Fatal("invalid handoff reached SQL", change, sql.reads, err)
			}
		})
	}
}

func TestContextNativeResponseCheckedAuthorityIgnoresLaterIdentity(t *testing.T) {
	f, sql, runtime, _ := warmContextRuntimeFixture(t)
	f.identity.Policy.Generation++
	f.identity.Scopes = []string{"evidence:read"}
	source, err := NewContextNativeResponse(t.Context(), runtime)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if _, _, err := source.describeChecked(t.Context(), f, f.s, f.a); err != nil || sql.reads == 0 || f.count("current-authority") != 0 {
		t.Fatal("handoff observed identity again", err, sql.reads, f.count("current-authority"))
	}
}
