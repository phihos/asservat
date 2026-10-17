package evidence

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"context"
	"slices"
	"testing"
)

type remotePreparationFixture struct {
	f                      *downloadWorkerFixture
	r                      ContextDownloadRequest
	reads, commits, closes int
	bad                    bool
	unknown                bool
}

func (f *remotePreparationFixture) PrepareNativeMetadata(ctx context.Context, r ContextDownloadRequest, i audit.DownloadIntent, a artifact.DownloadAuthority, check NativePreparationCheck) (artifact.NativeDownloadMetadata, NativePreparationCommit, error) {
	f.reads++
	if i.Batch.Purpose != artifact.DownloadMetadata || i.SessionID != r.SessionID || !slices.Contains(f.f.calls, "intent-ack") {
		return artifact.NativeDownloadMetadata{}, nil, artifact.ErrDownloadUnavailable
	}
	if _, e := check(ctx); e != nil {
		return artifact.NativeDownloadMetadata{}, nil, e
	}
	m := contextDownloadMetadata(r, f.f.body)
	if f.bad {
		m.Filename = "other.json"
	}
	return m, f, nil
}
func (f *remotePreparationFixture) Commit(context.Context) error {
	f.commits++
	if f.f.s.State != artifact.DownloadReady || !slices.Contains(f.f.calls, "outcome-ack") {
		return artifact.ErrDownloadUnavailable
	}
	if f.unknown {
		return artifact.ErrDownloadUnavailable
	}
	return nil
}
func (f *remotePreparationFixture) Close() error { f.closes++; return nil }
func TestNativePreparationPreservesOutcomeAndFinalGate(t *testing.T) {
	for _, mode := range []string{"success", "outcome-ack", "metadata-permit", "invalid-metadata", "unknown-commit"} {
		t.Run(mode, func(t *testing.T) {
			f, w, r := downloadWorkerTest(t)
			remote := &remotePreparationFixture{f: f, r: r, bad: mode == "invalid-metadata", unknown: mode == "unknown-commit"}
			w.Native = nil
			w.RegionalPreparation = remote
			if mode == "outcome-ack" || mode == "metadata-permit" {
				f.failure = mode
			}
			m, e := w.Prepare(context.Background(), "synthetic", r)
			if mode == "success" {
				if e != nil || m.Size != int64(len(f.body)) {
					t.Fatal("metadata", e)
				}
			} else if e == nil || m != (DownloadMetadata{}) {
				t.Fatal("failed remote preparation disclosed metadata")
			}
			want := 1
			if mode == "outcome-ack" || mode == "invalid-metadata" {
				want = 0
			}
			if remote.commits != want || remote.closes != 1 || remote.reads != 1 {
				t.Fatal("remote lifecycle", remote.commits, remote.closes, remote.reads)
			}
			if slices.Contains(f.calls, "native") || len(f.nativeBacking) != 0 {
				t.Fatal("hub read native payload")
			}
			if mode == "unknown-commit" && f.s.State != artifact.DownloadReady {
				t.Fatal("uncertain commit rewrote positive accounting")
			}
		})
	}
}
func TestNativePreparationDoesNotEnableLegacyContentOrAmbiguousReader(t *testing.T) {
	f, w, r := downloadWorkerTest(t)
	remote := &remotePreparationFixture{f: f, r: r}
	w.RegionalPreparation = remote
	if _, e := w.Prepare(context.Background(), "synthetic", r); e == nil || len(f.calls) != 0 {
		t.Fatal("ambiguous readers admitted")
	}
	w.Native = nil
	if e := w.Transfer(context.Background(), "synthetic", r, DownloadSelection{Length: 1}, f); e == nil || len(f.calls) != 0 {
		t.Fatal("remote metadata enabled legacy raw path")
	}
}
