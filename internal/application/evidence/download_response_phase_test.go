package evidence

import (
	"context"
	"testing"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	identityvalue "asservat.local/asservat/internal/domain/identity"
)

type responsePhaseSource struct {
	*responseTransferFixture
	described        identities.CurrentIdentity
	describes, reads int
	mode             string
	metadata         artifact.NativeDownloadMetadata
}

func (s *responsePhaseSource) DescribeCurrent(ctx context.Context, b identities.CurrentIdentity, session artifact.DownloadSession, a artifact.DownloadAuthority) (artifact.NativeDownloadMetadata, int64, error) {
	s.describes++
	s.described = b
	m, n, e := s.responseTransferFixture.Describe(ctx, session, a)
	s.now = s.now.Add(4 * time.Second) // joined metadata observation uses most of one lease
	switch s.mode {
	case "revoked":
		s.fail = "authority"
	case "shorter-retention":
		s.a.AccessUntil = s.now.Add(10 * time.Second)
		s.a.DeleteBy = s.now.Add(20 * time.Second)
	}
	return m, n, e
}
func (s *responsePhaseSource) ReadChunkCurrent(ctx context.Context, b identities.CurrentIdentity, l artifact.DownloadDeliveryLease, o, n int64) (NativeResponseChunk, error) {
	s.reads++
	if b == s.described {
		return NativeResponseChunk{}, artifact.ErrDownloadExpired
	}
	s.now = s.now.Add(2 * time.Second) // first fresh content admission remains within its own original bound
	return s.responseTransferFixture.ReadChunk(ctx, l, o, n)
}

var _ CurrentNativeResponseSource = (*responsePhaseSource)(nil)

func (s *responsePhaseSource) AcknowledgeNativeChunk(ctx context.Context, l artifact.DownloadDeliveryLease, o, n int64) error {
	if ctx.Err() != nil || !l.Allows(o, n, s.now) || o+n != s.emitted {
		return artifact.ErrDownloadUnavailable
	}
	return nil
}
func (s *responsePhaseSource) OpenDownloadResponse(ctx context.Context, m artifact.NativeDownloadMetadata, r artifact.DownloadResponse) (DownloadResponseSink, error) {
	s.metadata = m
	return s.responseTransferFixture.OpenDownloadResponse(ctx, m, r)
}
func TestNativeResponseFreshBatchBetweenJoinedMetadataAndContent(t *testing.T) {
	for _, mode := range []string{"success", "revoked", "shorter-retention"} {
		t.Run(mode, func(t *testing.T) {
			f, transfer, request := newResponseTransferFixture(t, 17)
			source := &responsePhaseSource{responseTransferFixture: f, mode: mode}
			originalEnd := request.HardUntil
			err := transfer.Transfer(context.Background(), f, request, source, source)
			if mode == "revoked" {
				if err == nil || f.begins != 0 || source.reads != 0 || f.s.ChargedOutput != 0 {
					t.Fatal("changed rights admitted content", err)
				}
			} else {
				if err != nil {
					t.Fatal("joined metadata consumed content observation", err)
				}
				if f.s.State != artifact.DownloadCompleted || f.batches != 2 || source.reads != 1 {
					t.Fatal("unexpected admission/retry", f.batches, source.reads)
				}
				if f.r.Until.After(originalEnd) || f.r.Until.After(f.a.AccessUntil) {
					t.Fatal("original deadline extended")
				}
				if mode == "shorter-retention" && (source.metadata.ReadUntil != f.a.AccessUntil || source.metadata.DeleteBy != f.a.DeleteBy) {
					t.Fatal("managed bounds were not intersected")
				}
			}
			if source.describes != 1 {
				t.Fatal("metadata observation repeated")
			}
			if _, e := source.described.ResolveIdentity(context.Background()); e == nil {
				t.Fatal("old observation revived")
			}
		})
	}
}

// A fresh batch is still bound to the original actor/client. No metadata fact
// can authorize a changed principal or let cancellation start a new batch.
type responseChangedReader struct {
	*responseTransferFixture
	mode   string
	cancel context.CancelFunc
}
type responseChangedBatch struct{ identities.IdentityBatch }

func (b responseChangedBatch) ResolveIdentity(ctx context.Context) (identityvalue.Identity, error) {
	i, e := b.IdentityBatch.ResolveIdentity(ctx)
	i.Principal.ClientID = "different-client"
	return i, e
}
func (r *responseChangedReader) BeginBatch(ctx context.Context) (identities.IdentityBatch, error) {
	b, e := r.responseTransferFixture.BeginBatch(ctx)
	if e == nil && r.batches == 2 {
		if r.mode == "cancel" {
			r.cancel()
		} else {
			return responseChangedBatch{b}, nil
		}
	}
	return b, e
}
func TestNativeResponseFreshPhaseCannotChangeClientOrIgnoreCancellation(t *testing.T) {
	for _, mode := range []string{"changed-client", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			f, transfer, request := newResponseTransferFixture(t, 17)
			source := &responsePhaseSource{responseTransferFixture: f}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			reader := &responseChangedReader{f, mode, cancel}
			if err := transfer.Transfer(ctx, reader, request, source, source); err == nil {
				t.Fatal("changed phase admitted")
			}
			if f.begins != 0 || source.reads != 0 || source.describes != 1 {
				t.Fatal("phase denial caused effects or repeated metadata")
			}
		})
	}
}
