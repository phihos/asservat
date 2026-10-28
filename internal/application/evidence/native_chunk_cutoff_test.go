package evidence

import (
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"context"
	"testing"
	"time"
)

type cutoffResponsePort struct {
	*responseTransferFixture
	cutoff       time.Time
	writes, acks int
}

func (s *cutoffResponsePort) DescribeCurrent(c context.Context, _ identities.CurrentIdentity, session artifact.DownloadSession, a artifact.DownloadAuthority) (artifact.NativeDownloadMetadata, int64, error) {
	return s.Describe(c, session, a)
}
func (s *cutoffResponsePort) ReadChunkCurrent(c context.Context, _ identities.CurrentIdentity, l artifact.DownloadDeliveryLease, o, n int64) (NativeResponseChunk, error) {
	chunk, err := s.ReadChunk(c, l, o, n)
	chunk.NativeUntil = s.cutoff
	return chunk, err
}
func (s *cutoffResponsePort) OpenDownloadResponse(context.Context, artifact.NativeDownloadMetadata, artifact.DownloadResponse) (DownloadResponseSink, error) {
	return s, nil
}
func (s *cutoffResponsePort) WriteChunk(c context.Context, l artifact.DownloadDeliveryLease, _ int64, _ []byte) (int64, error) {
	s.writes++
	deadline, ok := c.Deadline()
	if !ok || deadline.After(s.cutoff) || !s.cutoff.Before(l.Until) {
		return 0, artifact.ErrIntegrity
	}
	<-c.Done() // actual blocked final sink under a shorter worker-token bound
	return 0, c.Err()
}
func (s *cutoffResponsePort) AcknowledgeNativeChunk(context.Context, artifact.DownloadDeliveryLease, int64, int64) error {
	s.acks++
	return nil
}

func TestResponseTransferCarriesNativeCutoffThroughBlockedFinalSink(t *testing.T) {
	f, service, request := newResponseTransferFixture(t, 1)
	source := &cutoffResponsePort{responseTransferFixture: f, cutoff: time.Now().Add(100 * time.Millisecond)}
	parent, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	started := time.Now()
	if err := service.Transfer(parent, f, request, source, source); err == nil {
		t.Fatal("blocked sink passed native cutoff")
	}
	if time.Since(started) > time.Second || source.writes != 1 || source.acks != 0 || f.emitted != 0 {
		t.Fatal("native cutoff was not preserved through write and ACK", source.writes, source.acks, f.emitted)
	}
	if f.s.ChargedOutput != 1 || f.s.State == artifact.DownloadCompleted {
		t.Fatal("failed final sink refunded or completed")
	}
}
