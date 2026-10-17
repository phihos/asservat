package postgres

import (
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"context"
)

// FirstContextPreparations is selected only by the installed first-context
// runtime. Other Downloads users retain deliberate paid re-preparation.
// Embedding preserves the existing authority/accounting methods; only the
// initial metadata admission receives the stronger one-attempt predicate.
type FirstContextPreparations struct{ *Downloads }

var _ evidence.DownloadSessions = (*FirstContextPreparations)(nil)

func NewFirstContextPreparations(s *Downloads) (*FirstContextPreparations, error) {
	if s == nil || s.ledger == nil || s.retention == nil || s.recovery == nil {
		return nil, artifact.ErrInvalid
	}
	return &FirstContextPreparations{s}, nil
}
func firstContextPreparation(s artifact.DownloadSession, b artifact.DownloadBatch) bool {
	return s.StopProtocol == artifact.DownloadStopProtocol && s.State == artifact.DownloadPreparing && s.Generation == 0 && s.Requests == 0 && s.Active == nil && s.ChargedRead == 0 && s.ChargedOutput == 0 && s.EmittedBytes == 0 && b.Purpose == artifact.DownloadMetadata && b.Offset == 0 && b.OutputBytes == 0 && b.ReadBytes == evidence.ContextDownloadReadWork
}
func (s *FirstContextPreparations) BeginDownloadBatch(ctx context.Context, id string, a artifact.DownloadAuthority, b artifact.DownloadBatch) (audit.DownloadIntent, error) {
	if s == nil || s.Downloads == nil || b.Purpose != artifact.DownloadMetadata {
		return audit.DownloadIntent{}, artifact.ErrInvalid
	}
	return s.Downloads.beginDownloadBatch(ctx, id, a, b, true)
}

func (*FirstContextPreparations) FirstContextPreparationOnly() {}
