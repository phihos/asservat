package evidence

import (
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/authorization"
	"context"
	"time"
)

type WorkerConfigurationReader interface {
	ReadWorkerConfiguration(context.Context) (value.DownloadWorkerObservation, error)
}
type WorkerConfigurationLedger interface {
	ObserveWorkerConfiguration(context.Context, value.DownloadWorkerObservation) (audit.Receipt, bool, error)
	FenceWorkerConfiguration(context.Context, time.Time) error
}
type WorkerConfigurationGuard interface {
	CurrentWorkerConfiguration(context.Context, value.DownloadWorkerProfile) (time.Time, error)
}

// A constructor profile does not activate dispatch. This observer requires
// qualified Kubernetes input, current SQL recovery and separate encrypted audit.
type WorkerConfigurationObserver struct {
	Reader           WorkerConfigurationReader
	Ledger           WorkerConfigurationLedger
	Audit            auditapp.WorkerConfigurationWriter
	Acknowledgements auditapp.WorkerConfigurationAcknowledgements
	Now              func() time.Time
}

func (s *WorkerConfigurationObserver) Observe(ctx context.Context) error {
	if s == nil || ctx == nil || s.Reader == nil || s.Ledger == nil || s.Audit == nil || s.Acknowledgements == nil || s.Now == nil {
		return artifact.ErrInvalid
	}
	start := s.Now()
	o, e := s.Reader.ReadWorkerConfiguration(ctx)
	if e != nil || !o.Valid(s.Now()) || ctx.Err() != nil {
		cleanup, end := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer end()
		_ = s.Ledger.FenceWorkerConfiguration(cleanup, start)
		return artifact.ErrDownloadUnavailable
	}
	r, ok, e := s.Ledger.ObserveWorkerConfiguration(ctx, o)
	if e != nil {
		return e
	}
	if ok {
		if !r.ValidWorkerConfiguration(o.Configuration) {
			return artifact.ErrIntegrity
		}
		return nil
	}
	r, e = s.Audit.WriteWorkerConfiguration(ctx, o.Configuration)
	if e != nil {
		return e
	}
	if !r.ValidWorkerConfiguration(o.Configuration) {
		return artifact.ErrIntegrity
	}
	return s.Acknowledgements.AcknowledgeWorkerConfiguration(ctx, o.Configuration, r)
}
