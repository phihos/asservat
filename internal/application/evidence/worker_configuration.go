package evidence

import (
	"context"

	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/authorization"
)

type WorkerConfigurationReader interface {
	ReadWorkerConfiguration(context.Context) (value.DownloadWorkerObservation, error)
}
type WorkerConfigurationLedger interface {
	ObserveWorkerConfiguration(context.Context, value.DownloadWorkerObservation) (audit.Receipt, bool, error)
}
type WorkerConfigurationGuard interface {
	// CurrentWorkerConfiguration fails unless the profile is the current
	// accepted, audited and unsuspended revision.
	CurrentWorkerConfiguration(context.Context, value.DownloadWorkerProfile) error
}

// A constructor profile does not activate dispatch. This observer requires
// qualified Kubernetes input and separate encrypted audit. A failed read
// leaves the last accepted revision current: it stays valid until a later
// observation replaces it.
type WorkerConfigurationObserver struct {
	Reader           WorkerConfigurationReader
	Ledger           WorkerConfigurationLedger
	Audit            auditapp.WorkerConfigurationWriter
	Acknowledgements auditapp.WorkerConfigurationAcknowledgements
}

func (s *WorkerConfigurationObserver) Observe(ctx context.Context) error {
	if s == nil || ctx == nil || s.Reader == nil || s.Ledger == nil || s.Audit == nil || s.Acknowledgements == nil {
		return artifact.ErrInvalid
	}
	o, e := s.Reader.ReadWorkerConfiguration(ctx)
	if e != nil || !o.Valid() || ctx.Err() != nil {
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
