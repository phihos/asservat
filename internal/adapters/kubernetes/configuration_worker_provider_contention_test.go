package kubernetes

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/fleet"
)

// Only the SQL/audit sinks are synthetic. The actual ConfigurationReconciler,
// independent TrustObserver/OwnerConfigurationObserver, their original serial
// 5-second calls and 1-second post-completion delays, and both concrete native
// readers run on the same exact clients as the provider operation. This tests
// an already acknowledged owner configuration, not first encrypted publication.
type configurationProviderRuntimeSinks struct {
	fleet, owner, fenced atomic.Int32
	mu                   sync.Mutex
	acceptedFleet        fleet.Administration
	first                sync.Once
	accepted             chan struct{}
	admission            *app.WorkerRuntimeAdmission
}

func (*configurationProviderRuntimeSinks) ReadAdministrationBasis(context.Context) (fleet.ObservationBasis, error) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return fleet.ObservationBasis{InstallationID: "11111111-1111-4111-8111-111111111111", Database: fleet.DatabaseIncarnation{StartedAt: now.Add(-time.Hour), DatabaseOID: 42, SchemaVersion: 59}, SemanticVersion: 1, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, nil
}
func (s *configurationProviderRuntimeSinks) ObserveAdministration(ctx context.Context, b fleet.ObservationBasis, a fleet.Administration) error {
	if ctx.Err() != nil || !a.Valid(time.Now()) {
		if s.admission != nil {
			s.admission.InvalidateFleetNotice()
		}
		return fleet.ErrUnavailable
	}
	if s.admission != nil {
		s.admission.NoteFleetObservation(a)
	}
	s.mu.Lock()
	s.acceptedFleet = a
	s.mu.Unlock()
	s.fleet.Add(1)
	if s.admission != nil {
		s.admission.NoteFleetCommitted(ctx, a)
	}
	if s.accepted != nil {
		s.first.Do(func() { close(s.accepted) })
	}
	return nil
}
func (s *configurationProviderRuntimeSinks) FenceAdministration(context.Context, fleet.ObservationBasis, time.Time) error {
	s.fenced.Add(1)
	if s.admission != nil {
		s.admission.InvalidateFleetNotice()
	}
	return nil
}
func (s *configurationProviderRuntimeSinks) ObserveOwnerConfiguration(ctx context.Context, o fleet.OwnerConfigurationObservation) (audit.Receipt, bool, error) {
	if ctx.Err() != nil || !o.Valid(time.Now()) {
		return audit.Receipt{}, false, fleet.ErrUnavailable
	}
	s.owner.Add(1)
	return audit.Receipt{Key: audit.OwnerConfigurationAuditKey(o.Configuration), Version: "synthetic-acknowledged-version", ETag: "synthetic-acknowledged-etag", Bytes: 1, SHA256: artifact.Digest{1}}, true, nil
}
func (s *configurationProviderRuntimeSinks) FenceOwnerConfiguration(context.Context, time.Time) error {
	s.fenced.Add(1)
	return nil
}
func (*configurationProviderRuntimeSinks) WriteOwnerConfiguration(context.Context, fleet.OwnerConfiguration) (audit.Receipt, error) {
	return audit.Receipt{}, fleet.ErrUnavailable
}
func (*configurationProviderRuntimeSinks) AcknowledgeOwnerConfiguration(context.Context, fleet.OwnerConfiguration, audit.Receipt) error {
	return fleet.ErrUnavailable
}

type configurationProviderFleetStart struct {
	reader app.AdministrationReader
	first  sync.Once
	entry  chan struct{}
}

func (s *configurationProviderFleetStart) FleetAdministration(ctx context.Context) (fleet.Administration, error) {
	s.first.Do(func() { close(s.entry) })
	return s.reader.FleetAdministration(ctx)
}

type configurationProviderOwnerStart struct {
	reader app.OwnerConfigurationReader
	first  sync.Once
	entry  chan struct{}
}

func (s *configurationProviderOwnerStart) ReadOwnerConfiguration(ctx context.Context) (fleet.OwnerConfigurationObservation, error) {
	s.first.Do(func() { close(s.entry) })
	return s.reader.ReadOwnerConfiguration(ctx)
}
