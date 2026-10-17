package kubernetes

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
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

func TestConfigurationProviderRuntimeSharedReconcilerContention(t *testing.T) {
	configurationProviderReconcilerContention(t, false, false)
}

func TestConfigurationProviderRuntimeContentionRetainsAcceptedSourceEnd(t *testing.T) {
	configurationProviderReconcilerContention(t, true, false)
}

func TestConfigurationProviderRuntimeScheduledContentionRetainsAcceptedSourceEnd(t *testing.T) {
	configurationProviderReconcilerContention(t, true, true)
}

func configurationProviderReconcilerContention(t *testing.T, retainAccepted, scheduled bool) {
	t.Helper()
	f := newConfigurationProviderRuntimeFixture(t)
	if f.reader.fleet.settings.client != f.reader.worker.client || f.reader.owner.client != f.reader.worker.client || f.reader.fleet.protection.probe != f.reader.worker.guard.probe || f.reader.owner.protection.probe != f.reader.worker.guard.probe {
		t.Fatal("fixture did not retain actual loaded observer/probe aliases")
	}
	for f.observerLimiter.TryAccept() {
	}
	for f.probeLimiter.TryAccept() {
	}
	fixedFleet, fixedOwner, err := NewConfigurationWorkerSourceReaders(f.reader)
	if err != nil {
		t.Fatal(err)
	}
	fleetReader := &configurationProviderFleetStart{reader: fixedFleet, entry: make(chan struct{})}
	ownerReader := &configurationProviderOwnerStart{reader: fixedOwner, entry: make(chan struct{})}
	sinks := &configurationProviderRuntimeSinks{accepted: make(chan struct{})}
	var admission *app.WorkerRuntimeAdmission
	if scheduled {
		admission, err = app.NewWorkerRuntimeAdmission(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer admission.Close()
		sinks.admission = admission
	}
	reconciler := &app.ConfigurationReconciler{
		Fleet: &app.TrustObserver{Settings: fleetReader, Projection: sinks, Now: time.Now},
		Owner: &app.OwnerConfigurationObserver{Reader: ownerReader, Ledger: sinks, Audit: sinks, Acknowledgements: sinks, Now: time.Now},
	}
	root, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- reconciler.Run(root) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("actual reconciler failed joined cancellation")
		}
	}()
	for _, entry := range []chan struct{}{fleetReader.entry, ownerReader.entry} {
		select {
		case <-entry:
		case <-time.After(time.Second):
			t.Fatal("actual independent observer did not enter")
		}
	}
	if retainAccepted {
		select {
		case <-sinks.accepted:
		case <-time.After(5 * time.Second):
			t.Fatal("fleet source never became available within its own original interval")
		}
	}
	// This is deliberately a native-work lower bound: two serial refresh pairs
	// have the same ordering as the actual wrap/unwrap token owners, but include
	// no provider HTTP or SQL delays. A failure here blocks full composition;
	// success alone cannot qualify those concrete credential owners.
	for _, purpose := range []string{"audit-wrap", "audit-unwrap"} {
		operationRoot := root
		var lease *app.WorkerRuntimeAdmissionLease
		if scheduled {
			if purpose == "audit-wrap" {
				lease, err = admission.WaitWrapRefresh(root)
			} else {
				lease, err = admission.WaitUnwrapRefresh(root)
			}
			if err != nil {
				t.Fatal("bounded scheduling", err)
			}
			// Join/release even when a fatal assertion interrupts this iteration.
			defer lease.Release()
			if err = lease.AwaitFleetObservation(); err != nil {
				t.Fatal("independent scheduling observation", err)
			}
			operationRoot = lease.Context()
		}
		originalEnd := time.Now().Add(5 * time.Second)
		if retainAccepted {
			sinks.mu.Lock()
			originalFleet := sinks.acceptedFleet
			sinks.mu.Unlock()
			if !originalFleet.Valid(time.Now()) {
				t.Fatal("stored fleet observation already unavailable")
			}
			// The real RecoveryReader takes min(read-start+5s, row.fresh_until).
			// Preserve that stored source end here; later observer writes cannot
			// extend this operation's already admitted deadline. No SQL authority
			// is fabricated: this remains a native-work impossibility lower bound.
			if originalFleet.FreshUntil.Before(originalEnd) {
				originalEnd = originalFleet.FreshUntil
			}
		}
		call, end := context.WithDeadline(operationRoot, originalEnd)
		if deadline, ok := call.Deadline(); ok {
			originalEnd = deadline
		}
		started := time.Now()
		err := configurationProviderRuntimePair(call, f)
		end()
		if lease != nil {
			lease.Release()
		}
		t.Logf("purpose=%s original_available=%s elapsed=%s observer=%d probe=%d fleet=%d owner=%d fenced=%d error=%v", purpose, originalEnd.Sub(started), time.Since(started), f.observer.Load(), f.probe.Load(), sinks.fleet.Load(), sinks.owner.Load(), sinks.fenced.Load(), err)
		if err != nil {
			t.Fatalf("shared native lower bound cannot support %s within original interval: %v", purpose, err)
		}
	}
	if sinks.fleet.Load() == 0 || sinks.owner.Load() == 0 {
		t.Fatal("native refresh starved a required source observer")
	}
}
