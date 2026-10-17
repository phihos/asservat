package fleet

import (
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
	"context"
	"testing"
	"time"
)

type connectorSourceFixture struct {
	cfg            ConnectorIdentityConfiguration
	clock          *time.Time
	stages, fences int
	read           func()
	stored         ConnectorIdentityConfiguration
}

func (f *connectorSourceFixture) ReadConnectorIdentityConfiguration(context.Context) (ConnectorIdentityConfiguration, error) {
	if f.read != nil {
		f.read()
	}
	return f.cfg, nil
}
func (f *connectorSourceFixture) StageConnectorIdentity(_ context.Context, c ConnectorIdentityConfiguration) error {
	f.stages++
	f.stored = c
	return nil
}
func (f *connectorSourceFixture) FenceConnectorIdentity(context.Context, value.PeerBinding, time.Time) error {
	f.fences++
	return nil
}
func connectorSourceConfiguration(t *testing.T) (*connectorSourceFixture, ConnectorIdentityObserver) {
	t.Helper()
	f, s := newConnectorRenewalFixture(t)
	current, e := s.current(context.Background(), f.cert, f.now, f.now.Add(5*time.Second), nil)
	if e != nil {
		t.Fatal(e)
	}
	a, e := f.PrepareConnectorCredential(context.Background(), ConnectorCredentialCandidate{ID: f.request.ID, BootstrapID: f.request.BootstrapID, Usage: "server", PublicKeyDigest: f.process.ServerKeyDigest, Current: current})
	if e != nil {
		t.Fatal(e)
	}
	p := a.Intent.Lifecycle.Policy
	p.OverdueTerminal = audit.OperationOverdueTerminal
	p.MetadataSlots = 256
	b, w := p.History.SlotBacking(p.MaxPurgeLeases)
	p.BackupReservedBytes = b * 256
	p.WALReservedBytes = w * 256
	c := ConnectorIdentityConfiguration{Source: current.Source, Backing: ConnectorIdentityBacking{AccountVersion: "account-v1", AccountLimit: 2, RecordsPerAccount: 128, RetainedSeconds: 10800, ProfileLimit: 2, SourceTransitionLimit: 10, SourceBackupReservedBytes: 6 << 20, SourceWALReservedBytes: 20 << 20, Policy: p}}
	fixture := &connectorSourceFixture{cfg: c, clock: &f.now}
	observer := ConnectorIdentityObserver{Reader: fixture, Journal: fixture, Binding: f.binding, Qualification: ConnectorQualificationPin{InstallationID: p.InstallationID, StoreID: p.StoreID, BackupProfileID: p.BackupProfileID, Qualification: *p.History}, Now: func() time.Time { return f.now }}
	return fixture, observer
}
func TestConnectorIdentitySourceRequiresIndependentQualificationAndBacking(t *testing.T) {
	for _, which := range []string{"different measured result", "unqualified public layout", "short source backing", "short aggregate pool", "late protected source", "wrong binding"} {
		t.Run(which, func(t *testing.T) {
			f, s := connectorSourceConfiguration(t)
			switch which {
			case "different measured result":
				s.Qualification.Qualification.Digest[0]++
			case "unqualified public layout":
				f.cfg.Backing.Policy.History.Layout = audit.OperationVerificationHistoryLayout
			case "short source backing":
				f.cfg.Backing.SourceWALReservedBytes--
			case "short aggregate pool":
				f.cfg.Backing.Policy.MetadataSlots--
			case "late protected source":
				f.read = func() { *f.clock = f.clock.Add(6 * time.Second) }
			case "wrong binding":
				s.Binding.ClusterID = "20000000-0000-4000-8000-000000000001"
			}
			if e := s.Observe(context.Background()); e == nil || f.stages != 0 || f.fences != 1 {
				t.Fatal("unaccepted source staged", e, f.stages, f.fences)
			}
		})
	}
}
func TestConnectorIdentitySourceStagesSuspensionAndCopiesPublicPins(t *testing.T) {
	f, s := connectorSourceConfiguration(t)
	f.cfg.Source.Observation.Profile.Suspended = true
	if e := s.Observe(context.Background()); e != nil || f.stages != 1 || !f.stored.Source.Observation.Profile.Suspended {
		t.Fatal("negative source lost", e)
	}
	f.cfg.Source.Observation.Profile.ClientIssuerRoots[0][0]++
	f.cfg.Backing.Policy.History.Digest[0]++
	if f.stored.Source.Observation.Profile.ClientIssuerRoots[0][0] == f.cfg.Source.Observation.Profile.ClientIssuerRoots[0][0] || f.stored.Backing.Policy.History.Digest == f.cfg.Backing.Policy.History.Digest {
		t.Fatal("caller mutated staged source pins")
	}
}
