package fleet

import (
	"context"
	"errors"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

type localSettings struct{ a value.Administration }

func (s localSettings) FleetAdministration(context.Context) (value.Administration, error) {
	return s.a, nil
}

// The installation actor is bound to the protected fleet administration:
// suspension and delivery profiles deny as for an operator, and its limits
// and revision are those of the administration.
func TestInstallationEnrollmentAuthority(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	a := value.Administration{InstallationID: "00000000-0000-4000-8000-000000000001", IssuerEpoch: "00000000-0000-4000-8000-000000000002", Issuer: "https://identity.example.test", Revision: identity.Revision{UID: "fleet", Generation: 3, Digest: [32]byte{2}},
		ObservedAt: now, FreshUntil: now.Add(5 * time.Second), Clients: []string{"console"}, DeliveryProfiles: []string{"local"}, MaxActiveBootstraps: 1, MaxBootstrapHistory: 16, MaxClusters: 2}
	authorizer := InstallationEnrollmentAuthorizer{Settings: localSettings{a}, Now: func() time.Time { return now }}
	got, err := authorizer.AuthorizeEnrollment(context.Background(), "", "local")
	if err != nil || !got.Valid(now) || got.Actor != value.InstallationEnrollmentActor(a.InstallationID) || got.Actor.Kind != identity.Workload || got.AdministrationRevision != a.Revision || got.MaxClusters != 2 || !got.ValidUntil.Equal(a.FreshUntil) {
		t.Fatal("installation authority", got, err)
	}
	if _, err = authorizer.AuthorizeEnrollment(context.Background(), "", "other"); !errors.Is(err, value.ErrDenied) {
		t.Fatal("unconfigured delivery profile", err)
	}
	a.Suspended = true
	if _, err = (InstallationEnrollmentAuthorizer{Settings: localSettings{a}, Now: authorizer.Now}).AuthorizeEnrollment(context.Background(), "", "local"); !errors.Is(err, value.ErrDenied) {
		t.Fatal("suspended administration", err)
	}
	a.Suspended = false
	if _, err = (InstallationEnrollmentAuthorizer{Settings: localSettings{a}, Now: func() time.Time { return now.Add(6 * time.Second) }}).AuthorizeEnrollment(context.Background(), "", "local"); !errors.Is(err, value.ErrUnavailable) {
		t.Fatal("stale administration", err)
	}
}

type localRecords struct {
	written []value.BootstrapEnvelope
	fail    error
}

func (r *localRecords) CheckBootstrapRecord(context.Context) error { return r.fail }

func (r *localRecords) WriteBootstrapRecord(_ context.Context, e value.BootstrapEnvelope) error {
	if r.fail != nil {
		return r.fail
	}
	r.written = append(r.written, e)
	return nil
}

type localEnvelopes struct{ envelope value.BootstrapEnvelope }

func (e localEnvelopes) ReadBootstrapEnvelope(_ context.Context, id string) (value.BootstrapEnvelope, error) {
	if id != e.envelope.BootstrapID {
		return value.BootstrapEnvelope{}, value.ErrDenied
	}
	return e.envelope, nil
}

func newLocalFixture() (*bootstrapFixture, LocalClusterBootstrap, *localRecords) {
	f, issuer, _ := newBootstrapFixture()
	f.intent.DisplayName, f.intent.Region = localDisplayName, localRegion
	s := f.intent.Slot
	records := &localRecords{}
	envelope := value.BootstrapEnvelope{BootstrapID: s.ID, Binding: s.Binding, DeliveryProfile: s.DeliveryProfile, RequestDigest: s.RequestDigest, NotBefore: s.NotBefore, NotAfter: s.NotAfter, Secret: "synthetic"}
	return f, LocalClusterBootstrap{Issuer: issuer, Envelopes: localEnvelopes{envelope}, Records: records, Binding: s.Binding, DeliveryProfile: s.DeliveryProfile}, records
}

// The issued slot's record is written for the connector; a slot for another
// binding or an envelope of another slot is never written.
func TestLocalClusterBootstrapWritesTheIssuedRecord(t *testing.T) {
	f, l, records := newLocalFixture()
	notAfter, err := l.issue(context.Background(), f.intent.Slot.RequestDigest)
	if err != nil || len(records.written) != 1 || records.written[0].BootstrapID != f.intent.Slot.ID || !notAfter.Equal(f.intent.Slot.NotAfter) || f.activations != 1 {
		t.Fatal("record not written", err)
	}
	f, l, records = newLocalFixture()
	l.Binding.PeerID = "00000000-0000-4000-8000-0000000000ee"
	if _, err = l.issue(context.Background(), f.intent.Slot.RequestDigest); !errors.Is(err, value.ErrDenied) || len(records.written) != 0 {
		t.Fatal("slot of another binding written", err)
	}
	f, l, records = newLocalFixture()
	l.Envelopes = localEnvelopes{value.BootstrapEnvelope{BootstrapID: f.intent.Slot.ID, Binding: f.intent.Slot.Binding, NotAfter: f.intent.Slot.NotAfter.Add(time.Minute)}}
	if _, err = l.issue(context.Background(), f.intent.Slot.RequestDigest); !errors.Is(err, value.ErrDenied) || len(records.written) != 0 {
		t.Fatal("envelope of another slot lifetime written", err)
	}
}

// One request key is reused for retries within a slot lifetime and replaced
// afterwards, so a replacement slot never reuses an expired slot's key.
func TestLocalClusterBootstrapKeyLifetime(t *testing.T) {
	var l LocalClusterBootstrap
	var k localKey
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	first, _ := l.key(&k, now)
	retry, _ := l.key(&k, now.Add(4*time.Minute))
	next, _ := l.key(&k, now.Add(5*time.Minute))
	if first != retry || next == first {
		t.Fatal("request key lifetime")
	}
}

type consumedReservations struct{ *bootstrapFixture }

func (consumedReservations) ReserveBootstrap(context.Context, value.BootstrapRequest) (value.BootstrapIntent, error) {
	return value.BootstrapIntent{}, value.ErrLocalBootstrapConsumed
}

// A claimed slot ends the loop; no record is written.
func TestLocalClusterBootstrapStopsWhenClaimed(t *testing.T) {
	f, l, records := newLocalFixture()
	l.Issuer.Reservations = consumedReservations{f}
	var events []string
	if err := l.Run(context.Background(), func(e string) { events = append(events, e) }); err != nil || len(events) != 1 || events[0] != "claimed" || len(records.written) != 0 {
		t.Fatal("claimed local slot", events, err)
	}
}

// Without the record Secret (no local connector rendered) no slot is
// reserved, so the administration's bootstrap history is not spent.
func TestLocalClusterBootstrapWaitsForTheRecordSecret(t *testing.T) {
	f, l, records := newLocalFixture()
	records.fail = errors.New("not found")
	ctx, cancel := context.WithCancel(context.Background())
	var events []string
	err := l.Run(ctx, func(e string) { events = append(events, e); cancel() })
	if !errors.Is(err, context.Canceled) || len(events) != 1 || events[0] != "no-record-secret" || f.authorizations != 0 || f.activations != 0 {
		t.Fatal("slot reserved without the record Secret", events, err)
	}
}

// A refused issuance names its stage and a closed cause class.
func TestLocalClusterBootstrapNamesTheFailingStage(t *testing.T) {
	f, l, records := newLocalFixture()
	f.failObject = true
	if _, err := l.issue(context.Background(), f.intent.Slot.RequestDigest); localIssueCause(err) != "audit-write/unavailable" || len(records.written) != 0 {
		t.Fatal("stage", localIssueCause(err))
	}
	f, l, _ = newLocalFixture()
	records.fail = errors.New("forbidden")
	l.Records = records
	if _, err := l.issue(context.Background(), f.intent.Slot.RequestDigest); localIssueCause(err) != "record-secret/other" {
		t.Fatal("stage", localIssueCause(err))
	}
}
