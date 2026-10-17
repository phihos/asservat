package fleet

import (
	"bytes"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/identity"
)

func retirementMAC(t *testing.T, account string) *auditapp.OperationMAC {
	t.Helper()
	m, e := auditapp.NewOperationMAC("retirement-input/v1", bytes.Repeat([]byte{71}, 32), account, bytes.Repeat([]byte{72}, 32))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(m.Close)
	return m
}

func TestConnectorRetirementIntentUsesHistoricalOriginAndOriginalDates(t *testing.T) {
	p := connectorTicketPlan(t)
	ticket, e := p.Ticket()
	if e != nil {
		t.Fatal(e)
	}
	m := retirementMAC(t, ticket.AccountVersion)
	start := ticket.AdmissionUntil.Add(time.Second)
	in, e := ConnectorRetirementIntent(ticket, audit.ConnectorRetirementExpiry, nil, p.AcceptanceID, start, start.Add(5*time.Second), m)
	if e != nil || !in.Valid() || in.RetirementOrigin == nil || in.Process != nil || in.Peer != nil || in.Actor != (identity.Principal{}) || in.ID != ticket.ID || !in.RetainUntil.Equal(ticket.RetainUntil) || !in.Lifecycle.OriginalPurgeAt.Equal(ticket.OriginalPurgeAt()) || !in.CreatedAt.Equal(start) {
		t.Fatal("historical restrictive intent changed original authority or dates", e)
	}
	if !start.After(p.Backing.Policy.ValidUntil) {
		t.Fatal("fixture did not cross ordinary admission expiry")
	}
	for _, edit := range []func(*audit.OperationIntent){
		func(in *audit.OperationIntent) { in.Process = &p.OriginalActor },
		func(in *audit.OperationIntent) {
			in.Name = "connector_client_certificate"
			in.InputFormat = "connector-credential/v1"
		},
		func(in *audit.OperationIntent) { in.RetainUntil = in.RetainUntil.Add(time.Second) },
		func(in *audit.OperationIntent) { in.WriteUntil = ticket.ConsumeUntil.Add(time.Microsecond) },
		func(in *audit.OperationIntent) { in.AccountVersion += "-other" },
		func(in *audit.OperationIntent) { in.ID = p.AcceptanceID },
	} {
		other := in
		edit(&other)
		if other.Valid() {
			t.Fatal("retirement branch granted another actor, operation or interval")
		}
	}
	if _, e = ConnectorRetirementIntent(ticket, audit.ConnectorRetirementExpiry, nil, p.AcceptanceID, ticket.AdmissionUntil.Add(-time.Second), ticket.AdmissionUntil, m); e == nil {
		t.Fatal("historical expiry retired a still-live cohort early")
	}
	if _, e = ConnectorRetirementIntent(ticket, audit.ConnectorRetirementExpiry, nil, p.AcceptanceID, ticket.ConsumeUntil, ticket.ConsumeUntil.Add(time.Second), m); e == nil {
		t.Fatal("expired ticket renewed")
	}
}

func TestConnectorRetirementExplicitSourceCannotReplaceOriginalCohort(t *testing.T) {
	p := connectorTicketPlan(t)
	ticket, e := p.Ticket()
	if e != nil {
		t.Fatal(e)
	}
	m := retirementMAC(t, ticket.AccountVersion)
	source := &audit.ConnectorRetiringSource{Revision: ticket.Behavior, CompleteDigest: artifact.Digest{73}}
	source.Revision.Generation++
	source.Revision.Digest[0]++
	start := ticket.ReservedAt.Add(time.Second)
	in, e := ConnectorRetirementIntent(ticket, audit.ConnectorRetirementExplicit, source, p.AcceptanceID, start, start.Add(5*time.Second), m)
	if e != nil || !in.Valid() || in.RetirementOrigin.Ticket.Behavior != ticket.Behavior {
		t.Fatal("exact higher retiring source did not retain accepted cohort", e)
	}
	source.Revision.Generation++
	if in.RetirementOrigin.RetiringSource.Revision.Generation == source.Revision.Generation {
		t.Fatal("caller mutation rewrote immutable intent")
	}
	for _, which := range []string{"missing", "same generation", "other UID", "empty digest"} {
		t.Run(which, func(t *testing.T) {
			bad := *in.RetirementOrigin.RetiringSource
			ptr := &bad
			switch which {
			case "missing":
				ptr = nil
			case "same generation":
				bad.Revision = ticket.Behavior
			case "other UID":
				bad.Revision.UID = ticket.ID
			case "empty digest":
				bad.CompleteDigest = artifact.Digest{}
			}
			if _, e := ConnectorRetirementIntent(ticket, audit.ConnectorRetirementExplicit, ptr, p.AcceptanceID, start, start.Add(time.Second), m); e == nil {
				t.Fatal("unrelated or absent current retiring revision accepted")
			}
		})
	}
}

func TestConnectorAcceptanceRequiresExactReservationBeforeV2Binding(t *testing.T) {
	p := connectorTicketPlan(t)
	ticket, e := p.Ticket()
	if e != nil {
		t.Fatal(e)
	}
	in := audit.OperationIntent{ID: p.AcceptanceID, RootID: ticket.RootID, TraceID: ticket.ID, Name: "connector_process_enrollment", InputFormat: "connector-process/v1", MACVersion: "m1", AccountVersion: ticket.AccountVersion, Process: &p.OriginalActor, PrincipalDigest: ticket.PrincipalDigest, InputDigest: artifact.Digest{74}, CreatedAt: ticket.ReservedAt, RequestUntil: ticket.ReservedAt.Add(5 * time.Second), WriteUntil: ticket.ReservedAt.Add(30 * time.Second), RetainUntil: ticket.RetainUntil}
	missing := in
	missing.Name, missing.InputFormat = "connector_backing_acceptance", "connector-backing/v1"
	if _, e = auditapp.BindOperationLifecycle(missing, p.Backing.Policy); e == nil {
		t.Fatal("new v2 acceptance bound without restrictive reservation")
	}
	bound, e := BindConnectorRetirementAcceptance(in, p.Backing.Policy, []audit.ConnectorRetirementTicket{ticket})
	if e != nil || !bound.Valid() || bound.ConnectorReservations == nil {
		t.Fatal("exact reserved acceptance rejected", e)
	}
	before, _ := json.Marshal(bound)
	if _, e = BindConnectorRetirementAcceptance(bound, p.Backing.Policy, []audit.ConnectorRetirementTicket{ticket}); e != nil {
		t.Fatal("same-set construction was not stable", e)
	}
	changed := ticket.Clone()
	changed.Policy.PolicyDigest[0]++
	if _, e = BindConnectorRetirementAcceptance(bound, p.Backing.Policy, []audit.ConnectorRetirementTicket{changed}); e == nil {
		t.Fatal("accepted set digest silently changed")
	}
	after, _ := json.Marshal(bound)
	if !bytes.Equal(before, after) {
		t.Fatal("comparison mutated original intent")
	}
	legacy := in
	policy := p.Backing.Clone().Policy
	policy.History.Layout = audit.ConnectorOperationHistoryLayout
	legacy, e = auditapp.BindOperationLifecycle(legacy, policy)
	if e != nil || !legacy.Valid() {
		t.Fatal("historical v1 shape no longer readable", e)
	}
	b, _ := json.Marshal(legacy)
	if bytes.Contains(b, []byte("ConnectorReservations")) || bytes.Contains(b, []byte("RetirementOrigin")) {
		t.Fatal("historical absent fields acquired bytes")
	}
}

// Source-only until the focused gate runs. This specifically measures the new
// accepted private image; the native SQL fixture must additionally test the
// actual PostgreSQL jsonb::text constraint rather than infer it from Go JSON.
func TestConnectorRetirementIntentMaximumAcceptedTextFitsExistingAuditEnvelope(t *testing.T) {
	p := connectorTicketPlan(t)
	ticket, e := p.Ticket()
	if e != nil {
		t.Fatal(e)
	}
	ticket.AccountVersion = strings.Repeat("<", 64)
	ticket.OriginalActor.Deployment.Namespace = strings.Repeat("n", 63)
	name := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	ticket.OriginalActor.Deployment.ServiceAccount = name
	ticket.OriginalActor.Deployment.Deployment = name
	for i := range ticket.Behavior.Digest {
		ticket.Behavior.Digest[i] = 255
	}
	for _, d := range []*artifact.Digest{&ticket.BackingDigest, &ticket.PrincipalDigest, &ticket.OriginalActor.ClientKeyDigest, &ticket.OriginalActor.ServerKeyDigest, &ticket.Policy.PolicyDigest, &ticket.Policy.BackupProfileDigest, &ticket.Policy.History.Digest} {
		for i := range d {
			d[i] = 255
		}
	}
	ticket.OriginalActor.ServerKeyDigest[31] = 254
	ticket.OriginalActor.Deployment.ServingSlots = 16
	ticket.OriginalActor.Deployment.RetainedProcesses = 256
	ticket.ServingSlots = 16
	ticket.RetainedProcesses = 256
	ticket.Behavior.Generation = 2147483646 // The explicit retiring source advances once.
	ticket.BackingRevision = 1 << 60
	ticket.Policy.BackingRevision = ticket.BackingRevision
	ticket.Policy.MetadataSlots = 7000000
	ticket.Policy.BackupReservedBytes = math.MaxInt64
	ticket.Policy.WALReservedBytes = math.MaxInt64
	ticket.Policy.MaxPurgeLeases = 32
	ticket.Policy.History.MaximumRowFootprintBytes = 16 << 20
	ticket.Policy.History.MaximumTransitionWALBytes = 64 << 20
	ticket.Policy.History.BackupCopies = 64
	ticket.Policy.History.WALCopies = 64
	ticket.Policy.BackupHorizonSeconds = 100000000
	ticket.Policy.CleanupBudgetSeconds = 86400
	ticket.Policy.ProofWindowSeconds = 100000000
	ticket.ReservedAt = time.Date(2026, 10, 12, 0, 0, 0, 999999000, time.UTC)
	ticket.RetainUntil = ticket.ReservedAt.Add(316224000 * time.Second)
	ticket.OriginalAcceptancePurgeAt = ticket.OriginalPurgeAt()
	ticket.AdmissionUntil = ticket.OriginalPurgeAt().Add(-time.Minute)
	ticket.ConsumeUntil = ticket.OriginalPurgeAt().Add(-30 * time.Second)
	ticket.Policy.ValidUntil = ticket.ConsumeUntil
	if !ticket.Valid() {
		t.Fatal("extremal accepted ticket fixture invalid")
	}
	m, e := auditapp.NewOperationMAC(strings.Repeat("<", 64), bytes.Repeat([]byte{71}, 32), ticket.AccountVersion, bytes.Repeat([]byte{72}, 32))
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	source := &audit.ConnectorRetiringSource{Revision: ticket.Behavior, CompleteDigest: ticket.BackingDigest}
	source.Revision.Generation++
	start := ticket.ReservedAt.Add(time.Second)
	in, e := ConnectorRetirementIntent(ticket, audit.ConnectorRetirementExplicit, source, p.AcceptanceID, start, start.Add(5*time.Second), m)
	if e != nil {
		t.Fatal(e)
	}
	b, e := json.Marshal(in)
	if e != nil || len(b) > 8192 {
		t.Fatalf("retirement intent exceeds existing private/public SQL envelope: %d bytes, %v", len(b), e)
	}
	_, _, e = CanonicalConnectorRetirementTicket(ticket)
	if e != nil {
		t.Fatal("maximum accepted ticket exceeds canonical ceiling", e)
	}
	t.Logf("extremal Go JSON retirement intent: %d bytes; actual SQL rendering remains a native fixture check", len(b))
}
