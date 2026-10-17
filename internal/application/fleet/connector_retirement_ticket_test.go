package fleet

import (
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
)

func connectorTicketPlan(t *testing.T) ConnectorRetirementPlan {
	t.Helper()
	f, _ := connectorSourceConfiguration(t)
	c := f.cfg.Clone()
	a := c.Source.Observation.ObservedAt
	c.Backing.RetainedSeconds = 2100
	c.Backing.Policy.History.Layout = audit.ConnectorRetirementHistoryLayout
	backup, wal := c.Backing.Policy.History.SlotBacking(c.Backing.Policy.MaxPurgeLeases)
	c.Backing.Policy.BackupReservedBytes = backup * c.Backing.Policy.MetadataSlots
	c.Backing.Policy.WALReservedBytes = wal * c.Backing.Policy.MetadataSlots
	rows := 1 + c.Backing.ProfileLimit + c.Backing.ProfileLimit*(c.Backing.SourceTransitionLimit+1)
	c.Backing.SourceBackupReservedBytes = rows * backup
	c.Backing.SourceWALReservedBytes = (2*c.Backing.SourceTransitionLimit + ConnectorRetirementTicketTransitions*c.Backing.ProfileLimit*(c.Backing.SourceTransitionLimit+1)) * c.Backing.Policy.History.MaximumTransitionWALBytes * c.Backing.Policy.History.WALCopies
	c.Backing.Policy.ValidUntil = a.Add(30 * time.Minute)
	actor := audit.OperationConnectorProcessActor{Process: value.ConnectorProcessIdentity{Binding: c.Source.Observation.Profile.Binding, PodUID: "27000000-0000-4000-8000-000000000001", ProcessEpoch: "27000000-0000-4000-8000-000000000002"}, Deployment: c.Source.Observation.Profile.Deployment, ClientKeyDigest: artifact.Digest{51}, ServerKeyDigest: artifact.Digest{52}}
	return ConnectorRetirementPlan{TicketID: "27000000-0000-4000-8000-000000000003", AcceptanceID: "27000000-0000-4000-8000-000000000004", OriginalActor: actor, Cohort: ConnectorRetirementCohort{RootID: c.Source.Observation.Profile.RootID, Binding: c.Source.Observation.Profile.Binding, Behavior: c.Source.Observation.Profile.Revision, ServingSlots: c.Source.Observation.Profile.Deployment.ServingSlots, RetainedProcesses: c.Source.Observation.Profile.Deployment.RetainedProcesses, BackingRevision: c.Source.Observation.Backing.Revision, BackingDigest: c.Source.Observation.Backing.Digest}, Backing: c.Backing, BackingDigest: c.Source.Observation.Backing.Digest, AccountDigest: artifact.Digest{53}, PolicyDigest: artifact.Digest{54}, AcceptanceCreatedAt: a, AcceptanceRetainUntil: a.Add(2100 * time.Second), AcceptancePurgeAt: a.Add(1860 * time.Second)}
}

func TestConnectorRetirementTicketPreservesMinimumOriginalDates(t *testing.T) {
	p := connectorTicketPlan(t)
	old, _ := json.Marshal(p)
	ticket, e := p.Ticket()
	if e != nil || !ticket.Valid() {
		t.Fatal("original bounded ticket rejected", e)
	}
	if !ticket.OriginalPurgeAt().Equal(p.AcceptanceCreatedAt.Add(1860*time.Second)) || !ticket.ConsumeUntil.Equal(p.AcceptanceCreatedAt.Add(1830*time.Second)) || !ticket.AdmissionUntil.Equal(p.AcceptanceCreatedAt.Add(1800*time.Second)) || !ticket.RetainUntil.Equal(p.AcceptanceRetainUntil) {
		t.Fatal("ticket shifted original dates", ticket)
	}
	if ticket.CanStart(ticket.ConsumeUntil.Add(-time.Second), ticket.ConsumeUntil, ticket.ConsumeUntil) || ticket.CanStart(ticket.ConsumeUntil.Add(-time.Second), ticket.ConsumeUntil.Add(time.Microsecond), ticket.ConsumeUntil.Add(-time.Millisecond)) {
		t.Fatal("expired or extended retirement observation admitted")
	}
	if !ticket.CanStart(ticket.AdmissionUntil.Add(time.Second), ticket.AdmissionUntil.Add(6*time.Second), ticket.AdmissionUntil.Add(2*time.Second)) {
		t.Fatal("original reserved restrictive window disappeared at ordinary expiry")
	}
	ticket.Policy.History.Digest[0]++
	after, _ := json.Marshal(p)
	if string(old) != string(after) {
		t.Fatal("ticket creation/mutation changed the accepted original plan")
	}
}

func TestConnectorRetirementTicketRejectsImpossibleUpfrontPromises(t *testing.T) {
	for _, which := range []string{"admission ends too late", "earlier acceptance purge", "longer retention", "changed process", "wrong account", "identical operation", "short lifetime"} {
		t.Run(which, func(t *testing.T) {
			p := connectorTicketPlan(t)
			switch which {
			case "admission ends too late":
				p.Backing.Policy.ValidUntil = p.Backing.Policy.ValidUntil.Add(time.Microsecond)
			case "earlier acceptance purge":
				p.AcceptancePurgeAt = p.AcceptancePurgeAt.Add(-time.Microsecond)
			case "longer retention":
				p.AcceptanceRetainUntil = p.AcceptanceRetainUntil.Add(time.Second)
			case "changed process":
				p.OriginalActor.Process.Binding.InstallationID = p.TicketID
			case "wrong account":
				p.AccountDigest = artifact.Digest{}
			case "identical operation":
				p.TicketID = p.AcceptanceID
			case "short lifetime":
				p.Backing.RetainedSeconds = 2099
				p.AcceptanceRetainUntil = p.AcceptanceCreatedAt.Add(2099 * time.Second)
			}
			if _, e := p.Ticket(); e == nil {
				t.Fatal("impossible original retirement promise accepted")
			}
		})
	}
}

func TestConnectorRetirementTicketCannotMatchRenewedCohort(t *testing.T) {
	p := connectorTicketPlan(t)
	ticket, e := p.Ticket()
	if e != nil {
		t.Fatal(e)
	}
	b := value.ConnectorBackingObservation{Revision: p.Cohort.BackingRevision, Digest: p.Cohort.BackingDigest, SourceDigest: artifact.Digest{63}}
	if !ticket.MatchesCohort(p.Cohort.Binding, p.Cohort.Behavior, b) {
		t.Fatal("exact original cohort rejected")
	}
	for _, change := range []func(*value.ConnectorBackingObservation){
		func(b *value.ConnectorBackingObservation) { b.Revision++ },
		func(b *value.ConnectorBackingObservation) { b.Digest[0]++ },
	} {
		next := b
		change(&next)
		if ticket.MatchesCohort(p.Cohort.Binding, p.Cohort.Behavior, next) {
			t.Fatal("old ticket matched a changed backing with the same behavior")
		}
	}
	// A successor retains its own acceptance schedule; neither ticket acquires
	// the other's bounds or converts a historical actor into current proof.
	later := p
	later.TicketID = "27000000-0000-4000-8000-000000000005"
	later.AcceptanceID = "27000000-0000-4000-8000-000000000006"
	later.Backing = p.Backing.Clone()
	later.Backing.Policy.BackingRevision++
	later.BackingDigest[0]++
	later.AcceptanceCreatedAt = later.AcceptanceCreatedAt.Add(15 * time.Minute)
	later.AcceptancePurgeAt = later.AcceptancePurgeAt.Add(15 * time.Minute)
	later.AcceptanceRetainUntil = later.AcceptanceRetainUntil.Add(15 * time.Minute)
	later.Backing.Policy.ValidUntil = later.Backing.Policy.ValidUntil.Add(15 * time.Minute)
	next, e := later.Ticket()
	if e != nil || !next.Valid() || !ticket.RetainUntil.Equal(p.AcceptanceRetainUntil) || next.ID == ticket.ID || ticket.MatchesCohort(later.Cohort.Binding, later.Cohort.Behavior, value.ConnectorBackingObservation{Revision: later.Backing.Policy.BackingRevision, Digest: later.BackingDigest, SourceDigest: artifact.Digest{64}}) {
		t.Fatal("successor rewrote or impersonated the original", e)
	}
}

func TestConnectorRetirementTicketCapacityIsAdditional(t *testing.T) {
	p := connectorTicketPlan(t)
	b := p.Backing.Clone()
	d := p.OriginalActor.Deployment
	epochs := (b.RetainedSeconds+1799)/1800 + 1
	ordinary := 5*int64(d.RetainedProcesses) + 4*int64(d.ServingSlots)*epochs + b.SourceTransitionLimit
	b.RecordsPerAccount = ordinary
	if b.SupportsDeployment(d) || b.SupportsRetirementDeployment(d) {
		t.Fatal("ordinary funding silently covered restrictive reservations")
	}
	b.RecordsPerAccount += b.SourceTransitionLimit + 1
	if !b.SupportsRetirementDeployment(d) {
		t.Fatal("separate finite ticket slots not recognized")
	}
	ceiling, ok := b.RetirementTicketCeiling()
	if !ok || ceiling != b.ProfileLimit*(b.SourceTransitionLimit+1) {
		t.Fatal("ticket generations unbounded or omitted", ceiling, ok)
	}
	b.RecordsPerAccount--
	if b.SupportsRetirementDeployment(d) {
		t.Fatal("last reserved ticket spent by ordinary funding")
	}
}

func TestConnectorRetirementTicketRowsKeepSeparateOriginalBacking(t *testing.T) {
	p := connectorTicketPlan(t)
	b := p.Backing.Clone()
	q := b.Policy.History
	perRow := 2 * q.MaximumRowFootprintBytes * q.BackupCopies
	rows := 1 + b.ProfileLimit + b.ProfileLimit*(b.SourceTransitionLimit+1)
	b.SourceBackupReservedBytes = rows*perRow - 1
	if b.Valid() {
		t.Fatal("retained ticket tombstone borrowed a released audit-pair slot")
	}
	b.SourceBackupReservedBytes++
	if !b.Valid() {
		t.Fatal("complete independent ticket-row backing rejected")
	}
	legacy := b.Clone()
	legacy.Policy.History.Layout = audit.ConnectorOperationHistoryLayout
	legacy.SourceBackupReservedBytes = (legacy.ProfileLimit + 1) * perRow
	if !legacy.Valid() {
		t.Fatal("v1 historical source backing changed")
	}
	legacy.Policy.History.Layout = audit.ConnectorRetirementHistoryLayout
	if legacy.Valid() {
		t.Fatal("v1 source backing silently qualified retained ticket generations")
	}
}

func TestConnectorRetirementSuccessorPreservesLatePeersHistoricalCohort(t *testing.T) {
	p := connectorTicketPlan(t)
	// Peer A acknowledges the global transition while B still has its original
	// complete source observation. The reservation producer receives B's exact
	// historical SQL cohort, not a manufactured complete ConfigMap observation.
	p.Cohort.Binding.PeerID = "27000000-0000-4000-8000-000000000012"
	p.Cohort.Binding.ClusterID = "27000000-0000-4000-8000-000000000013"
	p.Cohort.Behavior.UID = "27000000-0000-4000-8000-000000000014"
	old, e := p.Ticket()
	if e != nil {
		t.Fatal(e)
	}
	historical := p.Cohort
	p.TicketID = "27000000-0000-4000-8000-000000000015"
	p.AcceptanceID = "27000000-0000-4000-8000-000000000016"
	p.Backing = p.Backing.Clone()
	p.Backing.Policy.BackingRevision++
	p.BackingDigest[0]++
	p.AcceptanceCreatedAt = p.AcceptanceCreatedAt.Add(15 * time.Minute)
	p.AcceptancePurgeAt = p.AcceptancePurgeAt.Add(15 * time.Minute)
	p.AcceptanceRetainUntil = p.AcceptanceRetainUntil.Add(15 * time.Minute)
	p.Backing.Policy.ValidUntil = p.Backing.Policy.ValidUntil.Add(15 * time.Minute)
	next, e := p.Ticket()
	if e != nil || p.Cohort != historical || next.Behavior != old.Behavior || next.Binding != old.Binding || next.OriginalActor.Process.Binding.PeerID == next.Binding.PeerID || next.BackingRevision != old.BackingRevision+1 || next.BackingDigest != p.BackingDigest {
		t.Fatal("successor rewrote B's observed behavior or invented its accepting actor", e)
	}
	// When B later actually observes the accepted backing, the original ticket
	// no longer matches. This pure comparison is not current-source authority.
	observed := value.ConnectorBackingObservation{Revision: next.BackingRevision, Digest: next.BackingDigest, SourceDigest: artifact.Digest{65}}
	if old.MatchesCohort(historical.Binding, historical.Behavior, observed) || !next.MatchesCohort(historical.Binding, historical.Behavior, observed) {
		t.Fatal("old ticket could retire the renewed peer")
	}
	for _, change := range []func(*ConnectorRetirementPlan){
		func(p *ConnectorRetirementPlan) { p.Backing.Policy.BackingRevision++ },
		func(p *ConnectorRetirementPlan) { p.Backing.Policy.BackingRevision = historical.BackingRevision - 1 },
		func(p *ConnectorRetirementPlan) { p.BackingDigest = historical.BackingDigest },
		func(p *ConnectorRetirementPlan) { p.Cohort.RootID = p.TicketID },
	} {
		changed := p
		changed.Backing = p.Backing.Clone()
		change(&changed)
		if _, e := changed.Ticket(); e == nil {
			t.Fatal("unrelated root, skipped revision or reused digest accepted")
		}
	}
}

func TestConnectorRetirementUnusedTicketCleanupHasIndependentWALBacking(t *testing.T) {
	b := connectorTicketPlan(t).Backing
	q := b.Policy.History
	floor := (2*b.SourceTransitionLimit + ConnectorRetirementTicketTransitions*b.ProfileLimit*(b.SourceTransitionLimit+1)) * q.MaximumTransitionWALBytes * q.WALCopies
	b.SourceWALReservedBytes = floor
	if !b.Valid() {
		t.Fatal("exact complete original ticket transition backing rejected")
	}
	b.SourceWALReservedBytes--
	if b.Valid() {
		t.Fatal("ticket tombstone cleanup accepted without complete independent WAL backing")
	}
	b.SourceWALReservedBytes = 2 * b.SourceTransitionLimit * q.MaximumTransitionWALBytes * q.WALCopies
	if b.Valid() {
		t.Fatal("legacy source transition backing covered independently retained ticket cleanup")
	}
}
