package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/jose"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SQL roles, reservation/CAS, encrypted pairs and physical S3 cleanup are real.
// Protected configuration/backup qualification, Pod facts, recovery observation
// and issuer/signing keys are explicitly synthetic. No production period or
// persisted date is shortened/backdated for these cases.
func qualifyConnectorRetirement(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, create func(*testing.T, int64) captureAdmissionScenario) {
	t.Run("connector-retirement-prepaid-fast", func(t *testing.T) {
		t.Run("successor-keeps-original-cohort-and-closes-unused", func(t *testing.T) {
			f := newConnectorSQLFixtureWithOptions(t, ctx, admin, poolFor, store, keys, create(t, 1), 2100, connectorRetirementFixtureOptions{Enabled: true, Admission: 15 * time.Second})
			old := connectorOriginalTicket(t, f)
			originalProcess, _ := json.Marshal(f.process)
			f.renewBacking(t)
			next := connectorOriginalTicket(t, f)
			if next.ID == old.ID || next.BackingRevision != old.BackingRevision+1 || !bytes.Equal(originalProcess, mustConnectorJSON(t, f.process)) {
				t.Fatal("backing promotion replaced original process or failed successor reservation")
			}
			journal, service, cleanup := connectorRetirementPorts(t, f)
			connectorWaitUntil(t, ctx, old.AdmissionUntil.Add(time.Millisecond))
			f.refresh(t)
			if result, err := service.Expire(ctx, old.ID); err == nil || result.Restricted {
				t.Fatal("old ticket restricted a renewed cohort", err)
			}
			if _, err := cleanup.CloseAdmission(ctx, old.ID, connectorRetirementCurrent(t, f)); err != nil {
				t.Fatal("superseded unused allowance did not close", err)
			}
			if _, err := cleanup.CloseAdmission(ctx, old.ID, connectorRetirementCurrent(t, f)); err != nil {
				t.Fatal("exact unused closure replay failed", err)
			}
			r, err := journal.ReadConnectorRetirement(ctx, old.ID, connectorRetirementCurrent(t, f))
			if err != nil || r.AdmissionOpen || r.Snapshot != nil {
				t.Fatal("closed unused ticket was revived or fabricated audit", err)
			}
			if _, err := cleanup.DeleteTicket(ctx, old.ID, connectorRetirementCurrent(t, f)); err == nil {
				t.Fatal("unused ticket tombstone deleted before its original retained end")
			}
			var originalRows, activeRows int
			if err = admin.QueryRow(ctx, "SELECT count(*) FILTER(WHERE id=$2),count(*) FILTER(WHERE activated_at IS NOT NULL AND superseded_at IS NULL) FROM connector_retirement_ticket WHERE root_id=$1", f.scenario.a.RootID, old.ID).Scan(&originalRows, &activeRows); err != nil || originalRows != 1 || activeRows != 1 {
				t.Fatal("successor lost bounded original identity", err)
			}
		})
		t.Run("explicit-retiring-source-keeps-last-accepted-cohort", func(t *testing.T) {
			f := newConnectorSQLFixtureWithOptions(t, ctx, admin, poolFor, store, keys, create(t, 1), 2100, connectorRetirementFixtureOptions{Enabled: true, Admission: 30 * time.Second})
			ticket := connectorOriginalTicket(t, f)
			f.configuration.Source.Observation.Profile.Revision.Generation++
			f.configuration.Source.Observation.Profile.Revision.Digest[0]++
			f.configuration.Source.Observation.Profile.Suspended = true
			f.configuration.Source.Observation.Profile.Retiring = true
			f.configuration.Source.Observation.Backing.SourceDigest[0]++
			f.refresh(t)
			source, _ := f.ReadConnectorIdentityConfiguration(ctx)
			if err := f.source.StageConnectorIdentity(ctx, source); err != nil {
				t.Fatal("protected retiring source", err)
			}
			_, service, _ := connectorRetirementPorts(t, f)
			service.Proof = connectorRetirementProofFixture{f}
			result, err := service.Retire(ctx, ticket.ID, f.request)
			if err != nil || !result.Restricted || !result.AuditAcknowledged {
				t.Fatal("actual higher retiring source could not restrict its original cohort", result, err)
			}
			if _, err = f.enrollment.Enroll(ctx, custodyID(), f.request); err == nil {
				t.Fatal("retirement-only source admitted ordinary serving work")
			}
			var raw []byte
			if err = admin.QueryRow(ctx, "SELECT intent FROM operation_audit WHERE id=$1", ticket.ID).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			var in audit.OperationIntent
			if json.Unmarshal(raw, &in) != nil || in.RetirementOrigin == nil || in.RetirementOrigin.RetiringSource == nil || in.RetirementOrigin.Ticket.Behavior != ticket.Behavior || in.RetirementOrigin.RetiringSource.Revision.Generation != ticket.Behavior.Generation+1 {
				t.Fatal("retirement rewrote cohort or omitted higher retiring observation")
			}
		})
		t.Run("dead-actor-original-expiry-and-role-isolation", func(t *testing.T) {
			f := newConnectorSQLFixtureWithOptions(t, ctx, admin, poolFor, store, keys, create(t, 1), 2100, connectorRetirementFixtureOptions{Enabled: true, Admission: 15 * time.Second})
			ticket := connectorOriginalTicket(t, f)
			leaf := f.issue(t, "client")
			f.issue(t, "server")
			journal, service, cleanup := connectorRetirementPorts(t, f)
			if _, err := cleanup.CloseAdmission(ctx, ticket.ID, connectorRetirementCurrent(t, f)); err == nil {
				t.Fatal("original live allowance closed before its admission interval")
			}
			// Calling with no live proof is intentional: the original process may have
			// died. This branch uses only its immutable prepaid historical authorization.
			connectorWaitUntil(t, ctx, ticket.AdmissionUntil.Add(time.Millisecond))
			f.refresh(t)
			qualifyConnectorRetirementBlockedOutcome(t, f, journal, ticket)
			result, err := service.Expire(ctx, ticket.ID)
			if err != nil || !result.Restricted || !result.AuditAcknowledged {
				t.Fatal("paid historical retirement unavailable after ordinary root expiry", result, err)
			}
			if _, err = f.registry.ConnectorLeafRegistration(ctx, leaf.Certificate); err == nil {
				t.Fatal("restricted original leaf remains current")
			}
			old := connectorOriginalTicketByID(t, f, ticket.ID)
			if !bytes.Equal(mustConnectorJSON(t, ticket), mustConnectorJSON(t, old)) {
				t.Fatal("consumption rewrote original ticket promises")
			}
			f.refresh(t)
			if _, err = service.Expire(ctx, ticket.ID); err != nil {
				t.Fatal("same retirement ID replay failed", err)
			}
			for _, role := range []string{"source", "acknowledgement", "read", "verifier", "finalizer"} {
				if _, err = f.pools[role].Exec(ctx, "SELECT restrict_connector_retirement($1,$2,'originalAdmissionEnd','{}'::jsonb)", f.scenario.a.RootID, ticket.ID); err == nil {
					t.Fatal("wrong role restricted ticket", role)
				}
				if _, err = f.pools[role].Exec(ctx, "DELETE FROM connector_retirement_ticket WHERE id=$1", ticket.ID); err == nil {
					t.Fatal("wrong role deleted ticket", role)
				}
			}
			if _, err = cleanup.DeleteTicket(ctx, ticket.ID, connectorRetirementCurrent(t, f)); err == nil {
				t.Fatal("retirement acknowledgement was mistaken for physical cleanup")
			}
			// Concurrent cleanup callers cannot convert acknowledgement into
			// physical/history absence or release the original reservation early.
			current := connectorRetirementCurrent(t, f)
			results := make(chan error, 4)
			for range 4 {
				go func() {
					_, e := cleanup.DeleteTicket(ctx, ticket.ID, current)
					results <- e
				}()
			}
			for range 4 {
				if e := <-results; e == nil {
					t.Error("concurrent cleanup released an unretired original ticket")
				}
			}
			if !bytes.Equal(mustConnectorJSON(t, ticket), mustConnectorJSON(t, connectorOriginalTicketByID(t, f, ticket.ID))) {
				t.Fatal("concurrent denied cleanup changed immutable ticket")
			}
			var charged, reserved int64
			if err = admin.QueryRow(ctx, "SELECT a.charged,(SELECT count(*) FROM connector_retirement_ticket t WHERE t.root_id=a.root_id AND t.principal_digest=a.principal_digest AND t.admitted_at IS NULL AND t.closed_unused_at IS NULL) FROM operation_audit_account a WHERE a.root_id=$1 AND a.lane='identity'", f.scenario.a.RootID).Scan(&charged, &reserved); err != nil || charged < 4 || reserved != 0 {
				t.Fatal("restriction refunded existing effects or duplicated reservation", charged, reserved, err)
			}
		})
	})
	t.Run("connector-identity-real-time-retirement", func(t *testing.T) {
		if os.Getenv("ASSERVAT_CONNECTOR_RETIREMENT_REALTIME") != "1" {
			t.Skip("explicit --connector-retirement owns the real minimum-time cleanup gate")
		}
		began := time.Now()
		f := newConnectorSQLFixtureWithOptions(t, ctx, admin, poolFor, store, keys, create(t, 1), 2100, connectorRetirementFixtureOptions{Enabled: true, Admission: 30 * time.Second})
		ticket := connectorOriginalTicket(t, f)
		// The supported thirty-second ordinary admission interval was configured
		// before acceptance. Certificate periods stay thirty minutes; retention is
		// the original 2100 seconds. This does not qualify maximum-duration admission.
		f.issue(t, "client")
		f.issue(t, "server")
		original := f.process
		connectorWaitUntil(t, ctx, ticket.AdmissionUntil.Add(-4*time.Second))
		f.refresh(t)
		f.request.Process.ProcessEpoch = custodyID()
		f.request.ClientCSRDER = connectorSQLCSR(t)
		f.request.ServerCSRDER = connectorSQLCSR(t)
		f.processID = custodyID()
		var err error
		f.process, err = f.enrollment.Enroll(ctx, f.processID, f.request)
		if err != nil {
			t.Fatal("process admitted near actual configured admission boundary", err)
		}
		if !f.process.ClaimedAt.After(ticket.AdmissionUntil.Add(-5*time.Second)) || f.process.RunUntil.Sub(f.process.ClaimedAt) != 30*time.Minute || !original.RunUntil.Equal(original.ClaimedAt.Add(30*time.Minute)) {
			t.Fatal("boundary process promises shortened")
		}
		f.issue(t, "client")
		f.issue(t, "server")
		_, service, closeTicket := connectorRetirementPorts(t, f)
		connectorWaitUntil(t, ctx, ticket.AdmissionUntil.Add(time.Millisecond))
		f.refresh(t)
		result, err := service.Expire(ctx, ticket.ID)
		if err != nil || !result.Restricted || !result.AuditAcknowledged {
			t.Fatal("historical retirement after original ordinary admission end", result, err)
		}
		// Original metadata/possible leaves remain untouched until their own end.
		var originalRows int
		if err = admin.QueryRow(ctx, "SELECT count(*) FROM connector_identity_process WHERE root_id=$1", f.scenario.a.RootID).Scan(&originalRows); err != nil || originalRows != 2 {
			t.Fatal("retirement deleted possible original process effects", originalRows, err)
		}
		var operations []audit.OperationIntent
		rows, err := admin.Query(ctx, "SELECT intent FROM operation_audit WHERE root_id=$1 AND lane='identity' ORDER BY id", f.scenario.a.RootID)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var raw []byte
			var in audit.OperationIntent
			if err = rows.Scan(&raw); err != nil || json.Unmarshal(raw, &in) != nil || !in.Valid() {
				rows.Close()
				t.Fatal("exact admitted lifecycle unavailable", err)
			}
			operations = append(operations, in)
		}
		err = rows.Err()
		rows.Close()
		if err != nil || len(operations) != 7 {
			t.Fatal("unexpected admitted operation set", len(operations), err)
		}
		var originalEnd, certificateEnd, historyEnd time.Time
		for _, in := range operations {
			originalEnd = maxConnectorTime(originalEnd, in.Lifecycle.OriginalPurgeAt)
			certificateEnd = maxConnectorTime(certificateEnd, in.Lifecycle.CertificatePurgeAt)
			historyEnd = maxConnectorTime(historyEnd, in.Lifecycle.HistoryReleaseAt)
		}
		connectorWaitUntil(t, ctx, ticket.ConsumeUntil.Add(time.Millisecond))
		if _, err = closeTicket.CloseAdmission(ctx, ticket.ID, connectorRetirementCurrent(t, f)); err != nil {
			t.Fatal("close permanently ended ticket admission", err)
		}
		if _, err = closeTicket.CloseWriterReference(ctx, ticket.ID, connectorRetirementCurrent(t, f)); err != nil {
			t.Fatal("close ended writer business reference", err)
		}
		connectorWaitUntil(t, ctx, originalEnd.Add(time.Millisecond))
		f.refresh(t)
		var detached int64
		if err = f.pools["cleanup"].QueryRow(ctx, "SELECT detach_connector_identity($1,$2)", f.scenario.a.RootID, f.process.Binding.PeerID).Scan(&detached); err != nil || detached != 2 {
			t.Fatal("original possible-leaf ends did not permit exact bounded detach", detached, err)
		}
		cleanups, history := connectorRetirementObjectCleanup(t, f, store, keys, operations)
		for i, cleanup := range cleanups {
			f.refresh(t)
			_ = cleanup.Advance(ctx, operations[i].ID) // Terminal certificate interval is still original and future.
			var acknowledged bool
			if err = admin.QueryRow(ctx, "SELECT certificate_acknowledged_at IS NOT NULL FROM operation_audit_lifecycle WHERE operation_id=$1", operations[i].ID).Scan(&acknowledged); err != nil || !acknowledged {
				t.Fatal("positive original purge/certificate not established", operations[i].ID, err)
			}
		}
		connectorWaitUntil(t, ctx, certificateEnd.Add(time.Millisecond))
		for i, cleanup := range cleanups {
			f.refresh(t)
			if err = cleanup.Advance(ctx, operations[i].ID); err != nil {
				t.Fatal("exact physical terminal purge/retirement", operations[i].ID, err)
			}
		}
		// Dedicated no-window regression: the old predicate required RetainUntil,
		// making compliant ticket deletion impossible. No persisted date is edited.
		t.Run("original-ticket-cleanup-window", func(t *testing.T) {
			ticketHistoryEnd := ticket.RetainUntil.Add(-time.Duration(ticket.Policy.BackupHorizonSeconds+ticket.Policy.CleanupBudgetSeconds) * time.Second)
			connectorWaitUntil(t, ctx, ticketHistoryEnd.Add(time.Millisecond))
			if !time.Now().Before(ticket.RetainUntil) {
				t.Fatal("missed original ticket metadata deletion window")
			}
			for _, h := range history {
				f.refresh(t)
				if report, e := h.Sweep(ctx); e != nil || report.Overdue {
					t.Fatal("original history cooling release", report, e)
				}
			}
			if deleted, e := closeTicket.DeleteTicket(ctx, ticket.ID, connectorRetirementCurrent(t, f)); e != nil || !deleted {
				t.Fatal("original ticket did not finish within original cleanup window", deleted, e)
			}
			if !time.Now().Before(ticket.RetainUntil) {
				t.Fatal("ticket cleanup exceeded its original retained bound")
			}
			var backup, wal, transitions int64
			if e := admin.QueryRow(ctx, "SELECT source_backup_bytes,source_wal_bytes,source_transitions FROM connector_identity_root WHERE root_id=$1", f.scenario.a.RootID).Scan(&backup, &wal, &transitions); e != nil || backup != f.configuration.Backing.SourceBackupReservedBytes || wal != f.configuration.Backing.SourceWALReservedBytes || transitions <= 0 {
				t.Fatal("ticket deletion refunded independent source backing or transitions", backup, wal, transitions, e)
			}
		})
		connectorWaitUntil(t, ctx, historyEnd.Add(time.Millisecond))
		for _, h := range history {
			f.refresh(t)
			if report, e := h.Sweep(ctx); e != nil || report.Overdue {
				t.Fatal("boundary process original history cooling release", report, e)
			}
		}
		var count int
		if err = admin.QueryRow(ctx, "SELECT (SELECT count(*) FROM connector_retirement_ticket WHERE root_id=$1)+(SELECT count(*) FROM operation_audit WHERE root_id=$1 AND lane='identity')+(SELECT count(*) FROM operation_audit_lifecycle WHERE root_id=$1 AND lane='identity')+(SELECT count(*) FROM operation_audit_history WHERE root_id=$1 AND lane='identity')", f.scenario.a.RootID).Scan(&count); err != nil || count != 0 {
			t.Fatal("ticket or admitted audit/history remained", count, err)
		}
		if _, err = service.Expire(ctx, ticket.ID); err == nil {
			t.Fatal("deleted original ticket was silently recreated")
		}
		if time.Since(began) < 1860*time.Second {
			t.Fatal("real-time qualification did not wait through the minimum original duration")
		}
		t.Logf("real configured admission=30s, unchanged process=1800s retention=2100s, measured subtest=%s; maximum-admission-duration native case remains separate", time.Since(began))
	})
}

func connectorOriginalTicket(t *testing.T, f *connectorSQLFixture) audit.ConnectorRetirementTicket {
	t.Helper()
	var id string
	if err := f.admin.QueryRow(f.ctx, "SELECT id::text FROM connector_retirement_ticket WHERE root_id=$1 AND peer_id=$2 AND activated_at IS NOT NULL AND superseded_at IS NULL", f.scenario.a.RootID, f.process.Binding.PeerID).Scan(&id); err != nil {
		t.Fatal("current immutable ticket", err)
	}
	return connectorOriginalTicketByID(t, f, id)
}
func connectorOriginalTicketByID(t *testing.T, f *connectorSQLFixture, id string) audit.ConnectorRetirementTicket {
	t.Helper()
	var raw []byte
	var ticket audit.ConnectorRetirementTicket
	if err := f.admin.QueryRow(f.ctx, "SELECT ticket FROM connector_retirement_ticket WHERE root_id=$1 AND id=$2", f.scenario.a.RootID, id).Scan(&raw); err != nil || json.Unmarshal(raw, &ticket) != nil || !ticket.Valid() {
		t.Fatal("invalid original ticket", err)
	}
	return ticket
}
func mustConnectorJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func maxConnectorTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}
func connectorWaitUntil(t *testing.T, ctx context.Context, until time.Time) {
	t.Helper()
	for time.Now().Before(until) {
		wait := min(time.Until(until), 20*time.Second)
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			t.Fatal("original test context ended while waiting", ctx.Err())
		case <-timer.C:
		}
	}
}
func connectorRetirementCurrent(t *testing.T, f *connectorSQLFixture) app.ConnectorRetirementCurrent {
	t.Helper()
	f.refresh(t)
	n := time.Now().UTC().Truncate(time.Microsecond)
	r, e := f.scenario.recovery.reader.RecoveryState(f.ctx)
	if e != nil {
		t.Fatal(e)
	}
	return app.ConnectorRetirementCurrent{Recovery: r, ObservedAt: n, Until: identity.Earlier(n.Add(5*time.Second), r.FreshUntil)}
}
func connectorRetirementPorts(t *testing.T, f *connectorSQLFixture) (*postgres.ConnectorRetirements, app.ConnectorRetirementService, *postgres.ConnectorRetirementCleanup) {
	t.Helper()
	j, e := postgres.NewConnectorRetirements(f.ctx, f.pools["journal"], f.scenario.a.RootID, f.configuration.Backing, f.mac)
	if e != nil {
		t.Fatal(e)
	}
	c, e := postgres.NewConnectorRetirementCleanup(f.ctx, f.pools["cleanup"], f.scenario.a.RootID, f.scenario.recovery.installation)
	if e != nil {
		t.Fatal(e)
	}
	return j, app.ConnectorRetirementService{RootID: f.scenario.a.RootID, Recovery: f.scenario.recovery.reader, Journal: j, Audit: f.audit, MAC: f.mac, Now: time.Now}, c
}
func connectorRetirementObjectCleanup(t *testing.T, f *connectorSQLFixture, store *objectstore.Store, keys authorityTestKeys, operations []audit.OperationIntent) ([]auditapp.OperationCleanup, []auditapp.OperationHistoryCleanup) {
	t.Helper()
	pub, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	signer, e := jose.NewOperationRetirementSignatures(f.scenario.a.RootID, "synthetic-connector-retirement", private, map[string]ed25519.PublicKey{"synthetic-connector-retirement": pub})
	if e != nil {
		t.Fatal(e)
	}
	verifier, e := jose.NewOperationRetirementSignatures(f.scenario.a.RootID, "", nil, map[string]ed25519.PublicKey{"synthetic-connector-retirement": pub})
	if e != nil {
		t.Fatal(e)
	}
	out := make([]auditapp.OperationCleanup, 0, len(operations))
	histories := make([]auditapp.OperationHistoryCleanup, 0, len(operations))
	for _, in := range operations {
		p := in.Lifecycle.Policy
		facet := func(role string) *postgres.OperationLifecycles {
			v, e := postgres.NewConnectorOperationLifecycles(f.ctx, f.pools[role], p, f.scenario.recovery.guard)
			if e != nil {
				t.Fatal(role, e)
			}
			return v
		}
		journal, ack, finalizer := facet("cleanup"), facet("verifier"), facet("finalizer")
		objects, e := objectstore.NewOperationAuditCleanupObjects(store, p.StoreID, keys, keys, signer, verifier)
		if e != nil {
			t.Fatal(e)
		}
		read, e := objectstore.NewOperationAuditCleanupVerifier(store, p.StoreID, keys, verifier)
		if e != nil {
			t.Fatal(e)
		}
		out = append(out, auditapp.OperationCleanup{Journal: journal, Acknowledgements: ack, Finalizer: finalizer, Objects: objects, Verifier: read})
		histories = append(histories, auditapp.OperationHistoryCleanup{Journal: journal, Finalizer: finalizer})
	}
	return out, histories
}

// Explicitly synthetic protected Pod/source proof for the SQL fixture only.
// The production Kubernetes attester is independently qualified and is not
// replaced by this callback in any installed composition.
type connectorRetirementProofFixture struct{ f *connectorSQLFixture }

func (p connectorRetirementProofFixture) ReadConnectorRetirementProof(ctx context.Context, request value.ConnectorProcessRequest) (value.ConnectorRetirementProof, error) {
	proof, err := p.f.ReadConnectorProcessProof(ctx, request)
	result := value.ConnectorRetirementProof(proof)
	if err != nil || !result.Valid(time.Now()) || proof.Valid(time.Now()) {
		return value.ConnectorRetirementProof{}, value.ErrUnavailable
	}
	return result, nil
}

// A real held event lock must not let Store's old observation become a new
// provider effect after its original deadline. No production date is changed.
func qualifyConnectorRetirementBlockedOutcome(t *testing.T, f *connectorSQLFixture, j *postgres.ConnectorRetirements, ticket audit.ConnectorRetirementTicket) {
	t.Helper()
	current := connectorRetirementCurrent(t, f)
	r, err := j.RestrictConnectorRetirement(f.ctx, ticket.ID, audit.ConnectorRetirementExpiry, current)
	if err != nil {
		t.Fatal("prepare actual restrictive fence", err)
	}
	r, err = j.PrepareConnectorRetirement(f.ctx, r, current)
	if err != nil || r.Snapshot == nil {
		t.Fatal("prepare exact original retirement writer", err)
	}
	if err = f.audit.Begin(f.ctx, r.Snapshot.Intent); err != nil {
		t.Fatal("original retirement intent acknowledgement", err)
	}
	current = connectorRetirementCurrent(t, f)
	current.Until = current.ObservedAt.Add(150 * time.Millisecond)
	out := audit.OperationOutcome{Intent: r.Snapshot.Intent, Status: "success", Reason: "prepared", Effect: "accepted", ClientReceipt: "unknown", OutputDigest: artifact.Digest{79}, OutputBytes: 1, RecordedAt: current.ObservedAt, MetadataUntil: current.Until}
	// Administrative credentials hold a fixture-only lock; no state is edited.
	tx, err := f.admin.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(f.ctx, "SELECT id FROM operation_audit WHERE id=$1 FOR UPDATE", ticket.ID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithDeadline(f.ctx, current.Until)
	defer cancel()
	if _, err = j.StoreConnectorRetirementOutcome(ctx, out, current); err == nil {
		t.Fatal("blocked outcome accepted beyond original observation")
	}
	if err = tx.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	var absent bool
	if err = f.admin.QueryRow(f.ctx, "SELECT outcome IS NULL FROM operation_audit WHERE id=$1", ticket.ID).Scan(&absent); err != nil || !absent {
		t.Fatal("expired blocked Store committed a business outcome", absent, err)
	}
}
