package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Actual SQL semantic control, explicitly below the public audited boundary.
// Synthetic current identity/protected observations remain fixture inputs.
func qualifyPolicyGrantAttachmentControl(t *testing.T, ctx context.Context, admin, hub *pgxpool.Pool, source *postgres.Policies, observation capture.PolicySource, actor identity.Identity, grant authorization.Grant, recovery artifact.RecoveryProof) {
	t.Helper()
	control, err := postgres.NewPolicies(ctx, hub, grant.RootID, grant.Policy.Authority.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	actor.Principal.Subject = "new-current-team-maintainer"
	actor.Scopes = []string{"evidence:read", "evidence:capture"}
	in := app.PolicyGrantAttachmentInput{ID: custodyID(), PolicyUID: observation.Revision.UID, GrantID: grant.ID, IdempotencyKey: "explicit-current-manager-attachment", Actor: actor, Recovery: recovery}
	a, replay, err := control.AttachPolicyGrant(ctx, in)
	if err != nil || replay || !a.Valid() || a.Actor != actor.Principal || a.Actor == grant.Requester || a.GrantID != grant.ID {
		t.Fatal("current manager could not attach original team grant", a, replay, err)
	}
	pointer := func() string {
		t.Helper()
		var id string
		if err := admin.QueryRow(ctx, `SELECT COALESCE(grant_attachment_id::text,'') FROM policy_source WHERE root_id=$1 AND policy_uid=$2`, grant.RootID, observation.Revision.UID).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	if pointer() != a.ID {
		t.Fatal("attachment did not name its immutable control receipt")
	}
	conflict := in
	conflict.ID, conflict.GrantID = custodyID(), custodyID()
	if _, _, err := control.AttachPolicyGrant(ctx, conflict); !errors.Is(err, app.ErrGrantConflict) || pointer() != a.ID {
		t.Fatal("changed original attachment input did not conflict before lookup", err)
	}
	wrongClient := in
	wrongClient.ID = custodyID()
	wrongClient.Actor.Principal.ClientID = "different-authorized-client"
	clientReceipt, clientReplay, err := control.AttachPolicyGrant(ctx, wrongClient)
	if err != nil || clientReplay || clientReceipt.ID == a.ID || clientReceipt.Actor != wrongClient.Actor.Principal || pointer() != clientReceipt.ID {
		t.Fatal("another client inherited attachment request journal", clientReceipt, clientReplay, err)
	}
	// Restore the original pointer through a fresh explicit control, so the
	// subsequent source-edit assertions distinguish clearing from replacement.
	restore := in
	restore.ID, restore.IdempotencyKey = custodyID(), "restore-original-client"
	a, replay, err = control.AttachPolicyGrant(ctx, restore)
	if err != nil || replay || pointer() != a.ID {
		t.Fatal("explicit original-client control failed", a, replay, err)
	}
	in = restore
	// Reproduce the previous predicate-only approach in a rolled-back SQL
	// transaction: accepted A→B→A leaves the original pointer reusable. These
	// synthetic source edits supply no product authority and never escape rollback.
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE policy_source SET authored_grant_ref=$3 WHERE root_id=$1 AND policy_uid=$2`, grant.RootID, observation.Revision.UID, grant.ID); err == nil {
		_, err = tx.Exec(ctx, `UPDATE policy_source SET authored_grant_ref='' WHERE root_id=$1 AND policy_uid=$2`, grant.RootID, observation.Revision.UID)
	}
	var oldPointer string
	if err == nil {
		err = tx.QueryRow(ctx, `SELECT grant_attachment_id::text FROM policy_source WHERE root_id=$1 AND policy_uid=$2`, grant.RootID, observation.Revision.UID).Scan(&oldPointer)
	}
	rolledBack := tx.Rollback(ctx)
	if err != nil || rolledBack != nil || oldPointer != a.ID {
		t.Fatal("prior pointer-only ABA reproduction invalid", oldPointer, err, rolledBack)
	}
	observe := func(ref string, change bool) {
		t.Helper()
		if change {
			observation.Revision.Generation++
			observation.Revision.Digest[0]++
		}
		observation.AuthoredGrantRef = ref
		observation.ResourceVersion = custodyID()
		observation.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
		observation.FreshUntil = observation.ObservedAt.Add(5 * time.Second)
		if err := source.ObservePolicy(ctx, observation); err != nil {
			t.Fatal("accepted protected source control", err)
		}
	}
	observe(grant.ID, true)
	if pointer() != "" {
		t.Fatal("accepted authored reference change retained old attachment")
	}
	observe("", true)
	if pointer() != "" {
		t.Fatal("accepted A→B→A revived old attachment")
	}
	lostReply := in
	lostReply.ID = custodyID()
	previous, replay, err := control.AttachPolicyGrant(ctx, lostReply)
	if err != nil || !replay || previous.ID != a.ID || !previous.AttachedAt.Equal(a.AttachedAt) || pointer() != "" {
		t.Fatal("lost original reply reattached or replaced the receipt", previous, replay, err)
	}
	withdrawn := in
	withdrawn.ID, withdrawn.IdempotencyKey = custodyID(), "departed-maintainer"
	withdrawn.Actor.Groups = nil
	if _, _, err := control.AttachPolicyGrant(ctx, withdrawn); !errors.Is(err, identity.ErrDenied) || pointer() != "" {
		t.Fatal("historical creator/requester identity became management authority", err)
	}
	reconciled := in
	reconciled.ID, reconciled.IdempotencyKey = custodyID(), "explicit-reconciliation-after-ref-change"
	b, replay, err := control.AttachPolicyGrant(ctx, reconciled)
	if err != nil || replay || b.ID == a.ID || b.GrantID != a.GrantID || pointer() != b.ID {
		t.Fatal("explicit reconciliation did not preserve original grant", b, replay, err)
	}
	observe("", false)
	if pointer() != b.ID {
		t.Fatal("unchanged reference observation discarded explicit attachment")
	}
	current, _, err := control.AcceptedPolicyRecord(ctx, observation.Revision.UID)
	if err != nil || current.Authority.ScopeDigest != grant.Policy.Authority.ScopeDigest || !current.Authority.IssuedAt.Equal(grant.Policy.Authority.IssuedAt) || !current.Authority.NotAfter.Equal(grant.Policy.Authority.NotAfter) {
		t.Fatal("control edits reissued accepted collection authority", err)
	}
	var executions, collected, observed int64
	if err = admin.QueryRow(ctx, `SELECT policy_executions_spent,policy_bytes_spent,policy_observed_bytes_spent FROM access_grant WHERE id=$1`, grant.ID).Scan(&executions, &collected, &observed); err != nil || executions != grant.PolicySpend.Executions || collected != grant.PolicySpend.CollectedBytes || observed != grant.PolicySpend.ObservedBytes {
		t.Fatal("attachment changed grant spend", err)
	}
	var count int
	if err = admin.QueryRow(ctx, `SELECT count(*) FROM policy_grant_attachment WHERE root_id=$1`, grant.RootID).Scan(&count); err != nil || count != 4 {
		t.Fatal("replay/refusal created another control receipt", count, err)
	}
}
