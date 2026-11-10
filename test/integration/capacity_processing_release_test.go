package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Own a fresh initial-activation/capacity fixture. Every processing and audit
// effect uses the actual compiled hub-runtime credential; the read-only profile
// uses its actual compiled capacity-profile-read credential. Protected source,
// privacy identity and physical-history qualification remain synthetic inputs.
func TestProcessingReleaseProfilesWithRealPostgres(t *testing.T) {
	withCapacityProducerFixture(t, func(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope fleet.InstallationWitnessScope, claim string, administration fleet.Administration, objects *objectstore.AuthorityObjects) {
		f := newCapacitySQLFixture(t, ctx, admin, address, tlsConfig, scope, claim, administration, objects, func(f *capacitySQLFixture) {
			// This dedicated qualification funds exactly initialize+restrict on
			// the human's normal account. The release reserve stays unchanged.
			normal := &f.qualification.RootBacking.Normal
			normal.RecordsPerAccount = 2
			normal.Policy.MetadataSlots = normal.Accounts * normal.RecordsPerAccount
			b, w := normal.Policy.History.SlotBacking(normal.Policy.MaxPurgeLeases)
			normal.Policy.BackupReservedBytes, normal.Policy.WALReservedBytes = b*normal.Policy.MetadataSlots, w*normal.Policy.MetadataSlots
			f.qualification.RootBacking.Processing.RetainedSeconds = normal.RetainedSeconds + 1000
		})
		if _, err := f.producer.InitializeCapacity(ctx, f.input, f.protection); err != nil {
			t.Fatal("initialize original capacity", err)
		}
		f.open(t)
		o := f.rootObservation(t)
		root, err := f.roots.ReserveCapacityRoot(ctx, o)
		if err != nil {
			t.Fatal("reserve original root", err)
		}
		root, err = f.captureRoots.BackCapacityRoot(ctx, o, root)
		if err != nil {
			t.Fatal("back original root", err)
		}
		root, err = f.roots.PublishCapacityRoot(ctx, o, root)
		if err != nil || !root.AdmissionReady(time.Now()) {
			t.Fatal("publish original root", err)
		}
		f.fresh(t)
		profiles := f.readAuditProfiles(t)
		var originalPolicy []byte
		var retained int64
		if err = admin.QueryRow(ctx, `SELECT p.release_policy,a.retained_seconds FROM processing_root p JOIN operation_audit_pool a ON a.root_id=p.root_id AND a.lane='processing' WHERE p.root_id=$1`, f.input.PermissionRootID).Scan(&originalPolicy, &retained); err != nil {
			t.Fatal("retained release reserve", err)
		}
		var persisted audit.OperationLifecyclePolicy
		if json.Unmarshal(originalPolicy, &persisted) != nil {
			t.Fatal("retained release policy malformed")
		}
		left, _ := json.Marshal(profiles.Processing.Policy)
		right, _ := json.Marshal(persisted)
		if !bytes.Equal(left, right) || profiles.Processing.Policy.History.Layout != audit.ProcessingReleaseHistoryLayout || profiles.Processing.RetainedSeconds != retained || retained == profiles.Normal.RetainedSeconds {
			t.Fatal("compiled profile read lost the exact private reserve or lane retention")
		}
		guard, err := postgres.NewRecoveryTransactionGuard(f.input.PermissionRootID, f.input.InstallationID)
		if err != nil {
			t.Fatal(err)
		}
		pool := f.roles["hub-runtime"]
		recovery, err := postgres.NewRecoveryReader(ctx, pool, f.input.InstallationID)
		if err != nil {
			t.Fatal("compiled hub recovery reader", err)
		}
		buildAudit := func(p audit.OperationLifecyclePolicy) *auditapp.HealthyOperationAuditor {
			t.Helper()
			var journal *postgres.OperationJournal
			var ack *postgres.OperationAcknowledgements
			var lifecycle *postgres.OperationLifecycles
			var err error
			if p.Lane == "processing" {
				journal, err = postgres.NewProcessingReleaseJournal(ctx, pool, p, guard)
				if err == nil {
					ack, err = postgres.NewProcessingReleaseAcknowledgements(ctx, pool, p, guard)
				}
				if err == nil {
					lifecycle, err = postgres.NewProcessingReleaseLifecycles(ctx, pool, p, guard)
				}
			} else {
				journal, err = postgres.NewHealthyOperationJournal(ctx, pool, p, guard)
				if err == nil {
					ack, err = postgres.NewOperationAcknowledgements(ctx, pool, p.RootID, p.Lane, guard)
				}
				if err == nil {
					lifecycle, err = postgres.NewOperationLifecycles(ctx, pool, p.RootID, p.Lane, guard)
				}
			}
			if err != nil {
				t.Fatal("compiled hub audit facets", p.Lane, err)
			}
			closed, err := objectstore.NewClosedOperationAuditObjects(f.store, p.StoreID, f.keys, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			out, err := auditapp.NewHealthyOperationAuditor(p, journal, ack, &objectstore.OperationAuditObjects{Store: f.store, Seal: f.keys, Open: f.keys}, closed, lifecycle, time.Now)
			if err != nil {
				t.Fatal("compiled hub audit composition", p.Lane, err)
			}
			return out
		}
		material := f.root.value.State.MAC
		mac, err := auditapp.NewOperationMAC(material.InputVersion, material.InputKey, material.AccountVersion, material.AccountKey)
		if err != nil {
			t.Fatal(err)
		}
		defer mac.Close()
		decisions, err := postgres.NewProcessingDecisions(ctx, pool, f.input.PermissionRootID, guard)
		if err != nil {
			t.Fatal("compiled hub processing decisions", err)
		}
		actor := processingTestIdentity{value: identity.Identity{Principal: identity.Principal{Issuer: "https://id.example.test", Subject: "capacity-privacy-operator", ClientID: "console", Kind: identity.Human}, Groups: []string{"operators"}, Scopes: []string{"evidence:privacy"}, Policy: identity.Revision{UID: "synthetic-privacy-identity", Generation: 1, Digest: artifact.Digest{28}}}}
		service := privacyapp.ProcessingChanges{RootID: f.input.PermissionRootID, InstallationID: f.input.InstallationID, Policies: processingTestPolicy{value: f.processingPolicy}, Recovery: recovery, Decisions: decisions,
			Audit: buildAudit(profiles.Normal.Policy), ReleaseAudit: buildAudit(profiles.Processing.Policy), MAC: mac, AuditPolicy: profiles.Normal.Policy, ReleaseAuditPolicy: profiles.Processing.Policy, RetainedSeconds: profiles.Normal.RetainedSeconds, Now: time.Now}
		change := func(in privacy.ProcessingChange, want string) privacy.ProcessingReceipt {
			t.Helper()
			f.fresh(t)
			r, err := service.Change(ctx, actor, in)
			if err != nil || r.State != want {
				t.Fatal("compiled hub processing change", in.Action, r, err)
			}
			return r
		}
		change(privacy.ProcessingChange{RequestID: custodyID(), Action: "initialize_processing"}, "initialized")
		now := time.Now().In(time.FixedZone("operator", 5*3600+30*60)).Truncate(time.Microsecond)
		restrict := privacy.ProcessingChange{RequestID: custodyID(), RuleID: custodyID(), Action: "restrict_processing", Scope: privacy.ProcessingScope{Kind: "workloadInterval", ClusterID: scope.ClusterID, NamespaceUID: f.namespace.UID, WorkloadUID: f.workloads[0].UID, AcquiredFrom: now.Add(-time.Second), AcquiredUntil: now.Add(time.Second)}}
		blocked := change(restrict, "restricted")
		human, err := mac.Principal(actor.value.Principal)
		if err != nil {
			t.Fatal(err)
		}
		var charged, limit int64
		if err = admin.QueryRow(ctx, `SELECT a.charged,p.records_per_account FROM operation_audit_account a JOIN operation_audit_pool p USING(root_id,lane) WHERE a.root_id=$1 AND a.lane='normal' AND a.principal_digest=$2`, f.input.PermissionRootID, human[:]).Scan(&charged, &limit); err != nil || charged != 2 || limit != 2 {
			t.Fatal("normal human audit account was not full before release", charged, limit, err)
		}
		service.RetainedSeconds = profiles.Processing.RetainedSeconds
		release := restrict
		release.RequestID, release.Action, release.ExpectedRevision = custodyID(), "release_processing", blocked.Revision
		released := change(release, "released")
		replayed := change(release, "released")
		if released.Revision != 2 || replayed.Revision != released.Revision || replayed.Sequence != released.Sequence || replayed.OperationID != released.OperationID {
			t.Fatal("same-key release replay changed its original effect", released, replayed)
		}
		var normalCount, releaseCount int64
		if err = admin.QueryRow(ctx, `SELECT count(*) FILTER(WHERE lane='normal'),count(*) FILTER(WHERE lane='processing') FROM operation_audit WHERE root_id=$1`, f.input.PermissionRootID).Scan(&normalCount, &releaseCount); err != nil || normalCount != 2 || releaseCount != 1 {
			t.Fatal("release or replay consumed normal capacity or another audit", normalCount, releaseCount, err)
		}
		var actualRetention int64
		var reservedAccount []byte
		var policyMatches, actorMatches, acknowledged bool
		expectedAccount, err := mac.ProcessingAccount(f.input.InstallationID, f.input.PermissionRootID, release.RuleID)
		if err != nil {
			t.Fatal(err)
		}
		actorJSON, _ := json.Marshal(actor.value.Principal)
		if err = admin.QueryRow(ctx, `SELECT extract(epoch FROM(a.retain_until-(a.intent->>'CreatedAt')::timestamptz))::bigint,a.principal_digest,a.intent->'Lifecycle'->'Policy'=p.release_policy,a.intent->'Actor'=$3::jsonb,a.intent_receipt IS NOT NULL AND a.outcome_receipt IS NOT NULL FROM operation_audit a JOIN processing_root p USING(root_id) WHERE a.root_id=$1 AND a.id=$2 AND a.lane='processing'`, f.input.PermissionRootID, release.RequestID, actorJSON).Scan(&actualRetention, &reservedAccount, &policyMatches, &actorMatches, &acknowledged); err != nil || actualRetention != retained || !bytes.Equal(reservedAccount, expectedAccount[:]) || bytes.Equal(reservedAccount, human[:]) || !policyMatches || !actorMatches || !acknowledged {
			t.Fatal("persisted release lost exact private policy/retention/reserve/human/ack", actualRetention, policyMatches, actorMatches, acknowledged, err)
		}
		t.Log("compiled capacity profile and hub role: exact reserved policy/retention, full-normal-account release, stable replay and one private audit")
	})
}
