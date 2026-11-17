package integration

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Own a fresh capacity fixture. Capacity creates the processing root and no
// normal, resolution or processing audit pool; each decision commits its own
// audit row through the compiled hub-runtime credential (REQ-AUT-005).
// Protected source and privacy identity remain synthetic inputs.
func TestProcessingDecisionsOnCapacityRootWithRealPostgres(t *testing.T) {
	withCapacityProducerFixture(t, func(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope fleet.InstallationWitnessScope, claim string, objects *objectstore.AuthorityObjects) {
		f := newCapacitySQLFixture(t, ctx, admin, address, tlsConfig, scope, claim, objects)
		f.setup(t)
		f.refreshBase(t)
		var lanes []string
		if err := admin.QueryRow(ctx, `SELECT coalesce(array_agg(lane ORDER BY lane),'{}') FROM operation_audit_pool WHERE root_id=$1`, f.input.PermissionRootID).Scan(&lanes); err != nil || len(lanes) != 1 || lanes[0] != "capture" {
			t.Fatal("capacity created an audit pool other than capture", lanes, err)
		}
		decisions, err := postgres.NewProcessingDecisions(ctx, f.roles["hub-runtime"], f.input.PermissionRootID)
		if err != nil {
			t.Fatal("compiled hub processing decisions", err)
		}
		actor := processingTestIdentity{value: identity.Identity{Principal: identity.Principal{Issuer: "https://id.example.test", Subject: "capacity-privacy-operator", ClientID: "console", Kind: identity.Human}, Groups: []string{"operators"}, Scopes: []string{"evidence:privacy"}, Policy: identity.Revision{UID: "synthetic-privacy-identity", Generation: 1, Digest: artifact.Digest{28}}}}
		service := privacyapp.ProcessingChanges{RootID: f.input.PermissionRootID, InstallationID: f.input.InstallationID, Policies: processingTestPolicy{value: f.processingPolicy}, Decisions: decisions, Now: time.Now}
		change := func(in privacy.ProcessingChange, want string) privacy.ProcessingReceipt {
			t.Helper()
			f.refreshBase(t)
			r, err := service.Change(ctx, actor, in)
			if err != nil || r.State != want {
				t.Fatal("compiled hub processing change", in.Action, r, err)
			}
			return r
		}
		now := time.Now().In(time.FixedZone("operator", 5*3600+30*60)).Truncate(time.Microsecond)
		restrict := privacy.ProcessingChange{RequestID: custodyID(), RuleID: custodyID(), Action: "restrict_processing", Scope: privacy.ProcessingScope{Kind: "workloadInterval", ClusterID: scope.ClusterID, NamespaceUID: f.namespace.UID, WorkloadUID: f.workloads[0].UID, AcquiredFrom: now.Add(-time.Second), AcquiredUntil: now.Add(time.Second)}}
		blocked := change(restrict, "restricted")
		release := restrict
		release.RequestID, release.Action, release.ExpectedRevision = custodyID(), "release_processing", blocked.Revision
		released := change(release, "released")
		replayed := change(release, "released")
		if released.Revision != 2 || replayed.Revision != released.Revision || replayed.Sequence != released.Sequence || replayed.OperationID != released.OperationID {
			t.Fatal("same-key release replay changed its original effect", released, replayed)
		}
		var rows int64
		if err = admin.QueryRow(ctx, `SELECT count(*) FROM audit_event WHERE operation_id=ANY($1::uuid[]) AND kind=operation AND subject='capacity-privacy-operator' AND status='success' AND effect='accepted'`, []string{restrict.RequestID, release.RequestID}).Scan(&rows); err != nil || rows != 2 {
			t.Fatal("decisions did not commit exactly one audit row each", rows, err)
		}
	})
}
