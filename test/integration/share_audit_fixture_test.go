package integration

import (
	"context"
	"testing"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/application/sharing"
	"asservat.local/asservat/internal/domain/authorization"
	"github.com/jackc/pgx/v5/pgxpool"
)

// paidShareService stands in for the public operation boundary: it gives each
// call a fresh request ID, which the effect's audit row carries.
type paidShareService struct {
	sharing.Service
}

func (s paidShareService) Create(ctx context.Context, current identities.CurrentIdentity, in sharing.CreateInput) (authorization.Share, bool, error) {
	in.OperationID = custodyID()
	return s.Service.Create(ctx, current, in)
}
func (s paidShareService) Revoke(ctx context.Context, current identities.CurrentIdentity, in sharing.RevokeInput) (authorization.Share, bool, error) {
	in.OperationID = custodyID()
	return s.Service.Revoke(ctx, current, in)
}
func (s paidShareService) Transfer(ctx context.Context, current identities.CurrentIdentity, in sharing.TransferInput) (authorization.Share, bool, error) {
	in.OperationID = custodyID()
	return s.Service.Transfer(ctx, current, in)
}
func (s paidShareService) RevokePolicySharing(ctx context.Context, current identities.CurrentIdentity, in sharing.PolicyRevokeInput) (sharing.PolicyRevokeResult, error) {
	in.OperationID = custodyID()
	return s.Service.RevokePolicySharing(ctx, current, in)
}
func (s paidShareService) StopPolicySharing(ctx context.Context, current identities.CurrentIdentity, in sharing.PolicyRevokeInput) (sharing.PolicyRevokeResult, error) {
	in.OperationID = custodyID()
	return s.Service.StopPolicySharing(ctx, current, in)
}

// A capture admission under the compiled capture-admit role. Its audit row
// commits with the admission (ADR-330 D6).
type shareCaptureAudit struct {
	publication   *postgres.CaptureIntents
	admissions    *postgres.ContextAdmissions
	admissionRole string
}

func newShareCaptureAudit(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, s captureAdmissionScenario) shareCaptureAudit {
	t.Helper()
	admissionRole := narrowRole(t, ctx, admin, "share_capture_admit_", "synthetic-share-capture-admit", func(role string) []string {
		grants, ok := postgres.PublicRuntimeRoleGrantSQL("capture-admit", role)
		if !ok {
			t.Fatal("compiled policy-aware capture admission role")
		}
		return grants
	})
	pool := poolFor(admissionRole, "synthetic-share-capture-admit")
	t.Cleanup(pool.Close)
	admissions, err := postgres.NewContextAdmissions(ctx, pool, s.a.RootID, s.recovery.installation)
	if err != nil {
		t.Fatal(err)
	}
	intents, err := postgres.NewCaptureIntents(ctx, pool, s.a.RootID)
	if err != nil {
		t.Fatal(err)
	}
	return shareCaptureAudit{intents, admissions, admissionRole}
}
