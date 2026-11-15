package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/application/sharing"
	value "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Test-only equivalent of the normal ingress Begin/Finish around actual sharing
// services. It reads the original preprovisioned cohort, never upgrades a live
// profile or manufactures an acknowledgement/operation ID.
type shareBusinessAudit struct {
	t        *testing.T
	gate     *auditapp.HealthyOperationAuditor
	mac      *auditapp.OperationMAC
	policy   value.OperationLifecyclePolicy
	retained int64
}

func newShareBusinessAudit(t *testing.T, ctx context.Context, hub *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, s captureAdmissionScenario) *shareBusinessAudit {
	t.Helper()
	cohort, ok := shareAuditCohorts.Load(s.a.RootID)
	if !ok {
		t.Fatal("share fixture requires the sharing-cohort processing fixture")
	}
	policy, retained := cohort.(shareAuditCohort).policy, cohort.(shareAuditCohort).retained
	if policy.History == nil || policy.History.Layout != value.ShareOperationHistoryLayout {
		t.Fatal("share fixture must select the qualified share cohort")
	}
	// Exact existing synthetic MAC material of newProcessingTestFixture.
	mac, err := auditapp.NewOperationMAC("input-v1", bytes.Repeat([]byte{31}, 32), "accounts-v1", bytes.Repeat([]byte{32}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mac.Close)
	qualifyShareLifecycleBusinessWAL(t, ctx, hub, policy, retained, mac, s.a.Eligibility.VerifiedIdentity.Principal)
	journal, err := postgres.NewHealthyOperationJournal(ctx, hub, policy)
	if err != nil {
		t.Fatal(err)
	}
	acks, err := postgres.NewOperationAcknowledgements(ctx, hub, s.a.RootID, "normal", s.recovery.installation)
	if err != nil {
		t.Fatal(err)
	}
	completions, err := postgres.NewOperationLifecycles(ctx, hub, s.a.RootID, "normal", s.recovery.installation)
	if err != nil {
		t.Fatal(err)
	}
	closed, err := objectstore.NewClosedOperationAuditObjects(store, policy.StoreID, keys, keys)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := auditapp.NewHealthyOperationAuditor(policy, journal, acks, &objectstore.OperationAuditObjects{Store: store, Seal: keys, Open: keys}, closed, completions, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	return &shareBusinessAudit{t, gate, mac, policy, retained}
}

// Attack the actual reservation table through the compiled hub role. The
// otherwise valid envelope is deliberately underfunded after Go binding, so a
// Go-side refusal cannot substitute for the lifecycle INSERT trigger's fence.
// Both the reservation and its charge roll back; no audit/provider I/O occurs.
func qualifyShareLifecycleBusinessWAL(t *testing.T, ctx context.Context, hub *pgxpool.Pool, policy value.OperationLifecyclePolicy, retained int64, mac *auditapp.OperationMAC, actor identity.Principal) {
	t.Helper()
	principal, err := mac.Principal(actor)
	if err != nil {
		t.Fatal(err)
	}
	input, err := mac.Digest("context-input/v1", []byte("business-wal-admission-probe"))
	if err != nil {
		t.Fatal(err)
	}
	_, slotWAL := policy.History.SlotBacking(policy.MaxPurgeLeases)
	minimumWAL := policy.MetadataSlots * slotWAL
	for _, tc := range []struct {
		name    string
		missing int64
	}{{"protocol-only", policy.MetadataSlots * 2 * policy.History.WALCopies * value.ShareOperationBusinessWALBytes}, {"one-byte-short", 1}} {
		n := time.Now().UTC().Truncate(time.Microsecond)
		operation := custodyID()
		in := value.OperationIntent{ID: operation, RootID: policy.RootID, TraceID: operation, Name: "create_share", InputFormat: "context-input/v1", MACVersion: mac.Version(), AccountVersion: mac.AccountVersion(), Actor: actor, PrincipalDigest: principal, InputDigest: input, CreatedAt: n, RequestUntil: n.Add(5 * time.Second), WriteUntil: n.Add(8 * time.Second), RetainUntil: n.Add(time.Duration(retained) * time.Second)}
		in, err = auditapp.BindOperationLifecycle(in, policy)
		if err != nil || !in.Valid() {
			t.Fatal("business WAL probe original envelope", err)
		}
		in.Lifecycle.Policy.WALReservedBytes = minimumWAL - tc.missing
		body, err := json.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		tx, err := hub.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, insertErr := tx.Exec(ctx, `INSERT INTO operation_audit(id,root_id,lane,principal_digest,intent,request_until,write_until,retain_until,issuer_epoch)
 SELECT $1,$2,'normal',$3,$4,$5,$6,$7,issuer_epoch FROM fleet_current_trust WHERE installation_id=$8`, in.ID, in.RootID, in.PrincipalDigest[:], body, in.RequestUntil, in.WriteUntil, in.RetainUntil, policy.InstallationID)
		rollbackErr := tx.Rollback(ctx)
		var refusal *pgconn.PgError
		if !errors.As(insertErr, &refusal) || refusal.Code != "23514" || refusal.Message != "audit history qualification unavailable" || rollbackErr != nil {
			t.Fatal("actual lifecycle accepted missing business WAL or refused outside funding guard", tc.name, insertErr, rollbackErr)
		}
		var absent bool
		if err := hub.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM operation_audit WHERE id=$1) AND NOT EXISTS(SELECT 1 FROM operation_audit_lifecycle WHERE operation_id=$1)`, operation).Scan(&absent); err != nil || !absent {
			t.Fatal("underfunded lifecycle probe left retained rows", tc.name, err)
		}
	}
	t.Log("actual normal-v4 lifecycle INSERT rejected protocol-only and one-byte-short business WAL through compiled hub grants; both transactions rolled back")
}

func (a *shareBusinessAudit) begin(ctx context.Context, current identities.CurrentIdentity, name, key string) value.OperationIntent {
	a.t.Helper()
	i, err := current.ResolveIdentity(ctx)
	if err != nil {
		a.t.Fatal("fixture ingress identity", err)
	}
	return beginPaidShareOperation(a.t, ctx, a.gate, a.mac, a.policy, i.Principal, name, key, a.retained)
}

func (a *shareBusinessAudit) finish(ctx context.Context, in value.OperationIntent, operationErr error) {
	a.t.Helper()
	status, reason, effect := "success", "prepared", "accepted"
	if operationErr != nil {
		status, reason, effect = "unavailable", "not_available", "unknown"
	}
	body, _ := json.Marshal(struct{ Operation, Status string }{in.Name, status})
	digest, err := a.mac.Digest("mcp-result/v1", body)
	if err != nil {
		a.t.Fatal(err)
	}
	out := value.OperationOutcome{Intent: in, Status: status, Reason: reason, Effect: effect, ClientReceipt: "unknown", OutputDigest: digest, OutputBytes: int64(len(body)), MetadataUntil: in.RequestUntil, RecordedAt: time.Now().UTC().Truncate(time.Microsecond)}
	if err := a.gate.Finish(ctx, out); err != nil {
		a.t.Fatal("fixture ingress outcome", in.Name, err)
	}
}

type paidShareService struct {
	sharing.Service
	audit *shareBusinessAudit
}

func (s paidShareService) Create(ctx context.Context, current identities.CurrentIdentity, in sharing.CreateInput) (authorization.Share, bool, error) {
	op := s.audit.begin(ctx, current, "create_share", in.IdempotencyKey)
	in.OperationID = op.ID
	out, replay, err := s.Service.Create(ctx, current, in)
	s.audit.finish(ctx, op, err)
	return out, replay, err
}
func (s paidShareService) Revoke(ctx context.Context, current identities.CurrentIdentity, in sharing.RevokeInput) (authorization.Share, bool, error) {
	op := s.audit.begin(ctx, current, "revoke_share", in.IdempotencyKey)
	in.OperationID = op.ID
	out, replay, err := s.Service.Revoke(ctx, current, in)
	s.audit.finish(ctx, op, err)
	return out, replay, err
}
func (s paidShareService) Transfer(ctx context.Context, current identities.CurrentIdentity, in sharing.TransferInput) (authorization.Share, bool, error) {
	op := s.audit.begin(ctx, current, "transfer_share", in.IdempotencyKey)
	in.OperationID = op.ID
	out, replay, err := s.Service.Transfer(ctx, current, in)
	s.audit.finish(ctx, op, err)
	return out, replay, err
}
func (s paidShareService) RevokePolicySharing(ctx context.Context, current identities.CurrentIdentity, in sharing.PolicyRevokeInput) (sharing.PolicyRevokeResult, error) {
	op := s.audit.begin(ctx, current, "revoke_share", in.IdempotencyKey)
	in.OperationID = op.ID
	out, err := s.Service.RevokePolicySharing(ctx, current, in)
	s.audit.finish(ctx, op, err)
	return out, err
}
func (s paidShareService) StopPolicySharing(ctx context.Context, current identities.CurrentIdentity, in sharing.PolicyRevokeInput) (sharing.PolicyRevokeResult, error) {
	op := s.audit.begin(ctx, current, "stop_future_sharing", in.IdempotencyKey)
	in.OperationID = op.ID
	out, err := s.Service.StopPolicySharing(ctx, current, in)
	s.audit.finish(ctx, op, err)
	return out, err
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
	admissions, err := postgres.NewContextAdmissions(ctx, pool, s.a.RootID, s.recovery.installation, s.retention.guard)
	if err != nil {
		t.Fatal(err)
	}
	intents, err := postgres.NewCaptureIntents(ctx, pool, s.a.RootID)
	if err != nil {
		t.Fatal(err)
	}
	return shareCaptureAudit{intents, admissions, admissionRole}
}
