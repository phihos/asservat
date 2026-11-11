package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/application/sharing"
	value "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
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
	var encoded []byte
	var retained int64
	if err := hub.QueryRow(ctx, `SELECT l.binding->'Policy',p.retained_seconds FROM operation_audit_lifecycle l JOIN operation_audit_pool p USING(root_id,lane) WHERE l.root_id=$1 AND l.lane='normal' ORDER BY l.operation_id LIMIT 1`, s.a.RootID).Scan(&encoded, &retained); err != nil {
		t.Fatal("original share audit cohort", err)
	}
	var policy value.OperationLifecyclePolicy
	if json.Unmarshal(encoded, &policy) != nil || policy.History == nil || policy.History.Layout != value.ShareOperationHistoryLayout {
		t.Fatal("share fixture must select original qualified cohort before first audit")
	}
	journal, err := postgres.NewHealthyOperationJournal(ctx, hub, policy, s.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	acks, err := postgres.NewOperationAcknowledgements(ctx, hub, s.a.RootID, "normal", s.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	completions, err := postgres.NewOperationLifecycles(ctx, hub, s.a.RootID, "normal", s.recovery.guard)
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
	// Exact existing synthetic MAC material of newProcessingTestFixture.
	mac, err := auditapp.NewOperationMAC("input-v1", bytes.Repeat([]byte{31}, 32), "accounts-v1", bytes.Repeat([]byte{32}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mac.Close)
	return &shareBusinessAudit{t, gate, mac, policy, retained}
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

// The protected pins/qualification/MAC and provider credentials remain explicit
// synthetic fixture inputs. Admission, immutable pair, positive writer closure,
// independent acknowledgements and publication use the current real components.
type shareCaptureAudit struct {
	publication   auditapp.CaptureOperationPublication
	admissions    *postgres.ContextAdmissions
	mac           *auditapp.OperationMAC
	admissionRole string
}

func newShareCaptureAudit(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, s captureAdmissionScenario) shareCaptureAudit {
	t.Helper()
	roles := map[string]*pgxpool.Pool{}
	admissionRole := narrowRole(t, ctx, admin, "share_capture_admit_", "synthetic-share-capture-admit", func(role string) []string {
		grants, ok := postgres.PublicRuntimeRoleGrantSQL("capture-admit", role)
		if !ok {
			t.Fatal("compiled policy-aware capture admission role")
		}
		return grants
	})
	for _, purpose := range []string{"source", "admit", "journal", "ack", "read"} {
		if purpose == "admit" {
			roles[purpose] = poolFor(admissionRole, "synthetic-share-capture-admit")
		} else {
			roles[purpose] = poolFor("capture_operation_"+purpose+"_runtime", "synthetic-capture-operation-"+purpose)
		}
		t.Cleanup(roles[purpose].Close)
	}
	defer roles["source"].Close()
	config, err := postgres.New(ctx, roles["source"])
	if err != nil {
		t.Fatal(err)
	}
	mac, err := auditapp.NewOperationMAC("capture-input-v1", bytes.Repeat([]byte{41}, 32), "capture-accounts-v1", bytes.Repeat([]byte{42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mac.Close)
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err = admin.Exec(ctx, `INSERT INTO capture_audit_root(root_id,installation_id,source_role,admission_role,journal_role,acknowledge_role,cleanup_role,verifier_role,finalizer_role,reader_role,revision,paused,valid_until) VALUES($1,$2,'capture_operation_source_runtime'::regrole::oid,$4::regrole::oid,'capture_operation_journal_runtime'::regrole::oid,'capture_operation_ack_runtime'::regrole::oid,'capture_operation_cleanup_runtime'::regrole::oid,'capture_operation_verify_runtime'::regrole::oid,'capture_operation_retire_runtime'::regrole::oid,'capture_operation_read_runtime'::regrole::oid,1,false,$3)`, s.a.RootID, s.recovery.installation, now.Add(time.Hour), admissionRole); err != nil {
		t.Fatal("original synthetic protected capture pins", err)
	}
	account := nativeContinuationAuditAccount(t, s.a.RootID, s.recovery.installation, s.a.Registration.AllocationID, now, mac)
	if err = admin.QueryRow(ctx, `SELECT full_limit FROM context_control_account WHERE root_id=$1 AND allocation_id=$2`, s.a.RootID, s.a.Registration.AllocationID).Scan(&account.Records); err != nil {
		t.Fatal("original control record coverage", err)
	}
	account.RetainedSeconds = 7200
	account.Policy.MetadataSlots = 2 * account.Records
	account.Policy.History.Layout = value.ShareCaptureOperationHistoryLayout
	backup, wal := account.Policy.History.SlotBacking(account.Policy.MaxPurgeLeases)
	account.Policy.BackupReservedBytes, account.Policy.WALReservedBytes = backup*account.Policy.MetadataSlots, wal*account.Policy.MetadataSlots
	policy := account.Policy
	backing := auditapp.OperationAuditPool{RootID: s.a.RootID, Lane: "capture", AccountVersion: account.AccountVersion, Accounts: 2, RecordsPerAccount: account.Records, RetainedSeconds: account.RetainedSeconds, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), ValidUntil: now.Add(time.Hour)}
	if err = config.ConfigureCaptureAuditBacking(ctx, postgres.CaptureAuditBacking{Pool: backing, Account: account, ValidUntil: backing.ValidUntil}, mac); err != nil {
		t.Fatal("original share-qualified capture cohort", err)
	}
	admissions, err := postgres.NewAuditedContextAdmissions(ctx, roles["admit"], s.a.RootID, mac, postgres.EffectTransactionGuards{Retention: s.retention.guard, Recovery: s.recovery.guard})
	if err != nil {
		t.Fatal(err)
	}
	journal, err := postgres.NewCaptureAuditJournal(ctx, roles["journal"], policy)
	if err != nil {
		t.Fatal(err)
	}
	acks, err := postgres.NewCaptureAuditAcknowledgements(ctx, roles["ack"], policy)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := objectstore.NewClosedOperationAuditObjects(store, policy.StoreID, keys, keys)
	if err != nil {
		t.Fatal(err)
	}
	completed, err := postgres.NewCaptureOperationIntents(ctx, roles["read"], s.a.RootID)
	if err != nil {
		t.Fatal(err)
	}
	return shareCaptureAudit{auditapp.CaptureOperationPublication{RootID: s.a.RootID, Completed: completed, Journal: journal, Acknowledgements: acks, Writer: writer, Reader: &objectstore.OperationAuditObjects{Store: store, Seal: keys, Open: keys}, MAC: mac, Now: time.Now}, admissions, mac, admissionRole}
}
