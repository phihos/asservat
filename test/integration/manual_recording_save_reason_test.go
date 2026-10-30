//go:build cgo && libpcap

package integration

import (
	"asservat.local/asservat/internal/adapters/jose"
	"asservat.local/asservat/internal/domain/artifact"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/application/capacity"
	captureapp "asservat.local/asservat/internal/application/capture"
	planningapp "asservat.local/asservat/internal/application/planning"
	auditvalue "asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
)

func TestManualRecordingSaveReasonWithRealServices(t *testing.T) {
	qualifySourceSnapshotServices(t, true, false, false, true)
}

// A separately selected short capture-audit profile, fixed before acceptance.
// Legacy tops retain10000s/H3600. Physical row/WAL and per-slot backing do not
// shrink: only this fixture's original lifetime/backup horizon is shorter.
func configureManualReasonCapacity(f *capacitySQLFixture) {
	in := &f.qualification.RootBacking
	in.AdmissionSeconds = 300
	in.Capture.RetainedSeconds = 180
	in.Capture.Policy.BackupHorizonSeconds = 5
	in.Capture.Policy.CleanupBudgetSeconds = 5
	in.Capture.Policy.ProofWindowSeconds = 5
}

func TestManualRecordingSaveReasonShortProfileCompiles(t *testing.T) {
	root, installation, cluster, control := custodyID(), custodyID(), custodyID(), custodyID()
	q, template := capacityNativeQualification(t, root, installation, cluster, control, "synthetic-reason-account")
	f := &capacitySQLFixture{qualification: q, template: template}
	configureManualSourceCapacity(f)
	configureManualReasonCapacity(f)
	plan, err := capacity.CompileProtectedPoolPlan(f.template, f.template.Pools[0].Budget.Name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = capacity.CompileQualifiedRootBacking(f.qualification, plan); err != nil {
		t.Fatal("short preaccepted profile invalid", err)
	}
	in := f.qualification.RootBacking
	if in.Capture.RetainedSeconds <= 2*in.Capture.Policy.BackupHorizonSeconds+3*in.Capture.Policy.CleanupBudgetSeconds+in.Capture.Policy.ProofWindowSeconds+30 {
		t.Fatal("profile cannot contain original writer interval")
	}
}

type reasonFixtureIdentity struct{ who identity.Identity }

func (i reasonFixtureIdentity) ResolveIdentity(ctx context.Context) (identity.Identity, error) {
	return i.who, ctx.Err()
}

type reasonFixtureCipher struct {
	auditapp.CaptureReasonCipher
	opens atomic.Int64
}

func (c *reasonFixtureCipher) OpenCaptureReason(ctx context.Context, b auditapp.CaptureReasonBinding, e auditvalue.CaptureReasonEnvelope) (string, error) {
	c.opens.Add(1)
	return c.CaptureReasonCipher.OpenCaptureReason(ctx, b, e)
}

// Maximum-width opaque provider representation only. The real fixture wrapper
// still seals/opens the actual Tink key with the exact same AD; random bytes
// avoid compressible slash padding. This is not a remote-provider measurement.
type reasonMaximumWrap struct {
	seals, opens        atomic.Int64
	base                authorityTestKeys
	actual, represented artifact.SealedKey
}

func (k *reasonMaximumWrap) Seal(ctx context.Context, plain, ad []byte) (artifact.SealedKey, error) {
	k.seals.Add(1)
	actual, err := k.base.Seal(ctx, plain, ad)
	if err != nil {
		return artifact.SealedKey{}, err
	}
	ref, wrap := make([]byte, 192), make([]byte, 6144)
	if _, err = rand.Read(ref); err != nil {
		return artifact.SealedKey{}, err
	}
	if _, err = rand.Read(wrap); err != nil {
		return artifact.SealedKey{}, err
	}
	k.actual = actual
	k.represented = artifact.SealedKey{Reference: base64.StdEncoding.EncodeToString(ref), Ciphertext: base64.StdEncoding.EncodeToString(wrap)}
	return k.represented, nil
}
func (k *reasonMaximumWrap) Open(ctx context.Context, sealed artifact.SealedKey, ad []byte) ([]byte, error) {
	k.opens.Add(1)
	if sealed != k.represented {
		return nil, artifact.ErrIntegrity
	}
	return k.base.Open(ctx, k.actual, ad)
}

// Length-only observation of the existing real outer wrapping calls.
type reasonOuterKeys struct {
	base    authorityTestKeys
	lengths []int
}

func (k *reasonOuterKeys) Seal(ctx context.Context, plain, ad []byte) (artifact.SealedKey, error) {
	v, err := k.base.Seal(ctx, plain, ad)
	if err == nil {
		k.lengths = append(k.lengths, len(v.Ciphertext))
	}
	return v, err
}
func (k *reasonOuterKeys) Open(ctx context.Context, v artifact.SealedKey, ad []byte) ([]byte, error) {
	return k.base.Open(ctx, v, ad)
}

func qualifyManualRecordingSaveReason(t *testing.T, ctx context.Context, f *capacitySQLFixture, admissions *postgres.ContextAdmissions, policy policySourceAcceptedFixture, source captureapp.PolicySourceAdmission, fresh captureapp.PolicySourceCheck, intents auditapp.CaptureOperationPublication) {
	t.Helper()
	before := readManualSaveCounters(t, ctx, f, policy)
	snapshot := prepareManualRecordingSaveFixture(t, ctx, f.roles["hub-runtime"], policy, source, fresh, 64<<10)
	a, p := snapshot.Admission, snapshot.Preview
	scope := bytes.Clone(p.CanonicalScope)
	scopeDigest := p.ScopeDigest
	maximumKeys := &reasonMaximumWrap{base: f.keys}
	cipher, err := objectstore.NewCaptureReasonCipher(maximumKeys, maximumKeys)
	if err != nil {
		t.Fatal(err)
	}
	//512 Unicode scalars, including whitespace/newline which must not normalize.
	reason := " \n\t" + strings.Repeat("🙂", 509)
	envelope, err := cipher.SealCaptureReason(ctx, auditapp.CaptureReasonBinding{RootID: p.RootID, CaptureID: p.CaptureID, Requester: p.Actor, ScopeDigest: p.ScopeDigest}, reason)
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := auditapp.EncodeCaptureReasonEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	p.Intent.Reason = &value.ProtectedReasonRef{ID: p.ID, CiphertextDigest: sha256.Sum256(opaque)}
	p.ReasonEnvelope = opaque
	// A tighter passive review lifetime permits real expiry cleanup before the
	// mandatory audit, while acquisition keeps its original accepted cutoffs.
	p.SelectionUntil = p.CreatedAt.Add(time.Second)
	if !captureapp.ValidContextPreview(p) || !bytes.Equal(p.CanonicalScope, scope) || p.ScopeDigest != scopeDigest {
		t.Fatal("reason changed reviewed collection scope")
	}
	previews, err := postgres.NewContextPreviews(ctx, f.roles["hub-runtime"], a.RootID)
	if err != nil {
		t.Fatal(err)
	}
	if err = previews.CreateContextPreview(ctx, p); err != nil {
		t.Fatal("real reason preview", err)
	}
	var blueprint, storedOpaque []byte
	if err = f.admin.QueryRow(ctx, `SELECT blueprint_json,reason_envelope FROM context_preview WHERE root_id=$1 AND id=$2`, a.RootID, p.ID).Scan(&blueprint, &storedOpaque); err != nil || !bytes.Equal(storedOpaque, opaque) || bytes.Contains(blueprint, []byte("ReasonEnvelope")) {
		t.Fatal("preview did not separate opaque erasable body", err)
	}
	var relationBefore int64
	if err = f.admin.QueryRow(ctx, `SELECT pg_total_relation_size('operation_audit')`).Scan(&relationBefore); err != nil {
		t.Fatal(err)
	}
	var walBefore, walAfter string
	if err = f.admin.QueryRow(ctx, `SELECT pg_current_wal_insert_lsn()::text`).Scan(&walBefore); err != nil {
		t.Fatal(err)
	}
	began := time.Now()
	accepted, err := admissions.AdmitReviewedContext(ctx, p.ID, a)
	if err != nil {
		t.Fatal("actual reason admission", err)
	}
	if err = f.admin.QueryRow(ctx, `SELECT pg_current_wal_insert_lsn()::text`).Scan(&walAfter); err != nil {
		t.Fatal(err)
	}
	var wal, tuple, intentBytes, outcomeBytes, relation int64
	if err = f.admin.QueryRow(ctx, `SELECT pg_wal_lsn_diff($1::pg_lsn,$2::pg_lsn)::bigint`, walAfter, walBefore).Scan(&wal); err != nil {
		t.Fatal(err)
	}
	if err = f.admin.QueryRow(ctx, `SELECT pg_column_size(a),octet_length(a.intent::text),COALESCE(octet_length(a.outcome::text),0),pg_total_relation_size('operation_audit') FROM operation_audit a WHERE root_id=$1 AND id=$2`, a.RootID, accepted.CaptureID).Scan(&tuple, &intentBytes, &outcomeBytes, &relation); err != nil {
		t.Fatal(err)
	}
	t.Logf("reason admission actual_ms=%d global_fixture_wal_delta=%d operation_row_pg_column_size=%d intent_jsonb_text=%d outcome=%d full_relation_bytes=%d relation_delta=%d; actual underlying synthetic-local-key wrap=%d; random maximum8192 innerrepresentation selected (not remote-provider qualification)", time.Since(began).Milliseconds(), wal, tuple, intentBytes, outcomeBytes, relation, relation-relationBefore, len(maximumKeys.actual.Ciphertext))
	// pg_column_size and full-relation page deltas are actual observations,
	// not a per-row heap/TOAST/index/backup attribution or all-shape proof.
	if intentBytes > 32<<10 {
		t.Fatal("closed reason intent serialization bound exceeded", intentBytes)
	}
	var bodyNull bool
	var afterBlueprint []byte
	if err = f.admin.QueryRow(ctx, `SELECT reason_envelope IS NULL,blueprint_json FROM context_preview WHERE root_id=$1 AND id=$2`, a.RootID, p.ID).Scan(&bodyNull, &afterBlueprint); err != nil || !bodyNull || !bytes.Equal(afterBlueprint, blueprint) {
		t.Fatal("atomic copy did not erase only body", err)
	}
	// Failed mutations run in their own implicit transactions and preserve the
	// immutable ref/blueprint independently of body erasure.
	if _, err = f.admin.Exec(ctx, `UPDATE context_capture SET reason_ref=jsonb_set(reason_ref,'{ID}',to_jsonb($3::text)) WHERE root_id=$1 AND id=$2`, a.RootID, accepted.CaptureID, custodyID()); capacitySQLState(err) != "23514" {
		t.Fatal("accepted reason ref mutable", err)
	}
	if _, err = f.admin.Exec(ctx, `UPDATE context_preview SET blueprint_json=convert_to(jsonb_set(convert_from(blueprint_json,'UTF8')::jsonb,'{Intent,Reason,ID}',to_jsonb($3::text))::text,'UTF8') WHERE root_id=$1 AND id=$2`, a.RootID, p.ID, custodyID()); capacitySQLState(err) != "23514" {
		t.Fatal("preview reason ref mutable", err)
	}
	after := readManualSaveCounters(t, ctx, f, policy)
	if after.Executions != before.Executions+1 || after.Reservations != before.Reservations+1 || after.Observed != before.Observed || after.Shares != before.Shares {
		t.Fatal("descriptive reason changed resource/grant units")
	}
	snapshot.Accepted = accepted
	snapshot.Admission.Plan, snapshot.Admission.Registration, err = planningapp.ReanchorRecordingSave(a.Plan, a.Registration, accepted.CreatedAt, policy.Authority.NotAfter)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Preview = p
	draft, err := captureapp.HistoryDraftFromPreview(p, accepted)
	if err != nil || draft.RecordingSave == nil {
		t.Fatal("reason-free fresh-selection repeat settings", err)
	}
	draftBytes, err := json.Marshal(draft)
	if err != nil || bytes.Contains(draftBytes, []byte("Reason")) || bytes.Contains(draftBytes, []byte(reason)) || bytes.Contains(draftBytes, opaque) {
		t.Fatal("repeat restored reason or opaque envelope", err)
	}
	// Independent record owns the envelope before the expired passive row is deleted.
	wait := time.Until(p.SelectionUntil.Add(time.Millisecond))
	if wait > 0 {
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			t.Fatal(ctx.Err())
		case <-timer.C:
		}
	}
	cleanup, err := postgres.NewContextPreviewCleanup(ctx, f.roles["hub-runtime"], a.RootID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = cleanup.DeleteExpiredContextPreviews(ctx); err != nil {
		t.Fatal("real expired preview deletion", err)
	}
	var left int
	if err = f.admin.QueryRow(ctx, `SELECT count(*) FROM context_preview WHERE root_id=$1 AND id=$2`, a.RootID, p.ID).Scan(&left); err != nil || left != 0 {
		t.Fatal("expired preview retained", left, err)
	}
	pending, err := intents.Journal.ReadCaptureOperation(ctx, accepted.CaptureID)
	if err != nil || pending.Intent.Lifecycle == nil {
		t.Fatal("original audit configuration", err)
	}
	outerKeys := &reasonOuterKeys{base: f.keys}
	writer, err := objectstore.NewClosedOperationAuditObjects(f.store, pending.Intent.Lifecycle.Policy.StoreID, outerKeys, outerKeys)
	if err != nil {
		t.Fatal(err)
	}
	intents.Writer = writer
	var auditWALBefore, auditWALAfter string
	if err = f.admin.QueryRow(ctx, `SELECT pg_current_wal_insert_lsn()::text`).Scan(&auditWALBefore); err != nil {
		t.Fatal(err)
	}
	auditBegan := time.Now()
	if _, err = intents.AcknowledgedCaptureIntent(ctx, accepted.CaptureID); err != nil {
		t.Fatal("joined reason pair after expired preview DELETE", err)
	}
	if err = f.admin.QueryRow(ctx, `SELECT pg_current_wal_insert_lsn()::text`).Scan(&auditWALAfter); err != nil {
		t.Fatal(err)
	}
	if err = f.admin.QueryRow(ctx, `SELECT pg_wal_lsn_diff($1::pg_lsn,$2::pg_lsn)::bigint`, auditWALAfter, auditWALBefore).Scan(&wal); err != nil {
		t.Fatal(err)
	}
	t.Logf("mandatory reason audit pair actual_ms=%d global_fixture_wal_delta=%d; existing fleet observations may contribute", time.Since(auditBegan).Milliseconds(), wal)
	t.Run("opaque-pair-native-after-preview-deletion", func(t *testing.T) { qualifySourceSnapshotCompletion(t, ctx, f, policy, snapshot, intents) })
	snap, err := intents.Journal.ReadCaptureOperation(ctx, accepted.CaptureID)
	if err != nil || snap.Outcome == nil || snap.Intent.ReasonEnvelope == nil || snap.Outcome.Intent.ReasonEnvelope == nil || snap.IntentReceipt == nil || snap.OutcomeReceipt == nil {
		t.Fatal("mandatory opaque pair incomplete", err)
	}
	intentOpaque, _ := auditapp.EncodeCaptureReasonEnvelope(*snap.Intent.ReasonEnvelope)
	outcomeOpaque, _ := auditapp.EncodeCaptureReasonEnvelope(*snap.Outcome.Intent.ReasonEnvelope)
	intentFrame, err := auditapp.EncodeCaptureOperationIntent(snap.Intent)
	if err != nil {
		t.Fatal(err)
	}
	outcomeFrame, err := auditapp.EncodeCaptureOperationOutcome(*snap.Outcome)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Intent.InputFormat != auditvalue.CaptureReasonInputFormat || len(intentFrame) > 32<<10 || len(outcomeFrame) > 32<<10 || len(outerKeys.lengths) != 2 {
		t.Fatal("closed reason branch/outer key operation changed")
	}
	t.Logf("exact reason frames intent=%d outcome=%d receipts=%d/%d; inner actual_wrap=%d TESTopaque_repr=%d, outer actual_wrap_lengths=%v; >legacy16KiBintent=%t usesnew32KiBformat", len(intentFrame), len(outcomeFrame), snap.IntentReceipt.Bytes, snap.OutcomeReceipt.Bytes, len(maximumKeys.actual.Ciphertext), len(envelope.WrappedKey), outerKeys.lengths, len(intentFrame) > 16<<10)
	if !bytes.Equal(intentOpaque, opaque) || !bytes.Equal(outcomeOpaque, opaque) || snap.Intent.Capture.ReasonRef == nil || *snap.Intent.Capture.ReasonRef != (auditvalue.CaptureReasonRef{ID: p.ID, CiphertextDigest: p.Intent.Reason.CiphertextDigest}) {
		t.Fatal("audit phases changed exact encrypted reason")
	}
	if err = f.admin.QueryRow(ctx, `SELECT pg_column_size(a),octet_length(a.intent::text),octet_length(a.outcome::text),pg_total_relation_size('operation_audit') FROM operation_audit a WHERE root_id=$1 AND id=$2`, a.RootID, accepted.CaptureID).Scan(&tuple, &intentBytes, &outcomeBytes, &relation); err != nil {
		t.Fatal(err)
	}
	t.Logf("reason joined pair actual operation_row_pg_column_size=%d intent_jsonb_text=%d outcome_jsonb_text=%d full_relation_bytes=%d; original fullrow backing128KiB/WAL256KiB are configuredlimits, not per-row attribution", tuple, intentBytes, outcomeBytes, relation)
	if intentBytes > 32<<10 || outcomeBytes > 32<<10 || snap.IntentReceipt.Bytes > 64<<10 || snap.OutcomeReceipt.Bytes > 64<<10 {
		t.Fatal("reason pair exceeded unchanged serialized/object bounds")
	}
	f.refreshBase(t)
	replayIdentity := snapshot.Admission.RecordingSave.Initiator.VerifiedIdentity
	replayIdentity.VerifiedAt = time.Now().UTC().Truncate(time.Microsecond)
	replayIdentity.ValidUntil = replayIdentity.VerifiedAt.Add(5 * time.Second)
	replayRecovery, err := policy.Scenario.recovery.reader.RecoveryState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	replay, found, err := admissions.LookupContextAdmission(ctx, value.ReplayQuery{RootID: a.RootID, PreviewID: p.ID, IdempotencyKey: a.IdempotencyKey, SubmissionDigest: a.SubmissionDigest, Identity: replayIdentity, Recovery: replayRecovery})
	if err != nil || !found || replay.CaptureID != accepted.CaptureID || !replay.CreatedAt.Equal(accepted.CreatedAt) || readManualSaveCounters(t, ctx, f, policy) != after {
		t.Fatal("accepted replay depended on expired preview or changed spend", err)
	}
	if maximumKeys.seals.Load() != 1 || maximumKeys.opens.Load() != 0 {
		t.Fatal("opaque admission/audit/replay added reason key operations", maximumKeys.seals.Load(), maximumKeys.opens.Load())
	}
	qualifyReasonProgress(t, ctx, f, policy, snapshot, intents, cipher, reason)
	t.Run("populated110-down-refusal", func(t *testing.T) {
		provider, closeProvider := source107MigrationProvider(t, f.admin)
		defer closeProvider()
		if _, err := provider.DownTo(ctx, 109); capacitySQLState(err) != "P0001" {
			t.Fatal("reason downgrade was not restrictive", err)
		}
		if version, err := provider.GetDBVersion(ctx); err != nil || version != 110 {
			t.Fatal("reason refusal partially changed schema", version, err)
		}
	})
}

// Waits against actual UTC while maintaining the fixture's existing source
// observations. It never edits original audit, source or capacity deadlines.
func waitReasonFixtureUntil(t *testing.T, ctx context.Context, f *capacitySQLFixture, until time.Time) {
	t.Helper()
	for time.Now().Before(until) {
		wait := min(time.Second, time.Until(until))
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			t.Fatal(ctx.Err())
		case <-timer.C:
		}
		f.refreshBase(t)
	}
}

func qualifyReasonProgress(t *testing.T, ctx context.Context, f *capacitySQLFixture, policy policySourceAcceptedFixture, snapshot policySourceSnapshotAdmissionFixture, intents auditapp.CaptureOperationPublication, cipher auditapp.CaptureReasonCipher, reason string) {
	t.Helper()
	root := snapshot.Admission.RootID
	reader, err := postgres.NewContextProgressReads(ctx, f.roles["hub-runtime"], root, policy.Scenario.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	records, ok := intents.Journal.(captureapp.CaptureReasonRecords)
	if !ok {
		t.Fatal("real audit journal lacks bounded descriptive read")
	}
	counted := &reasonFixtureCipher{CaptureReasonCipher: cipher}
	service := captureapp.ContextProgressService{RootID: root, InstallationID: policy.Authority.InstallationID, Reader: reader, Recovery: policy.Scenario.recovery.reader, Reasons: captureapp.StoredCaptureReasons{Records: records, Cipher: counted}, Now: time.Now}
	current := func() reasonFixtureIdentity {
		f.refreshBase(t)
		who := snapshot.Admission.RecordingSave.Initiator.VerifiedIdentity
		who.VerifiedAt = time.Now().UTC().Truncate(time.Microsecond)
		who.ValidUntil = who.VerifiedAt.Add(5 * time.Second)
		return reasonFixtureIdentity{who}
	}
	if !t.Run("current-authorized-parent-metadata-one-unwrap", func(t *testing.T) {
		before := counted.opens.Load()
		p, err := service.Get(ctx, current(), snapshot.Accepted.CaptureID)
		if err != nil || p.Reason == nil || *p.Reason != reason || p.ReasonState != "available" || counted.opens.Load() != before+1 {
			t.Fatal("authorized reason lost/current unwrap count", p.ReasonState, err)
		}
		denied := current()
		denied.who.Groups = []string{"no-current-workload-rights"}
		before = counted.opens.Load()
		if _, err = service.Get(ctx, denied, snapshot.Accepted.CaptureID); err == nil || counted.opens.Load() != before {
			t.Fatal("denied status opened descriptive reason")
		}
	}) {
		return
	}
	if !t.Run("descriptive-read-after-original-write-cutoff", func(t *testing.T) {
		var original time.Time
		if err = f.admin.QueryRow(ctx, `SELECT write_until FROM operation_audit WHERE root_id=$1 AND id=$2`, root, snapshot.Accepted.CaptureID).Scan(&original); err != nil {
			t.Fatal(err)
		}
		waitReasonFixtureUntil(t, ctx, f, original.Add(time.Millisecond))
		p, err := service.Get(ctx, current(), snapshot.Accepted.CaptureID)
		if err != nil || p.Reason == nil || *p.Reason != reason || p.ReasonState != "available" {
			t.Fatal("descriptive read inherited old writer authority cutoff", p.ReasonState, err)
		}
	}) {
		return
	}
	qualifyReasonAuditRetirement(t, ctx, f, policy, snapshot, intents, service, current)
}

func qualifyReasonAuditRetirement(t *testing.T, ctx context.Context, f *capacitySQLFixture, policy policySourceAcceptedFixture, snapshot policySourceSnapshotAdmissionFixture, intents auditapp.CaptureOperationPublication, progress captureapp.ContextProgressService, current func() reasonFixtureIdentity) {
	t.Helper()
	root, capture := snapshot.Admission.RootID, snapshot.Accepted.CaptureID
	// Read immutable lifecycle facts before the original writer deadline closes.
	var in auditvalue.OperationIntent
	var raw []byte
	if err := f.admin.QueryRow(ctx, `SELECT intent FROM operation_audit WHERE root_id=$1 AND id=$2`, root, capture).Scan(&raw); err != nil || json.Unmarshal(raw, &in) != nil || in.Lifecycle == nil {
		t.Fatal("original lifecycle binding", err)
	}
	life := func(purpose string) *postgres.OperationLifecycles {
		v, err := postgres.NewCaptureOperationLifecycles(ctx, f.roles[purpose], in.Lifecycle.Policy, policy.Scenario.recovery.guard)
		if err != nil {
			t.Fatal(purpose, err)
		}
		return v
	}
	cleanup, verify, finalize := life("capture-cleanup"), life("capture-verifier"), life("capture-finalizer")
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewOperationRetirementSignatures(root, "synthetic-reason-retirement", private, map[string]ed25519.PublicKey{"synthetic-reason-retirement": pub})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := jose.NewOperationRetirementSignatures(root, "", nil, map[string]ed25519.PublicKey{"synthetic-reason-retirement": pub})
	if err != nil {
		t.Fatal(err)
	}
	objects, err := objectstore.NewOperationAuditCleanupObjects(f.store, in.Lifecycle.Policy.StoreID, f.keys, f.keys, signer, verifier)
	if err != nil {
		t.Fatal(err)
	}
	independent, err := objectstore.NewOperationAuditCleanupVerifier(f.store, in.Lifecycle.Policy.StoreID, f.keys, verifier)
	if err != nil {
		t.Fatal(err)
	}
	driver := auditapp.OperationCleanup{Journal: cleanup, Acknowledgements: verify, Finalizer: finalize, Objects: objects, Verifier: independent}
	t.Run("actual-short-profile-original-and-terminal-retirement", func(t *testing.T) {
		t.Logf("separately preaccepted capture audit Retain180/H5/Cleanup5/Proof5/Admission300: originalPurge=%s certificatePurge=%s liveRetire=%s; clocks unchanged", in.Lifecycle.OriginalPurgeAt, in.Lifecycle.CertificatePurgeAt, in.Lifecycle.LiveRetireBy)
		waitReasonFixtureUntil(t, ctx, f, in.Lifecycle.OriginalPurgeAt.Add(time.Millisecond))
		// First advance must create and independently verify the real encrypted
		// retirement certificate. Terminal purge is not due yet.
		_ = driver.Advance(ctx, capture)
		state, err := cleanup.ReadOperationLifecycle(ctx, capture)
		if err != nil || state.Retirement == nil || state.CertificateReceipt == nil {
			t.Fatal("original pair did not join real retirement", err)
		}
		waitReasonFixtureUntil(t, ctx, f, state.Retirement.CertificatePurgeAt.Add(time.Millisecond))
		if err = driver.Advance(ctx, capture); err != nil {
			t.Fatal("terminal retirement", err)
		}
		var count int
		if err = f.admin.QueryRow(ctx, `SELECT count(*) FROM operation_audit WHERE root_id=$1 AND id=$2`, root, capture).Scan(&count); err != nil || count != 0 {
			t.Fatal("opaque reason journal did not retire", count, err)
		}
		p, err := progress.Get(ctx, current(), capture)
		if err != nil || p.Reason != nil || p.ReasonState != "unavailable" || p.Phase == "" {
			t.Fatal("retired descriptive reason blocked normal status", p.ReasonState, p.Phase, err)
		}
	})
	_ = intents
}
