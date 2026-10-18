package postgres

import (
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	auditapp "asservat.local/asservat/internal/application/audit"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/identity"
)

func queryAuditFixture(t *testing.T) (custodydb.ReadContextQueryInvocationRow, value.ContextQueryCall) {
	t.Helper()
	const key = "8e3eeae7-0c1f-43f4-912e-fb408c02e7cb"
	n := time.Now().UTC().Truncate(time.Microsecond)
	in := audit.OperationIntent{ID: key, RootID: key, TraceID: key, Name: "get_query_result", InputFormat: "context-query-input/v1", MACVersion: "fixture-v1", AccountVersion: "fixture-v1", Actor: identity.Principal{Issuer: "https://fixture.invalid", Subject: "subject", ClientID: "client", Kind: identity.Human}, PrincipalDigest: artifact.Digest{1}, InputDigest: artifact.Digest{2}, CreatedAt: n, RequestUntil: n.Add(5 * time.Second), WriteUntil: n.Add(30 * time.Second), RetainUntil: n.Add(time.Hour)}
	p := audit.OperationLifecyclePolicy{RootID: key, InstallationID: key, StoreID: key, PolicyID: key, BackupProfileID: key, Lane: "normal", PolicyDigest: artifact.Digest{3}, BackupProfileDigest: artifact.Digest{4}, BackingRevision: 1, MetadataSlots: 1, MaxPurgeLeases: 2, CleanupBudgetSeconds: 1, ProofWindowSeconds: 1, ValidUntil: n.Add(time.Hour), History: &audit.OperationHistoryQualification{ID: key, Digest: artifact.Digest{5}, Layout: audit.OperationVerificationHistoryLayout, MaximumRowFootprintBytes: 128 << 10, MaximumTransitionWALBytes: 128 << 10, BackupCopies: 1, WALCopies: 1}}
	p.BackupReservedBytes, p.WALReservedBytes = p.History.SlotBacking(p.MaxPurgeLeases)
	var e error
	in, e = auditapp.BindOperationLifecycle(in, p)
	if e != nil {
		t.Fatal(e)
	}
	raw := func(v any) []byte {
		b, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	receipt := audit.Receipt{Key: audit.OperationAuditKey(key, key, "intent"), Version: "fixture-version", ETag: "fixture-etag", Bytes: 512, SHA256: artifact.Digest{8}}
	completion := audit.OperationWriteCompletion{Protocol: audit.OperationWriterProtocol, RootID: key, OperationID: key, StoreID: key, Phase: "intent", RecordDigest: auditapp.OperationLifecycleDigest(in), Receipt: receipt, StoredAt: n, ClosedAt: n}
	row := custodydb.ReadContextQueryInvocationRow{OperationAudit: custodydb.OperationAudit{ID: id(key), RootID: id(key), Lane: "normal", IssuerEpoch: id(key), PrincipalDigest: in.PrincipalDigest[:], Intent: raw(in), RequestUntil: ts(in.RequestUntil), WriteUntil: ts(in.WriteUntil), RetainUntil: ts(in.RetainUntil), IntentStarted: true, IntentReceipt: raw(receipt)}, OperationAuditLifecycle: custodydb.OperationAuditLifecycle{OperationID: id(key), RootID: id(key), Lane: "normal", PrincipalDigest: in.PrincipalDigest[:], InstallationID: id(key), IssuerEpoch: id(key), Binding: raw(in.Lifecycle), IntentCompletion: raw(completion)}}
	call := value.ContextQueryCall{ID: key, RootID: key, Tool: in.Name, InputFormat: in.InputFormat, MACVersion: in.MACVersion, InputDigest: in.InputDigest, PrincipalDigest: in.PrincipalDigest, Principal: in.Actor, StartedAt: n, Until: in.RequestUntil, WriteUntil: in.WriteUntil}
	return row, call
}
func TestContextQueryIntentRequiresExactHealthyCurrentInvocation(t *testing.T) {
	row, call := queryAuditFixture(t)
	if _, e := queryAuditSnapshot(row, call); e != nil {
		t.Fatal("exact fixture rejected", e)
	}
	for name, change := range map[string]func(*custodydb.ReadContextQueryInvocationRow, *value.ContextQueryCall){
		"other-client": func(_ *custodydb.ReadContextQueryInvocationRow, c *value.ContextQueryCall) {
			c.Principal.ClientID = "other"
		},
		"old-initial-tool": func(_ *custodydb.ReadContextQueryInvocationRow, c *value.ContextQueryCall) {
			c.Tool = "get_file_excerpt"
		},
		"other-input":          func(_ *custodydb.ReadContextQueryInvocationRow, c *value.ContextQueryCall) { c.InputDigest[0]++ },
		"other-principal-hmac": func(_ *custodydb.ReadContextQueryInvocationRow, c *value.ContextQueryCall) { c.PrincipalDigest[0]++ },
		"extended-request": func(_ *custodydb.ReadContextQueryInvocationRow, c *value.ContextQueryCall) {
			c.Until = c.Until.Add(time.Second)
		},
		"receipt-without-closure": func(r *custodydb.ReadContextQueryInvocationRow, _ *value.ContextQueryCall) {
			r.OperationAuditLifecycle.IntentCompletion = nil
		},
		"closure-without-ack": func(r *custodydb.ReadContextQueryInvocationRow, _ *value.ContextQueryCall) {
			r.OperationAudit.IntentReceipt = nil
		},
		"other-incarnation": func(r *custodydb.ReadContextQueryInvocationRow, _ *value.ContextQueryCall) {
			r.OperationAuditLifecycle.IssuerEpoch = id("73489d22-65a6-4fd9-9db4-7b2d90a40d83")
		},
		"other-record-digest": func(r *custodydb.ReadContextQueryInvocationRow, _ *value.ContextQueryCall) {
			var c audit.OperationWriteCompletion
			_ = json.Unmarshal(r.OperationAuditLifecycle.IntentCompletion, &c)
			c.RecordDigest[0]++
			r.OperationAuditLifecycle.IntentCompletion, _ = json.Marshal(c)
		},
		"retiring": func(r *custodydb.ReadContextQueryInvocationRow, _ *value.ContextQueryCall) {
			r.OperationAuditLifecycle.Retirement = []byte(`{}`)
		},
	} {
		t.Run(name, func(t *testing.T) {
			r, c := queryAuditFixture(t)
			change(&r, &c)
			if _, e := queryAuditSnapshot(r, c); e == nil {
				t.Fatal("invalid lineage accepted")
			}
		})
	}
}
