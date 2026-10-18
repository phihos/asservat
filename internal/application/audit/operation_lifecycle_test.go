package audit

import (
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/audit"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func healthyPolicy(in value.OperationIntent) value.OperationLifecyclePolicy {
	p := value.OperationLifecyclePolicy{RootID: in.RootID, Lane: value.OperationLane(in.Name), InstallationID: in.RootID, StoreID: in.RootID, PolicyID: in.RootID, BackupProfileID: in.RootID, PolicyDigest: artifact.Digest{1}, BackupProfileDigest: artifact.Digest{2}, BackingRevision: 1, MetadataSlots: 10, MaxPurgeLeases: 16, CleanupBudgetSeconds: 10, ProofWindowSeconds: 60, ValidUntil: in.CreatedAt.Add(time.Hour)}
	p.History = &value.OperationHistoryQualification{ID: in.RootID, Digest: artifact.Digest{4}, Layout: value.OperationVerificationHistoryLayout, MaximumRowFootprintBytes: 128 << 10, MaximumTransitionWALBytes: 128 << 10, BackupCopies: 2, WALCopies: 2}
	b, w := p.History.SlotBacking(p.MaxPurgeLeases)
	p.BackupReservedBytes, p.WALReservedBytes = b*p.MetadataSlots, w*p.MetadataSlots
	return p
}

type healthyFixture struct {
	*operationFixture
	saved             map[string]value.OperationWriteCompletion
	writes            int
	lose, losePersist bool
}

func (f *healthyFixture) RecordOperationCompletion(_ context.Context, _ value.OperationIntent, phase string, c value.OperationWriteCompletion) error {
	if f.saved == nil {
		f.saved = map[string]value.OperationWriteCompletion{}
	}
	f.saved[phase] = c
	if f.losePersist {
		return ErrUnavailable
	}
	return nil
}
func (f *healthyFixture) ReadOperationCompletion(_ context.Context, _ value.OperationIntent, phase string) (value.OperationWriteCompletion, error) {
	c, ok := f.saved[phase]
	if !ok {
		return c, ErrUnavailable
	}
	return c, nil
}
func (f *healthyFixture) complete(in value.OperationIntent, phase string, v any) (value.OperationWriteCompletion, error) {
	f.writes++
	f.creates++
	if f.lose {
		return value.OperationWriteCompletion{}, ErrUnavailable
	}
	return value.OperationWriteCompletion{Protocol: value.OperationWriterProtocol, RootID: in.RootID, OperationID: in.ID, StoreID: in.Lifecycle.Policy.StoreID, Phase: phase, RecordDigest: OperationLifecycleDigest(v), Receipt: receipt(in, phase), StoredAt: in.CreatedAt, ClosedAt: in.CreatedAt}, nil
}
func (f *healthyFixture) CreateClosedOperationIntent(_ context.Context, in value.OperationIntent) (value.OperationWriteCompletion, error) {
	return f.complete(in, "intent", in)
}
func (f *healthyFixture) CreateClosedOperationOutcome(_ context.Context, out value.OperationOutcome) (value.OperationWriteCompletion, error) {
	return f.complete(out.Intent, "outcome", out)
}
func TestHealthyAuditFindNeverManufacturesClosure(t *testing.T) {
	for _, mode := range []string{"unknown-put", "unknown-completion-commit", "unknown-claim"} {
		t.Run(mode, func(t *testing.T) {
			in := auditIntent()
			f := &healthyFixture{operationFixture: &operationFixture{}, lose: mode == "unknown-put", losePersist: mode == "unknown-completion-commit"}
			f.lostClaim = mode == "unknown-claim"
			gate, e := NewHealthyOperationAuditor(healthyPolicy(in), f, f, f, f, f, func() time.Time { return in.CreatedAt })
			if e != nil {
				t.Fatal(e)
			}
			if e = gate.Begin(context.Background(), in); !errors.Is(e, ErrUnavailable) {
				t.Fatal("unknown write succeeded", e)
			}
			f.lose = false
			f.losePersist = false
			e = gate.Begin(context.Background(), in)
			if mode == "unknown-completion-commit" {
				if e != nil || f.writes != 1 || f.finds != 1 {
					t.Fatal("exact durable completion did not recover", e, f)
				}
			} else if !errors.Is(e, ErrUnavailable) || f.finds != 0 || f.writes > 1 || f.acks != 0 {
				t.Fatal("historical GET invented quiescence", e, f)
			}
		})
	}
}
func TestHealthyAuditBindingDoesNotReanchorFinish(t *testing.T) {
	in := auditIntent()
	p := healthyPolicy(in)
	f := &healthyFixture{operationFixture: &operationFixture{}}
	now := in.CreatedAt
	gate, e := NewHealthyOperationAuditor(p, f, f, f, f, f, func() time.Time { return now })
	if e != nil {
		t.Fatal(e)
	}
	if e = gate.Begin(context.Background(), in); e != nil {
		t.Fatal(e)
	}
	frozen := *f.snap.Intent.Lifecycle
	now = now.Add(2 * time.Second)
	p.ProofWindowSeconds++
	out := auditOutcome(in)
	if e = gate.Finish(context.Background(), out); e != nil {
		t.Fatal(e)
	}
	if !sameOperationRecord(frozen, *f.snap.Outcome.Intent.Lifecycle) {
		t.Fatal("finish moved the original dates")
	}
	changed := out
	other := frozen
	other.Policy.ProofWindowSeconds++
	changed.Intent.Lifecycle = &other
	if !errors.Is(gate.Finish(context.Background(), changed), ErrUnavailable) {
		t.Fatal("caller replaced the accepted binding")
	}
}
func TestHealthyAuditDatesIncludeBackupsAndLegacyJSONIsUnchanged(t *testing.T) {
	in := auditIntent()
	p := healthyPolicy(in)
	p.BackupHorizonSeconds = 120
	p.History = &value.OperationHistoryQualification{ID: in.RootID, Digest: artifact.Digest{4}, Layout: value.OperationVerificationHistoryLayout, MaximumRowFootprintBytes: 128 << 10, MaximumTransitionWALBytes: 128 << 10, BackupCopies: 2, WALCopies: 2}
	b, w := p.History.SlotBacking(p.MaxPurgeLeases)
	p.BackupReservedBytes = b * p.MetadataSlots
	p.WALReservedBytes = w * p.MetadataSlots
	bound, e := BindOperationLifecycle(in, p)
	if e != nil {
		t.Fatal(e)
	}
	if bound.Lifecycle.LiveRetireBy != in.RetainUntil.Add(-250*time.Second) || bound.Lifecycle.OriginalPurgeAt != in.RetainUntil.Add(-330*time.Second) {
		t.Fatal("backup/cleanup/proof allowances omitted", bound.Lifecycle)
	}
	p.BackupReservedBytes = 0
	if _, e = BindOperationLifecycle(in, p); e != ErrUnavailable {
		t.Fatal("unbacked residual history accepted")
	}
	p = healthyPolicy(in)
	in.RetainUntil = in.WriteUntil.Add(20 * time.Second)
	if _, e = BindOperationLifecycle(in, p); e != ErrUnavailable {
		t.Fatal("short retention silently truncated proof window")
	}
	encoded, _ := json.Marshal(auditIntent())
	if strings.Contains(string(encoded), "Lifecycle") {
		t.Fatal("legacy encrypted record gained a null field")
	}
}

func TestHealthyAuditQualificationIsConcreteAndFrozen(t *testing.T) {
	in := auditIntent()
	p := healthyPolicy(in)
	p.BackupHorizonSeconds = 120
	p.History = &value.OperationHistoryQualification{ID: in.RootID, Digest: artifact.Digest{4}, Layout: value.OperationVerificationHistoryLayout, MaximumRowFootprintBytes: 128 << 10, MaximumTransitionWALBytes: 128 << 10, BackupCopies: 2, WALCopies: 2}
	b, w := p.History.SlotBacking(p.MaxPurgeLeases)
	p.BackupReservedBytes, p.WALReservedBytes = b*p.MetadataSlots, w*p.MetadataSlots
	for _, edit := range []func(*value.OperationLifecyclePolicy){
		func(p *value.OperationLifecyclePolicy) { p.History = nil },
		func(p *value.OperationLifecyclePolicy) { p.BackupReservedBytes-- },
		func(p *value.OperationLifecyclePolicy) { p.WALReservedBytes-- },
		func(p *value.OperationLifecyclePolicy) { p.MaxPurgeLeases = 1 },
		func(p *value.OperationLifecyclePolicy) { p.MaxPurgeLeases = 33 },
		func(p *value.OperationLifecyclePolicy) { p.History.Layout = "unqualified" },
		func(p *value.OperationLifecyclePolicy) { p.History.BackupCopies = 0 },
	} {
		q := p
		h := *p.History
		q.History = &h
		edit(&q)
		if _, e := BindOperationLifecycle(in, q); e != ErrUnavailable {
			t.Fatal("unqualified or under-backed history accepted", q)
		}
	}
	f := &healthyFixture{operationFixture: &operationFixture{}}
	gate, e := NewHealthyOperationAuditor(p, f, f, f, f, f, func() time.Time { return in.CreatedAt })
	if e != nil {
		t.Fatal(e)
	}
	p.History.Layout = "changed-after-construction"
	if e = gate.Begin(context.Background(), in); e != nil {
		t.Fatal("caller changed frozen qualification", e)
	}
	if f.snap.Intent.Lifecycle.Policy.History.Layout != value.OperationVerificationHistoryLayout {
		t.Fatal("policy retained mutable caller alias")
	}
	out := auditOutcome(in)
	if e = gate.Finish(context.Background(), out); e != nil {
		t.Fatal("Finish failed to reuse original qualification", e)
	}
}

func TestHealthyAuditorZeroValueIsUnavailable(t *testing.T) {
	var absent *HealthyOperationAuditor
	empty := &HealthyOperationAuditor{}
	for _, s := range []*HealthyOperationAuditor{absent, empty} {
		if s.Configured() {
			t.Fatal("empty composition configured")
		}
		if s.Begin(context.Background(), auditIntent()) != ErrUnavailable || s.Finish(context.Background(), auditOutcome(auditIntent())) != ErrUnavailable {
			t.Fatal("empty composition enabled")
		}
	}
	f := &healthyFixture{operationFixture: &operationFixture{}}
	in := auditIntent()
	s, e := NewHealthyOperationAuditor(healthyPolicy(in), f, f, f, f, f, func() time.Time { return in.CreatedAt })
	if e != nil || !s.Configured() {
		t.Fatal("complete composition unavailable", e)
	}
}

func TestHealthyAdmissionRejectsHistoricalVerifierAllowances(t *testing.T) {
	in := auditIntent()
	f := &healthyFixture{operationFixture: &operationFixture{}}
	for _, layout := range []string{"", value.OperationHistoryLayout, value.OperationOverdueHistoryLayout} {
		p := healthyPolicy(in)
		if layout == "" {
			p.History = nil
			p.BackupReservedBytes = 0
			p.WALReservedBytes = 0
		} else {
			p.History.Layout = layout
			p.BackupHorizonSeconds = 1
			if layout == value.OperationOverdueHistoryLayout {
				p.OverdueTerminal = value.OperationOverdueTerminal
			}
		}
		if !p.Valid() {
			t.Fatal("historical binding no longer readable", layout)
		}
		if _, e := BindOperationLifecycle(in, p); e != nil {
			t.Fatal("historical binding cannot be reconstructed", e)
		}
		if _, e := NewHealthyOperationAuditor(p, f, f, f, f, f, time.Now); e != ErrUnavailable {
			t.Fatal("old qualification acquired fresh verifier allowance", layout, e)
		}
	}
}
