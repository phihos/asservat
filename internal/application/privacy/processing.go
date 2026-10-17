package privacy

import (
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/artifact"
	auditvalue "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"time"
)

// Narrow ports consume existing request-owned identity and protected policy;
// they introduce neither a new identity evaluator nor a public management API.
type ProcessingIdentity interface {
	ResolveIdentity(context.Context) (identity.Identity, error)
}
type ProcessingPolicyReader interface {
	DownloadPolicy(context.Context) (value.DownloadPolicy, error)
}
type ProcessingRecoveryReader interface {
	RecoveryState(context.Context) (artifact.RecoveryProof, error)
}
type ProcessingPrepared struct {
	Decision ProcessingDecision
	Receipt  *value.ProcessingReceipt
}
type ProcessingDecisions interface {
	PrepareProcessing(context.Context, value.ProcessingAuthority, ProcessingDecision) (ProcessingPrepared, error)
	ApplyProcessing(context.Context, value.ProcessingAuthority, ProcessingDecision) (value.ProcessingReceipt, error)
}
type ProcessingAudit interface {
	Begin(context.Context, auditvalue.OperationIntent) error
	Finish(context.Context, auditvalue.OperationOutcome) error
}
type ProcessingChanges struct {
	RootID, InstallationID string
	Policies               ProcessingPolicyReader
	Recovery               ProcessingRecoveryReader
	Decisions              ProcessingDecisions
	Audit                  ProcessingAudit
	ReleaseAudit           ProcessingAudit
	MAC                    *auditapp.OperationMAC
	AuditPolicy            auditvalue.OperationLifecyclePolicy
	ReleaseAuditPolicy     auditvalue.OperationLifecyclePolicy
	RetainedSeconds        int64
	Now                    func() time.Time
}

func (s ProcessingChanges) authority(ctx context.Context, source ProcessingIdentity, started, until time.Time) (value.ProcessingAuthority, error) {
	var zero value.ProcessingAuthority
	i, e := source.ResolveIdentity(ctx)
	if e != nil || !i.Valid(s.Now()) {
		return zero, value.ErrUnavailable
	}
	p, e := s.Policies.DownloadPolicy(ctx)
	if e != nil || p.RootID != s.RootID || p.InstallationID != s.InstallationID || !p.Operator(i, s.Now()) {
		return zero, value.ErrUnavailable
	}
	r, e := s.Recovery.RecoveryState(ctx)
	if e != nil {
		return zero, value.ErrUnavailable
	}
	for _, v := range []time.Time{i.ValidUntil, p.FreshUntil, r.FreshUntil} {
		until = identity.Earlier(until, v)
	}
	a := value.ProcessingAuthority{Identity: i, Policy: p, Recovery: r, ObservedAt: started, ValidUntil: until}
	if ctx.Err() != nil || !a.Valid(s.Now()) {
		return zero, value.ErrUnavailable
	}
	return a, nil
}
func sameProcessingIdentity(a, b identity.Identity) bool {
	if a.Principal != b.Principal || a.Policy != b.Policy {
		return false
	}
	x, y := slices.Clone(a.Groups), slices.Clone(b.Groups)
	slices.Sort(x)
	slices.Sort(y)
	if !slices.Equal(x, y) {
		return false
	}
	x, y = slices.Clone(a.Scopes), slices.Clone(b.Scopes)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}
func (s ProcessingChanges) Change(ctx context.Context, source ProcessingIdentity, c value.ProcessingChange) (value.ProcessingReceipt, error) {
	var zero value.ProcessingReceipt
	if ctx == nil || ctx.Err() != nil || source == nil || s.Policies == nil || s.Recovery == nil || s.Decisions == nil || s.Audit == nil || s.MAC == nil || s.Now == nil || !c.Valid() || !s.AuditPolicy.CertificateVerificationBacked() || s.RetainedSeconds < 60 || s.RetainedSeconds > 316224000 {
		return zero, value.ErrUnavailable
	}
	started := s.Now().UTC().Truncate(time.Microsecond)
	until := started.Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d).UTC().Truncate(time.Microsecond)
	}
	call, stop := context.WithDeadline(ctx, until)
	defer stop()
	authority, e := s.authority(call, source, started, until)
	if e != nil {
		return zero, e
	}
	until = authority.ValidUntil.UTC().Truncate(time.Microsecond)
	call, stopOriginal := context.WithDeadline(call, until)
	defer stopOriginal()
	// The initiating private operation retains RequestID. Replays cannot give
	// the same decision a new audit ID or acquire another provider attempt.
	input, e := json.Marshal(struct {
		Root   string
		Change value.ProcessingChange
		Policy identity.Revision
		Guard  artifact.Digest
	}{s.RootID, c, authority.Policy.Revision, authority.Policy.ProtectionDigest})
	if e != nil {
		return zero, value.ErrUnavailable
	}
	inputMAC, e := s.MAC.Digest("processing-input/v1", input)
	if e != nil {
		return zero, value.ErrUnavailable
	}
	account, e := s.MAC.Principal(authority.Identity.Principal)
	if e != nil {
		return zero, value.ErrUnavailable
	}
	releaseAccount := artifact.Digest{}
	if c.RuleID != "" {
		releaseAccount, e = s.MAC.ProcessingAccount(s.InstallationID, s.RootID, c.RuleID)
		if e != nil {
			return zero, value.ErrUnavailable
		}
	}
	auditService, auditPolicy := s.Audit, s.AuditPolicy
	if c.Action == "release_processing" {
		auditService, auditPolicy = s.ReleaseAudit, s.ReleaseAuditPolicy
		account = releaseAccount
		if auditService == nil || !auditPolicy.CertificateVerificationBacked() || auditPolicy.Lane != "processing" {
			return zero, value.ErrUnavailable
		}
	}
	in := auditvalue.OperationIntent{ID: c.RequestID, RootID: s.RootID, TraceID: c.RequestID, Name: c.Action, InputFormat: "processing-input/v1", MACVersion: s.MAC.Version(), AccountVersion: s.MAC.AccountVersion(), Actor: authority.Identity.Principal, PrincipalDigest: account, InputDigest: inputMAC, CreatedAt: started, RequestUntil: until, WriteUntil: started.Add(30 * time.Second), RetainUntil: started.Add(time.Duration(s.RetainedSeconds) * time.Second)}
	in, e = auditapp.BindOperationLifecycle(in, auditPolicy)
	if e != nil {
		return zero, value.ErrUnavailable
	}
	projection, e := json.Marshal(struct {
		RequestID, Action, RuleID string
		ExpectedRevision          int64
		Decision                  string
	}{c.RequestID, c.Action, c.RuleID, c.ExpectedRevision, "prepared"})
	if e != nil {
		return zero, value.ErrUnavailable
	}
	outputMAC, e := s.MAC.Digest("processing-result/v1", projection)
	if e != nil {
		return zero, value.ErrUnavailable
	}
	outcome := auditvalue.OperationOutcome{Intent: in, Status: "success", Reason: "prepared", Effect: "unknown", ClientReceipt: "unknown", OutputDigest: outputMAC, OutputBytes: int64(len(projection)), MetadataUntil: until, RecordedAt: started}
	draft := ProcessingDecision{Change: c, Intent: in, Outcome: outcome, ReleaseAccount: releaseAccount}
	draft.DecisionDigest = ProcessingDecisionDigest(draft)
	if !draft.Valid() {
		return zero, value.ErrUnavailable
	}
	prepared, e := s.Decisions.PrepareProcessing(call, authority, draft)
	if errors.Is(e, ErrCapacity) {
		return zero, ErrCapacity
	}
	if e != nil {
		return zero, value.ErrUnavailable
	}
	if prepared.Receipt != nil {
		if !prepared.Receipt.Valid(s.Now()) || prepared.Receipt.RequestID != c.RequestID || call.Err() != nil {
			return zero, value.ErrUnavailable
		}
		return s.finalReceipt(call, source, authority, *prepared.Receipt)
	}
	decision := prepared.Decision
	if !decision.Valid() || decision.Change != c || decision.Intent.Actor != authority.Identity.Principal || !s.Now().Before(decision.Intent.RequestUntil) {
		return zero, value.ErrUnavailable
	}
	original := identity.Earlier(until, decision.Intent.RequestUntil)
	call, stopDecision := context.WithDeadline(call, original)
	defer stopDecision()
	if e = auditService.Begin(call, decision.Intent); e != nil {
		return zero, value.ErrUnavailable
	}
	if e = auditService.Finish(call, decision.Outcome); e != nil {
		return zero, value.ErrUnavailable
	}
	// Audit says prepared/effect-unknown. Current authority is still required
	// after provider waits; only the SQL result can prove the bounded CAS.
	final, e := s.authority(call, source, started, identity.Earlier(authority.ValidUntil, original))
	if e != nil || !authority.Valid(s.Now()) || !sameProcessingIdentity(authority.Identity, final.Identity) || authority.Policy.Revision != final.Policy.Revision || authority.Policy.ProtectionDigest != final.Policy.ProtectionDigest || authority.Recovery.Revision != final.Recovery.Revision || authority.Recovery.IssuerEpoch != final.Recovery.IssuerEpoch {
		return zero, value.ErrUnavailable
	}
	result, e := s.Decisions.ApplyProcessing(call, final, decision)
	if e != nil || !result.Valid(s.Now()) || result.RequestID != c.RequestID || call.Err() != nil {
		return zero, value.ErrUnavailable
	}
	return s.finalReceipt(call, source, final, result)
}
func ProcessingDecisionDigest(d ProcessingDecision) artifact.Digest {
	d.DecisionDigest = artifact.Digest{}
	b, e := json.Marshal(d)
	if e != nil || len(b) > 32<<10 {
		return artifact.Digest{}
	}
	return sha256.Sum256(b)
}
func ProcessingRequestDigest(c value.ProcessingChange) artifact.Digest {
	b, e := json.Marshal(c)
	if e != nil || !c.Valid() {
		return artifact.Digest{}
	}
	return sha256.Sum256(b)
}

func (s ProcessingChanges) finalReceipt(ctx context.Context, source ProcessingIdentity, original value.ProcessingAuthority, r value.ProcessingReceipt) (value.ProcessingReceipt, error) {
	now, e := s.authority(ctx, source, original.ObservedAt, identity.Earlier(original.ValidUntil, r.ValidUntil))
	if e != nil || !original.Valid(s.Now()) || !sameProcessingIdentity(original.Identity, now.Identity) || now.Policy.Revision != original.Policy.Revision || now.Policy.ProtectionDigest != original.Policy.ProtectionDigest || now.Recovery.Revision != original.Recovery.Revision || now.Recovery.IssuerEpoch != original.Recovery.IssuerEpoch {
		return value.ProcessingReceipt{}, value.ErrUnavailable
	}
	r.ValidUntil = identity.Earlier(r.ValidUntil, now.ValidUntil)
	if !r.Valid(s.Now()) || ctx.Err() != nil {
		return value.ProcessingReceipt{}, value.ErrUnavailable
	}
	return r, nil
}
