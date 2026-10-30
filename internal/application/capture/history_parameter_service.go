package capture

import (
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	privacy "asservat.local/asservat/internal/domain/privacy"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"time"
)

type HistoryParameterLedger interface {
	ReserveHistoryParameters(context.Context, value.HistoryReservation) (value.HistoryStorage, error)
	ClaimHistoryWrite(context.Context, value.HistoryWriteRequest) (value.HistoryOperationAuthority, error)
	CompleteHistoryWrite(context.Context, value.HistoryWriteResult) error
	ReadHistoryStorage(context.Context, value.SettingsQuery) (value.HistoryStorage, bool, error)
	AuthorizeHistoryRead(context.Context, value.HistoryReadRequest) (value.HistoryReadPermission, error)
}
type HistoryMetadataRetention interface {
	ResolveCaseMetadata(context.Context, privacy.Input) (privacy.Resolution, error)
	ResolveRetainedCaseMetadata(context.Context, privacy.Input, privacy.Deadlines, []artifact.RetentionRule) (privacy.RetainedResolution, error)
}

// HistoryParameterService operates only on independently admitted captures.
// Its optional persistence result is not an acquisition outcome and callers
// must preserve a successfully admitted incident when history is unavailable.
type ContextPreviewExpiryCleanup interface {
	DeleteExpiredContextPreviews(context.Context) (int64, error)
}

type HistoryParameterService struct {
	PreviewCleanup         ContextPreviewExpiryCleanup
	RootID, InstallationID string
	Ledger                 HistoryParameterLedger
	Regional               fleetapp.HistoryDispatcher
	Codec                  HistoryParameterCodec
	Keys                   HistoryKeys
	Recovery               fleetapp.RecoveryReader
	Retention              HistoryMetadataRetention
	Legacy                 ContextHistoryReader
	Limits                 value.HistoryLimits
	NewID                  func() string
	Now                    func() time.Time
	// ReportFailure receives only closed operation/stage/context-state words.
	ReportFailure func(string)
}

func (s HistoryParameterService) configured() bool {
	return authorization.UUID(s.RootID) && authorization.UUID(s.InstallationID) && s.Ledger != nil && s.Regional != nil && s.Codec != nil && s.Keys != nil && s.Recovery != nil && s.Retention != nil && s.Limits.Valid() && s.NewID != nil && s.Now != nil
}

func (s HistoryParameterService) Persist(ctx context.Context, accepted value.Accepted, i identity.Identity, p value.HistoryParameters, source *value.HistoryLineage) (failure error) {
	stage := "input"
	defer func() { s.reportFailure(ctx, "write", stage, failure) }()
	if !s.configured() || ctx == nil || !p.Valid() || !acceptedContext(accepted, accepted.SubmissionDigest) || p.OriginalExecutionDigest != accepted.ScopeDigest || accepted.Replay {
		return value.ErrHistoryUnavailable
	}
	original := accepted.Expectation
	if accepted.Group != nil {
		// All children independently establish the same selected metadata pool. The
		// new history object has its own genuine ID; the parent has no artifact.
		original = accepted.Group.Children[0].Expectation
		for _, child := range accepted.Group.Children {
			e := child.Expectation
			if e.Registration.Location.ClusterID != original.Registration.Location.ClusterID || e.NamespaceUID != original.NamespaceUID || e.WorkloadUID != original.WorkloadUID || e.Registration.StoreID != original.Registration.StoreID || e.Registration.AllocationID != original.Registration.AllocationID || e.Registration.PoolRevision != original.Registration.PoolRevision || e.Registration.AllocationRevision != original.Registration.AllocationRevision {
				return value.ErrHistoryUnavailable
			}
		}
	}
	if p.Target.ClusterID != original.Registration.Location.ClusterID || p.NamespaceUID != original.NamespaceUID || p.WorkloadUID != original.WorkloadUID {
		return value.ErrInvalid
	}
	// Validate and bound the immutable plaintext before reserving storage or
	// invoking any KMS/backend operation.
	stage = "parameters"
	plain, err := value.CanonicalHistoryParameters(p)
	if err != nil {
		return err
	}
	clear(plain)
	stage = "keys"
	selector, settings, err := HistoryParameterKeys(s.Keys, s.RootID, p)
	if err != nil {
		return err
	}
	stage = "recovery"
	recovery, err := s.Recovery.RecoveryState(ctx)
	if err != nil || recovery.InstallationID != s.InstallationID || !recovery.Valid(s.Now()) {
		return value.ErrHistoryUnavailable
	}
	target := authorization.Target{ClusterID: p.Target.ClusterID, NamespaceUID: p.NamespaceUID, WorkloadUID: p.WorkloadUID, PodUID: original.PodUID}
	// The actual retained member is a metadata-selector witness only. Current
	// retention selectors cover namespace/workload; all children independently
	// establish that same workload and remain separately authorized below SQL.
	stage = "retention"
	retention, err := s.Retention.ResolveCaseMetadata(ctx, privacy.Input{ControlKind: "case-metadata", Target: target, PrivacyClass: "potentialPersonalData", EvidenceType: "other", AnchorAt: accepted.CreatedAt})
	if err != nil {
		return err
	}
	expiry, deleteBy := retention.ExpiresAt, retention.DeleteBy
	stage = "source"
	if source != nil {
		if !source.Valid(s.Now()) {
			return value.ErrSettingsUnavailable
		}
		expiry = identity.Earlier(expiry, source.ExpiresAt)
		deleteBy = identity.Earlier(deleteBy, source.ExpiresAt.Add(time.Duration(retention.DeletionBudgetSeconds)*time.Second))
	}
	r := original.Registration
	r.Location.ArtifactID = s.NewID()
	r.Location.AttemptID = s.NewID()
	r.NativeLimit = value.MaxHistoryParameters
	r.AnchorAt = accepted.CreatedAt
	r.WriteUntil = identity.Earlier(accepted.Deadline, s.Now().UTC().Truncate(time.Microsecond).Add(30*time.Second))
	r.ExpiresAt = expiry
	r.DeleteBy = deleteBy
	e := value.HistoryExpectation{RootID: s.RootID, CaptureID: accepted.CaptureID, Registration: r, SelectorKey: selector, SettingsKey: settings, MACVersion: s.Keys.AccountVersion(), OriginalExecutionDigest: accepted.ScopeDigest}
	stage = "expectation"
	if !e.Valid() {
		return value.ErrSettingsUnavailable
	}
	stage = "reserve"
	storage, err := s.Ledger.ReserveHistoryParameters(ctx, value.HistoryReservation{Expectation: e, Identity: i, Recovery: recovery, Limits: s.Limits, SummaryExpiresAt: retention.ExpiresAt, Retention: retention, Source: source})
	if err != nil {
		return err
	}
	stage = "seal"
	bundle, err := s.Codec.SealHistory(ctx, e, p)
	if err != nil {
		return err
	}
	defer bundle.Clear()
	stage = "prepare"
	session, err := s.Regional.PrepareHistory(ctx, p.Target.ClusterID, accepted.CaptureID)
	if err != nil {
		return err
	}
	defer session.Close()
	operation, cancel := context.WithDeadline(ctx, session.NotAfter())
	defer cancel()
	stage = "bundle"
	bundleDigest, err := value.HistoryCiphertextsDigest(bundle)
	if err != nil {
		return err
	}
	stage = "claim"
	authority, err := s.Ledger.ClaimHistoryWrite(operation, value.HistoryWriteRequest{Storage: storage, Identity: i, Recovery: recovery, RequestID: s.NewID(), ExecutorEpoch: session.ExecutorEpoch(), BundleDigest: bundleDigest})
	if err != nil {
		return err
	}
	stage = "execute"
	reply, err := session.ExecuteHistory(operation, authority, bundle, artifact.Copies{})
	if err != nil {
		return err
	}
	stage = "completion"
	if reply.WriterCompletion == nil || !reply.WriterCompletion.Valid(e) || reply.WriterCompletion.OperationID != authority.RequestID || reply.WriterCompletion.ProcessEpoch != authority.ExecutorEpoch || reply.Copies.Validate(r) != nil || reply.WriterCompletion.CopiesDigest != value.HistoryCopiesDigest(reply.Copies) {
		return artifact.ErrIntegrity
	}
	for role := 0; role < 3; role++ {
		if reply.Copies[role].Bytes != int64(len(bundle[role])) || reply.Copies[role].SHA256 != artifact.Digest(sha256.Sum256(bundle[role])) {
			return artifact.ErrIntegrity
		}
	}
	stage = "settle"
	return s.Ledger.CompleteHistoryWrite(ctx, value.HistoryWriteResult{Authority: authority, Copies: reply.Copies, Completion: *reply.WriterCompletion, Recovery: recovery})
}

func (s HistoryParameterService) ListCaptureHistory(ctx context.Context, q value.HistoryQuery) (value.HistoryPage, error) {
	if s.Legacy == nil {
		return value.HistoryPage{}, value.ErrUnavailable
	}
	return s.Legacy.ListCaptureHistory(ctx, q)
}
func (s HistoryParameterService) ReadCaptureSettings(ctx context.Context, q value.SettingsQuery) (result value.CaptureSettings, failure error) {
	stage := "input"
	defer func() { s.reportFailure(ctx, "read", stage, failure) }()
	var zero value.CaptureSettings
	if !s.configured() || !q.Valid(s.Now()) || q.RootID != s.RootID {
		return zero, value.ErrDenied
	}
	stage = "storage"
	storage, required, err := s.Ledger.ReadHistoryStorage(ctx, q)
	if err != nil {
		return zero, err
	}
	stage = "legacy"
	if !required {
		if s.Legacy == nil {
			return zero, value.ErrSettingsUnavailable
		}
		return s.Legacy.ReadCaptureSettings(ctx, q)
	}
	stage = "retention"
	retained, err := s.Retention.ResolveRetainedCaseMetadata(ctx, storage.Retention.Input, storage.Effective, storage.Retention.Origins)
	if err != nil || !s.Now().Before(retained.ExpiresAt) {
		return zero, value.ErrSettingsUnavailable
	}
	stage = "prepare"
	session, err := s.Regional.PrepareHistory(ctx, storage.Expectation.Registration.Location.ClusterID, q.CaptureID)
	if err != nil {
		return zero, value.ErrSettingsUnavailable
	}
	defer session.Close()
	operation, cancel := context.WithDeadline(ctx, session.NotAfter())
	defer cancel()
	in := value.HistoryReadRequest{Retention: retained, Query: q, RequestID: s.NewID(), ExecutorEpoch: session.ExecutorEpoch()}
	stage = "authorize"
	permission, err := s.Ledger.AuthorizeHistoryRead(operation, in)
	if err != nil {
		return zero, err
	}
	stage = "execute"
	reply, err := session.ExecuteHistory(operation, permission.Authority, value.HistoryCiphertexts{}, permission.Storage.Copies)
	if err != nil {
		return zero, value.ErrSettingsUnavailable
	}
	defer reply.Bundle.Clear()
	stage = "open"
	p, err := s.Codec.OpenHistory(operation, permission.Storage.Expectation, permission.Storage.Copies, reply.Bundle)
	if err != nil {
		return zero, value.ErrSettingsUnavailable
	}
	// The original operation stays finite across provider/object I/O. A second
	// current SQL check grants no extra lifetime and prevents stale disclosure.
	stage = "final"
	final, err := s.Ledger.AuthorizeHistoryRead(operation, in)
	if err != nil || !s.Now().Before(permission.Authority.NotAfter) || value.HistoryExpectationDigest(final.Storage.Expectation) != value.HistoryExpectationDigest(permission.Storage.Expectation) {
		return zero, value.ErrSettingsUnavailable
	}
	target := bytes.Clone(p.AuthoredTargetJSON)
	if len(target) == 0 {
		target, _ = json.Marshal(p.Target)
	}
	until := identity.Earlier(permission.Authority.NotAfter, final.Authority.NotAfter)
	return value.CaptureSettings{RecordingSave: p.RecordingSave.Clone(), CaptureID: q.CaptureID, Origin: storage.Origin, ClusterID: p.Target.ClusterID, NamespaceUID: p.NamespaceUID, WorkloadUID: p.WorkloadUID, AcceptedAt: storage.Expectation.Registration.AnchorAt, ExpiresAt: identity.Earlier(final.Storage.SummaryExpiresAt, identity.Earlier(final.Storage.Effective.ExpiresAt, retained.ExpiresAt)), TargetJSON: target, DependencyJSON: bytes.Clone(p.DependencyJSON), RecipeJSON: bytes.Clone(p.RecipeJSON), CompositionJSON: bytes.Clone(p.CompositionJSON), FrozenFilters: bytes.Clone(p.FrozenFilters), ExplicitPodUID: p.ExplicitPodUID, Selection: p.Selection, PolicyOrigins: append([]value.HistoryPolicyOrigin(nil), p.PolicyOrigins...), Composition: p.Composition.Clone(), SettingsKey: storage.Expectation.SettingsKey, OriginalEffectiveSeconds: p.OriginalEffectiveSeconds, Namespace: p.Target.Namespace, WorkloadKind: p.Target.Kind, WorkloadName: p.Target.Name, RequestedSeconds: p.RequestedSeconds, ExecutionDigest: p.OriginalExecutionDigest, ObservedAt: final.Storage.ObservedAt, ValidUntil: until}, nil
}

type HistoryRetirementLedger interface {
	HistoryRetirementCandidates(context.Context, time.Time, string) ([]value.HistoryRetirementCandidate, error)
	ExpireHistorySummaries(context.Context, artifact.RecoveryProof) error
	ClaimHistoryDeletion(context.Context, value.HistoryDeleteRequest) (value.HistoryDeletePermission, error)
	FinishHistoryDeletion(context.Context, value.HistoryOperationAuthority, value.HistoryDeleteCompletion, artifact.RecoveryProof) error
}

// Sweep reuses the supervised hub maintenance cadence and live outbound
// connector slots. Each original finite exchange joins before its charge can
// be released; unavailable/uncertain regions retain their storage obligation.
func (s HistoryParameterService) Sweep(ctx context.Context) error {
	_, _, err := s.sweep(ctx, "")
	return err
}

func (s HistoryParameterService) sweep(ctx context.Context, after string) (string, bool, error) {
	if !s.configured() || ctx == nil {
		return after, false, value.ErrUnavailable
	}
	ledger, ok := s.Ledger.(HistoryRetirementLedger)
	if !ok {
		return after, false, value.ErrUnavailable
	}
	rows, err := ledger.HistoryRetirementCandidates(ctx, s.Now(), after)
	if err != nil || len(rows) == 0 {
		return "", false, err
	}
	recovery, err := s.Recovery.RecoveryState(ctx)
	if err != nil || recovery.InstallationID != s.InstallationID || !recovery.Valid(s.Now()) {
		return after, false, value.ErrUnavailable
	}
	if err = ledger.ExpireHistorySummaries(ctx, recovery); err != nil {
		return after, false, err
	}
	var first error
	for _, row := range rows {
		if row.State == "deleted" {
			continue
		}
		if err = s.retire(ctx, ledger, row); err != nil && first == nil {
			first = err
		}
		if ctx.Err() != nil {
			return row.CaptureID, false, ctx.Err()
		}
	}
	next := ""
	if len(rows) == 16 {
		next = rows[len(rows)-1].CaptureID
	}
	return next, len(rows) == 16 && first == nil, first
}
func (s HistoryParameterService) retire(ctx context.Context, ledger HistoryRetirementLedger, row value.HistoryRetirementCandidate) error {
	recovery, err := s.Recovery.RecoveryState(ctx)
	if err != nil || recovery.InstallationID != s.InstallationID || !recovery.Valid(s.Now()) {
		return value.ErrUnavailable
	}
	session, err := s.Regional.PrepareHistory(ctx, row.ClusterID, row.CaptureID)
	if err != nil {
		return err
	}
	defer session.Close()
	operation, cancel := context.WithDeadline(ctx, session.NotAfter())
	defer cancel()
	permission, err := ledger.ClaimHistoryDeletion(operation, value.HistoryDeleteRequest{CaptureID: row.CaptureID, RequestID: s.NewID(), ExecutorEpoch: session.ExecutorEpoch(), Recovery: recovery})
	if err != nil {
		return err
	}
	reply, err := session.ExecuteHistory(operation, permission.Authority, value.HistoryCiphertexts{}, permission.Storage.Copies)
	if err != nil {
		return err
	}
	if reply.DeleteCompletion == nil || !reply.DeleteCompletion.Valid(permission.Authority) {
		return artifact.ErrIntegrity
	}
	return ledger.FinishHistoryDeletion(operation, permission.Authority, *reply.DeleteCompletion, recovery)
}

// Run is owned and joined by the existing hub supervisor. One bounded SQL
// hint every three idle seconds; successful full pages drain without an idle
// delay. Failures keep charges and pace retries. No new deployment or watch.
func (s HistoryParameterService) Run(ctx context.Context, report func(string)) error {
	if ctx == nil || (!s.configured() && s.PreviewCleanup == nil) {
		return value.ErrUnavailable
	}
	delay := time.NewTimer(3 * time.Second)
	defer delay.Stop()
	// A process-local keyset advances even across unavailable regions.
	// Restart may repeat cleanup; a stuck first page cannot starve others.
	after := ""
	var nextPreviewCleanup time.Time
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-delay.C:
		}
		var cleanupErr error
		nextPreviewCleanup, cleanupErr = s.cleanupExpiredPreviews(ctx, nextPreviewCleanup, time.Now())
		if cleanupErr != nil && report != nil {
			report("previews")
		}
		var more bool
		var err error
		if s.configured() {
			call, cancel := context.WithTimeout(ctx, 30*time.Second)
			var next string
			next, more, err = s.sweep(call, after)
			after = next
			cancel()
		}
		if err != nil && report != nil {
			report("sweep")
		}
		interval := 3 * time.Second
		if more && err == nil {
			interval = time.Millisecond
		}
		delay.Reset(interval)
	}
}

// Cleanup shares the existing owned loop but never depends on history readiness
// or publication success. Pacing state is not identity or capture authority.
func (s HistoryParameterService) cleanupExpiredPreviews(ctx context.Context, next, now time.Time) (time.Time, error) {
	if s.PreviewCleanup == nil || now.Before(next) {
		return next, nil
	}
	cleanup, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	_, err := s.PreviewCleanup.DeleteExpiredContextPreviews(cleanup)
	return now.Add(30 * time.Second), err
}
