package evidence

import (
	auditapp "asservat.local/asservat/internal/application/audit"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"sync"
	"time"
)

// These are transient domain values, shared with the final delivery adapter.
type DownloadMetadata = artifact.NativeDownloadMetadata
type DownloadSelection = artifact.DownloadSelection

type DownloadDestination interface {
	// Send must enforce the supplied context's original socket/relay deadline.
	// It returns only bytes actually handed to the transport. It must neither
	// retain plaintext nor retry/redirect/use an arbitrary caller destination.
	Send(context.Context, DownloadMetadata, DownloadSelection, []byte) (int64, error)
}
type ContextDownloadRequest struct {
	SessionID   string
	Scope       artifact.DownloadScope
	Expectation artifact.ContextExpectation
	Copies      artifact.Copies
}

// ContextDownloadWorker is a regional acquisition-role service. Its ledger and
// current-gate ports may be mediated by authenticated control relay; the hub
// must never wire an artifact unwrap key into its public HTTP/API process.
// Public scope/source resolution and relay bootstrap remain separate work.
type ContextDownloadWorker struct {
	Sessions              DownloadSessions
	AuditAcknowledgements DownloadAuditAcknowledger
	Audit                 auditapp.DownloadWriter
	Authority             DownloadAuthorityGate
	CurrentAuthority      CurrentDownloadAuthority
	Native                ContextNativeReader
	BatchNative           ContextBatchNativeReader
	RegionalPreparation   RegionalPreparation
	Now                   func() time.Time
	NewID                 func() string
}

// Covers four bounded ciphertext reads and bounded plaintext decode work for
// this 4096-byte context profile. S3 retries are disabled in the selected adapter.
const ContextDownloadReadWork int64 = 4 << 20

func (w ContextDownloadWorker) valid(r ContextDownloadRequest) bool {
	e, s := r.Expectation, r.Scope
	readers := 0
	for _, present := range []bool{w.Native != nil, w.BatchNative != nil, w.RegionalPreparation != nil} {
		if present {
			readers++
		}
	}
	return w.Sessions != nil && w.AuditAcknowledgements != nil && w.Audit != nil && (w.Authority != nil || w.CurrentAuthority != nil) && readers == 1 && w.Now != nil && w.NewID != nil && s.Valid() && e.Validate() == nil && e.DataClass == "metadata" && r.Copies.Validate(e.Registration) == nil && s.ArtifactID == e.Registration.Location.ArtifactID && s.CaptureID == e.CaptureUID && s.ClusterID == e.Registration.Location.ClusterID && s.NamespaceUID == e.NamespaceUID && s.WorkloadUID == e.WorkloadUID && s.PodUID == e.PodUID && s.Version == ContextCopiesDigest(r.Copies)
}

func (w ContextDownloadWorker) read(ctx context.Context, r ContextDownloadRequest, i audit.DownloadIntent, a artifact.DownloadAuthority) ([]byte, error) {
	if w.BatchNative != nil {
		return w.BatchNative.ReadContextBatch(ctx, r.Expectation, r.Copies, i, a)
	}
	return w.Native.ReadContext(ctx, r.Expectation, r.Copies, minDownloadTime(i.Batch.LeaseUntil, a.ValidUntil))
}
func (w ContextDownloadWorker) current(ctx context.Context, credential string, r ContextDownloadRequest) (artifact.DownloadAuthority, error) {
	if w.Authority == nil {
		return artifact.DownloadAuthority{}, artifact.ErrInvalid
	}
	a, err := w.Authority.CheckDownload(ctx, credential, r.Scope)
	if err != nil {
		return a, err
	}
	if ctx.Err() != nil || !a.Valid(w.Now()) || a.Scope != r.Scope || a.AccessUntil.After(r.Expectation.Registration.ExpiresAt) || a.DeleteBy.IsZero() || a.DeleteBy.After(r.Expectation.Registration.DeleteBy) {
		return a, artifact.ErrDownloadExpired
	}
	return a, nil
}

type contextDownloadCheck func(context.Context) (artifact.DownloadAuthority, error)

func (w ContextDownloadWorker) begin(ctx context.Context, credential string, r ContextDownloadRequest, purpose artifact.DownloadPurpose, selection DownloadSelection) (audit.DownloadIntent, error) {
	return w.beginChecked(ctx, r, purpose, selection, func(ctx context.Context) (artifact.DownloadAuthority, error) { return w.current(ctx, credential, r) })
}
func (w ContextDownloadWorker) beginChecked(ctx context.Context, r ContextDownloadRequest, purpose artifact.DownloadPurpose, selection DownloadSelection, check contextDownloadCheck) (audit.DownloadIntent, error) {
	var zero audit.DownloadIntent
	if ctx == nil || ctx.Err() != nil || !w.valid(r) || check == nil {
		return zero, artifact.ErrInvalid
	}
	a, err := check(ctx)
	if err != nil {
		return zero, err
	}
	i, err := w.Sessions.BeginDownloadBatch(ctx, r.SessionID, a, artifact.DownloadBatch{ID: w.NewID(), Purpose: purpose, Offset: selection.Offset, OutputBytes: selection.Length, ReadBytes: ContextDownloadReadWork})
	if err != nil {
		return zero, err
	}
	if !i.Valid() || i.SessionID != r.SessionID || i.Batch.Authority.Scope != r.Scope || i.Batch.Purpose != purpose || i.Batch.Offset != selection.Offset || i.Batch.OutputBytes != selection.Length || i.Batch.ReadBytes != ContextDownloadReadWork || !w.Now().Before(i.Batch.LeaseUntil) {
		return zero, artifact.ErrIntegrity
	}
	return i, nil
}
func (w ContextDownloadWorker) ackIntent(ctx context.Context, i audit.DownloadIntent) error {
	receipt, err := w.Audit.WriteDownloadIntent(ctx, i)
	if err != nil {
		return err
	}
	if !receipt.ValidDownload(i.Batch.Authority.Scope.RootID, i.SessionID, i.Batch.ID, "intent") {
		return artifact.ErrIntegrity
	}
	return w.AuditAcknowledgements.AcknowledgeDownloadIntent(ctx, i, receipt)
}
func (w ContextDownloadWorker) finish(ctx context.Context, i audit.DownloadIntent, emitted int64, success, full bool) error {
	// A disconnected client cannot erase accounting. Recovery is bounded and
	// carries no plaintext; failed work remains conservatively charged in SQL.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	o, err := w.Sessions.FinishDownloadBatch(ctx, i.SessionID, i.Batch.ID, i.Batch.Generation, emitted, success, full)
	if err != nil {
		return err
	}
	if !o.Valid() || !o.Intent.Equal(i) || o.EmittedBytes != emitted || o.Success != success || o.FullFile != full {
		return artifact.ErrIntegrity
	}
	receipt, err := w.Audit.WriteDownloadOutcome(ctx, o)
	if err != nil {
		return err
	}
	if !receipt.ValidDownload(i.Batch.Authority.Scope.RootID, i.SessionID, i.Batch.ID, "outcome") {
		return artifact.ErrIntegrity
	}
	return w.AuditAcknowledgements.AcknowledgeDownloadOutcome(ctx, o, receipt)
}
func (w ContextDownloadWorker) permit(ctx context.Context, credential string, r ContextDownloadRequest, i audit.DownloadIntent) (artifact.DownloadAuthority, error) {
	return w.permitChecked(ctx, r, i, func(ctx context.Context) (artifact.DownloadAuthority, error) { return w.current(ctx, credential, r) })
}
func (w ContextDownloadWorker) permitChecked(ctx context.Context, r ContextDownloadRequest, i audit.DownloadIntent, check contextDownloadCheck) (artifact.DownloadAuthority, error) {
	a, err := check(ctx)
	if err != nil {
		return a, err
	}
	if !w.Now().Before(i.Batch.LeaseUntil) {
		return a, artifact.ErrDownloadExpired
	}
	return a, w.Sessions.PermitDownloadBatch(ctx, r.SessionID, a, i.Batch.ID, i.Batch.Generation)
}
func contextDownloadMetadata(r ContextDownloadRequest, native []byte) DownloadMetadata {
	return DownloadMetadata{Filename: "artifact-" + r.Scope.ArtifactID + ".json", Format: artifact.ContextFormat, ETag: `"v1-` + hex.EncodeToString(r.Scope.Version[:]) + `"`, Coverage: "Selected pod-status fields only; no logs, messages or workload configuration.", Size: int64(len(native)), SHA256: sha256.Sum256(native), ReadUntil: r.Expectation.Registration.ExpiresAt, DeleteBy: r.Expectation.Registration.DeleteBy}
}

func (w ContextDownloadWorker) Prepare(ctx context.Context, credential string, r ContextDownloadRequest) (DownloadMetadata, error) {
	return w.prepareChecked(ctx, r, func(ctx context.Context) (artifact.DownloadAuthority, error) { return w.current(ctx, credential, r) }, nil)
}

// PrepareCurrent accepts a live request-owned identity directly. It shares the
// original preparation/accounting/first-response gates, with no bearer adapter.
func (w ContextDownloadWorker) PrepareCurrent(ctx context.Context, current identities.CurrentIdentity, r ContextDownloadRequest) (DownloadMetadata, error) {
	return w.prepareCurrentRetained(ctx, current, r, nil)
}

// prepareCurrentRetained adds the private post-acknowledgement retention point.
func (w ContextDownloadWorker) prepareCurrentRetained(ctx context.Context, current identities.CurrentIdentity, r ContextDownloadRequest, retain func(artifact.PreparedDownload) error) (DownloadMetadata, error) {
	check, err := w.identityCheck(ctx, current, r)
	if err != nil {
		return DownloadMetadata{}, err
	}
	return w.prepareChecked(ctx, r, check, retain)
}

func (w ContextDownloadWorker) prepareChecked(ctx context.Context, r ContextDownloadRequest, check contextDownloadCheck, retain func(artifact.PreparedDownload) error) (out DownloadMetadata, err error) {
	// Private transport can recheck concurrently with control accounting. Share
	// one serialized original closure; waiting cannot restart its deadline.
	if check == nil {
		return out, artifact.ErrInvalid
	}
	var currentMu sync.Mutex
	original := check
	check = func(call context.Context) (artifact.DownloadAuthority, error) {
		currentMu.Lock()
		defer currentMu.Unlock()
		if call == nil || call.Err() != nil || ctx.Err() != nil {
			return artifact.DownloadAuthority{}, artifact.ErrDownloadExpired
		}
		return original(call)
	}
	i, err := w.beginChecked(ctx, r, artifact.DownloadMetadata, DownloadSelection{}, check)
	if err != nil {
		return out, err
	}
	ctx, cancel := context.WithDeadline(ctx, i.Batch.LeaseUntil)
	defer cancel()
	finished := false
	defer func() {
		if !finished {
			err = errors.Join(err, w.finish(ctx, i, 0, false, false))
		}
	}()
	if err = w.ackIntent(ctx, i); err != nil {
		return out, err
	}
	a, err := w.permitChecked(ctx, r, i, check)
	if err != nil {
		return out, err
	}
	readCtx, stopRead := context.WithDeadline(ctx, a.ValidUntil)
	defer stopRead()
	var metadata DownloadMetadata
	var remote NativePreparationCommit
	if w.RegionalPreparation != nil {
		metadata, remote, err = w.RegionalPreparation.PrepareNativeMetadata(readCtx, r, i, a, NativePreparationCheck(check))
		if remote != nil {
			defer remote.Close()
		}
		if err != nil {
			return out, err
		}
		if remote == nil || !validRegionalMetadata(r, metadata) {
			return out, artifact.ErrIntegrity
		}
	} else {
		native, readErr := w.read(readCtx, r, i, a)
		defer clear(native)
		if readErr != nil {
			return out, readErr
		}
		if len(native) == 0 || len(native) > artifact.MaxContextBytes {
			return out, artifact.ErrIntegrity
		}
		metadata = contextDownloadMetadata(r, native)
	}
	if _, err = w.permitChecked(ctx, r, i, check); err != nil {
		return out, err
	}
	finished = true // an uncertain finish must never be rewritten as failure
	if err = w.finish(ctx, i, 0, true, false); err != nil {
		return out, err
	}
	if remote != nil {
		if err = remote.Commit(ctx); err != nil {
			return out, err
		}
	}
	// This private retention point follows acknowledged immutable accounting.
	// It is deliberately before the unchanged first-response authority gate:
	// losing that response cannot erase successfully paid verification facts.
	if retain != nil {
		prepared := artifact.PreparedDownload{Preparation: artifact.DownloadPreparation{SessionID: r.SessionID, BatchID: i.Batch.ID, Generation: i.Batch.Generation}, Scope: r.Scope, Native: metadata}
		if !prepared.Valid() {
			return out, artifact.ErrIntegrity
		}
		if err = retain(prepared); err != nil {
			return out, err
		}
	}
	a, err = check(ctx)
	if err != nil {
		return out, err
	}
	if err = w.Sessions.PermitDownloadMetadata(ctx, r.SessionID, a, i.Batch.ID, i.Batch.Generation); err != nil {
		return out, err
	}
	metadata.ReadUntil = a.AccessUntil
	metadata.DeleteBy = a.DeleteBy
	return metadata, nil
}

func (w ContextDownloadWorker) Transfer(ctx context.Context, credential string, r ContextDownloadRequest, selection DownloadSelection, destination DownloadDestination) (err error) {
	if w.RegionalPreparation != nil || destination == nil || selection.Offset < 0 || selection.Length < 1 || selection.Offset > artifact.MaxContextBytes || selection.Length > artifact.MaxContextBytes-selection.Offset {
		return artifact.ErrInvalid
	}
	i, err := w.begin(ctx, credential, r, artifact.DownloadContent, selection)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithDeadline(ctx, i.Batch.LeaseUntil)
	defer cancel()
	finished := false
	var emitted int64
	defer func() {
		if !finished {
			err = errors.Join(err, w.finish(ctx, i, emitted, false, false))
		}
	}()
	if err = w.ackIntent(ctx, i); err != nil {
		return err
	}
	a, err := w.permit(ctx, credential, r, i)
	if err != nil {
		return err
	}
	readCtx, stopRead := context.WithDeadline(ctx, a.ValidUntil)
	defer stopRead()
	native, err := w.read(readCtx, r, i, a)
	defer clear(native)
	if err != nil {
		return err
	}
	if len(native) == 0 || len(native) > artifact.MaxContextBytes || selection.Offset+selection.Length > int64(len(native)) || !selection.Partial && (selection.Offset != 0 || selection.Length != int64(len(native))) {
		return artifact.ErrIntegrity
	}
	metadata := contextDownloadMetadata(r, native)
	// The complete native hash/length/projection has passed before this final
	// single bounded batch. Later artifact mechanisms require chunked workers.
	a, err = w.permit(ctx, credential, r, i)
	if err != nil {
		return err
	}
	metadata.ReadUntil = a.AccessUntil
	metadata.DeleteBy = a.DeleteBy
	sendCtx, stopSend := context.WithDeadline(ctx, a.ValidUntil)
	defer stopSend()
	n, sendErr := destination.Send(sendCtx, metadata, selection, native[selection.Offset:selection.Offset+selection.Length])
	if n < 0 || n > selection.Length {
		return artifact.ErrIntegrity
	}
	emitted = n
	if sendErr != nil {
		return sendErr
	}
	if n != selection.Length {
		return artifact.ErrIntegrity
	}
	finished = true
	return w.finish(ctx, i, emitted, true, selection.Offset == 0 && selection.Length == int64(len(native)))
}

func minDownloadTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// identityCheck pins the initial caller/client/claims and the original response
// interval. Rechecking current identity can shorten, but never renew, that bound.
func (w ContextDownloadWorker) identityCheck(ctx context.Context, current identities.CurrentIdentity, r ContextDownloadRequest) (contextDownloadCheck, error) {
	if ctx == nil || ctx.Err() != nil || current == nil || w.CurrentAuthority == nil || !w.valid(r) {
		return nil, artifact.ErrInvalid
	}
	started := w.Now()
	initialCtx, stopInitial := context.WithDeadline(ctx, started.Add(artifact.DownloadLease))
	initial, err := current.ResolveIdentity(initialCtx)
	initialErr := initialCtx.Err()
	stopInitial()
	if err != nil || initialErr != nil || !initial.Valid(w.Now()) || initial.Principal != r.Scope.Principal || !slices.Contains(initial.Scopes, "evidence:read") || !slices.Contains(initial.Scopes, "evidence:download") {
		return nil, artifact.ErrDownloadUnavailable
	}
	initial.Groups = slices.Clone(initial.Groups)
	initial.Scopes = slices.Clone(initial.Scopes)
	until := identity.Earlier(started.Add(artifact.DownloadLease), initial.ValidUntil)
	if deadline, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, deadline)
	}
	return func(call context.Context) (artifact.DownloadAuthority, error) {
		if call == nil || call.Err() != nil || !w.Now().Before(until) {
			return artifact.DownloadAuthority{}, artifact.ErrDownloadExpired
		}
		bounded, stop := context.WithDeadline(call, until)
		defer stop()
		latest, err := current.ResolveIdentity(bounded)
		if err != nil || !downloadSameIdentity(initial, latest, w.Now()) {
			return artifact.DownloadAuthority{}, artifact.ErrDownloadUnavailable
		}
		until = identity.Earlier(until, latest.ValidUntil)
		authorityCtx, stopAuthority := context.WithDeadline(bounded, until)
		defer stopAuthority()
		a, err := w.CurrentAuthority.CheckDownloadCurrent(authorityCtx, current, r.Scope)
		if err != nil || authorityCtx.Err() != nil || !a.Valid(w.Now()) || !a.Environment.Valid(w.Now()) || !a.Retention.Valid(w.Now()) || a.Environment.StoreID != r.Expectation.Registration.StoreID || a.Environment.Location != r.Expectation.Registration.Location || a.Scope != r.Scope || a.AccessUntil.After(r.Expectation.Registration.ExpiresAt) || a.DeleteBy.IsZero() || a.DeleteBy.After(r.Expectation.Registration.DeleteBy) {
			return artifact.DownloadAuthority{}, artifact.ErrDownloadUnavailable
		}
		latest, err = current.ResolveIdentity(authorityCtx)
		if err != nil || !downloadSameIdentity(initial, latest, w.Now()) {
			return artifact.DownloadAuthority{}, artifact.ErrDownloadUnavailable
		}
		until = identity.Earlier(until, identity.Earlier(latest.ValidUntil, a.ValidUntil))
		a.ValidUntil = until
		if authorityCtx.Err() != nil || !a.Valid(w.Now()) {
			return artifact.DownloadAuthority{}, artifact.ErrDownloadExpired
		}
		return a, nil
	}, nil
}
