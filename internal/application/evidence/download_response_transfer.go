package evidence

import (
	auditapp "asservat.local/asservat/internal/application/audit"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	identityvalue "asservat.local/asservat/internal/domain/identity"
	"context"
	"crypto/sha256"
	"time"
)

// DownloadResponseTransfer is one synchronous, joined response. Source and
// destination are request-owned protected adapters, not serialized capabilities.
// It admits one prepaid window at a time and never retries uncertain SQL/audit,
// worker reads or HTTP writes. A fresh identity batch only replaces an expired
// observation between completed chunks; it cannot renew an old CurrentIdentity.
type DownloadResponseTransfer struct {
	Sessions  DownloadSessions
	Responses DownloadResponses
	Authority CurrentDownloadAuthority
	Objects   auditapp.DownloadWindowObjects
	Audit     DownloadWindowAcknowledgements
	Now       func() time.Time
	NewID     func() string
}

func (t DownloadResponseTransfer) valid() bool {
	return t.Sessions != nil && t.Responses != nil && t.Authority != nil && t.Objects != nil && t.Audit != nil && t.Now != nil && t.NewID != nil
}

type responseCurrent struct {
	reader    identities.ReaderIdentity
	authority CurrentDownloadAuthority
	batch     identities.IdentityBatch
	scope     artifact.DownloadScope
	value     artifact.DownloadAuthority
	now       func() time.Time
	response  identityvalue.RefreshResponseBinding
	pauseUsed bool
	lastPause identityvalue.RefreshPause
}

func (c *responseCurrent) close() {
	if c.batch != nil {
		c.batch.Close()
		c.batch = nil
	}
}
func (c *responseCurrent) get(ctx context.Context) (artifact.DownloadAuthority, error) {
	if ctx.Err() != nil {
		return artifact.DownloadAuthority{}, ctx.Err()
	}
	if c.batch != nil && c.value.Valid(c.now()) {
		return c.value, nil
	}
	c.close()
	b, e := c.begin(ctx)
	if e != nil {
		return artifact.DownloadAuthority{}, e
	}
	c.batch = b
	a, e := c.authority.CheckDownloadCurrent(ctx, b, c.scope)
	if e != nil {
		c.close()
		return artifact.DownloadAuthority{}, e
	}
	i, e := b.ResolveIdentity(ctx)
	if e != nil || i.Principal != c.scope.Principal {
		c.close()
		return artifact.DownloadAuthority{}, artifact.ErrDownloadUnavailable
	}
	a.ValidUntil = identityvalue.Earlier(a.ValidUntil, i.ValidUntil)
	if !a.Valid(c.now()) || a.Scope != c.scope || ctx.Err() != nil {
		c.close()
		return artifact.DownloadAuthority{}, artifact.ErrDownloadExpired
	}
	c.value = a
	return a, nil
}

// Transfer does not return native contents and does not install a public route.
// A denied/preflight-unavailable source causes no response/window reservation.
func (t DownloadResponseTransfer) Transfer(ctx context.Context, reader identities.ReaderIdentity, request DownloadResponseRequest, source NativeResponseSource, destination DownloadResponseSinkFactory) (err error) {
	return t.transfer(ctx, reader, request, source, destination, nil)
}

// TransferAudited is required by the installed HTTP composition. Intent and
// outcome precede every metadata/conditional reply and content reservation.
func (t DownloadResponseTransfer) TransferAudited(ctx context.Context, reader identities.ReaderIdentity, request DownloadResponseRequest, source NativeResponseSource, destination DownloadResponseSinkFactory, auditor DownloadContentAuditor) error {
	if auditor == nil {
		return artifact.ErrDownloadUnavailable
	}
	return t.transfer(ctx, reader, request, source, destination, auditor)
}
func (t DownloadResponseTransfer) transfer(ctx context.Context, reader identities.ReaderIdentity, request DownloadResponseRequest, source NativeResponseSource, destination DownloadResponseSinkFactory, auditor DownloadContentAuditor) (err error) {
	if !t.valid() || ctx == nil || reader == nil || source == nil || destination == nil || !authorization.UUID(request.SessionID) || !authorization.UUID(request.ResponseID) || !authorization.UUID(request.OwnerID) || !t.Now().Before(request.HardUntil) || request.HardUntil.After(t.Now().Add(8*time.Hour)) {
		return artifact.ErrInvalid
	}
	defer reader.Close()
	defer source.Close()
	work, cancel := context.WithDeadline(ctx, request.HardUntil)
	defer cancel()
	first, e := reader.BeginBatch(work)
	if e != nil {
		return e
	}
	current := responseCurrent{reader: reader, authority: t.Authority, batch: first, now: t.Now}
	defer current.close()
	i, e := first.ResolveIdentity(work)
	if e != nil {
		return e
	}
	preflightWork := work
	var preflight DownloadContentAudit
	finished := false
	initial := i
	if auditor != nil {
		original := identityvalue.Earlier(i.ValidUntil, t.Now().Add(artifact.DownloadLease))
		call, end := context.WithDeadline(work, original)
		defer end()
		preflightWork = call
		preflight, e = auditor.BeginDownloadContent(call, first, request)
		if e != nil || preflight == nil {
			return artifact.ErrDownloadUnavailable
		}
		defer preflight.Close()
		if !t.Now().Before(preflight.Deadline()) || preflight.Deadline().After(original) {
			return artifact.ErrDownloadUnavailable
		}
		bounded, end := context.WithDeadline(call, preflight.Deadline())
		defer end()
		preflightWork = bounded
	}
	finishPreflight := func(status DownloadContentStatus) error {
		if finished {
			return artifact.ErrDownloadConflict
		}
		finished = true
		if preflight == nil {
			return nil
		}
		until, e := preflight.Finish(preflightWork, status)
		if e != nil || preflightWork.Err() != nil || !t.Now().Before(until) || until.After(preflight.Deadline()) {
			return artifact.ErrDownloadUnavailable
		}
		fresh, e := first.ResolveIdentity(preflightWork)
		if e != nil || !downloadSameIdentity(initial, fresh, t.Now()) {
			return artifact.ErrDownloadUnavailable
		}
		until = identityvalue.Earlier(until, fresh.ValidUntil)
		if current.scope.Valid() {
			checked, e := t.Authority.CheckDownloadCurrent(preflightWork, first, current.scope)
			if e != nil || !checked.Valid(t.Now()) || checked.Scope != current.scope {
				return artifact.ErrDownloadUnavailable
			}
			until = identityvalue.Earlier(until, checked.ValidUntil)
			current.value = checked
		}
		if preflightWork.Err() != nil || !t.Now().Before(until) {
			return artifact.ErrDownloadExpired
		}
		if receive, ok := destination.(DownloadContentPreflightReceiver); ok {
			receive.DownloadContentPreflightComplete(until)
		}
		preflight.Close()
		return nil
	}
	defer func() {
		if !finished {
			if e := finishPreflight(contentStatus(err)); e != nil {
				err = e
			}
		}
	}()
	// Intent acknowledgement may block across revocation or a shorter identity
	// observation. Do not perform even the protected session lookup afterward.
	if preflight != nil {
		fresh, checkErr := first.ResolveIdentity(preflightWork)
		if checkErr != nil || preflightWork.Err() != nil || !downloadSameIdentity(initial, fresh, t.Now()) {
			return artifact.ErrDownloadUnavailable
		}
		i = fresh
	}
	session, e := t.Sessions.LookupDownload(preflightWork, request.SessionID, i.Principal)
	if e != nil {
		return e
	}
	if !session.Valid() || session.Scope.Principal != i.Principal {
		return artifact.ErrDownloadUnavailable
	}
	current.scope = session.Scope
	// get must authorize even though the ingress batch already exists.
	a, e := t.Authority.CheckDownloadCurrent(preflightWork, first, session.Scope)
	if e != nil {
		return e
	}
	i, e = first.ResolveIdentity(preflightWork)
	if e != nil {
		return e
	}
	a.ValidUntil = identityvalue.Earlier(a.ValidUntil, i.ValidUntil)
	if !a.Valid(t.Now()) || a.Scope != session.Scope || i.Principal != session.Scope.Principal {
		return artifact.ErrDownloadExpired
	}
	current.value = a
	until := identityvalue.Earlier(request.HardUntil, identityvalue.Earlier(session.Deadline, a.AccessUntil))
	work, cancelResponse := context.WithDeadline(work, until)
	defer cancelResponse()
	describe, stop := context.WithDeadline(preflightWork, a.ValidUntil)
	var metadata artifact.NativeDownloadMetadata
	var readLimit int64
	if remote, ok := source.(CurrentNativeResponseSource); ok {
		metadata, readLimit, e = remote.DescribeCurrent(describe, current.batch, session, a)
	} else {
		metadata, readLimit, e = source.Describe(describe, session, a)
	}
	stop()
	if e != nil {
		return e
	}
	if !a.Valid(t.Now()) || work.Err() != nil || metadata.Size < 0 || metadata.Size > artifact.MaxNativeBytes || metadata.SHA256 == (artifact.Digest{}) || metadata.ETag == "" || metadata.Filename == "" || !metadata.ReadUntil.After(t.Now()) || metadata.ReadUntil.After(a.AccessUntil) || metadata.DeleteBy.After(a.DeleteBy) || !metadata.ReadUntil.Before(metadata.DeleteBy) {
		return artifact.ErrDownloadUnavailable
	}
	until = identityvalue.Earlier(until, metadata.ReadUntil)
	selection, e := destination.SelectDownloadResponse(metadata)
	if e != nil {
		return e
	}
	if selection.Offset < 0 || selection.Length < 0 || selection.Offset > metadata.Size || selection.Length > metadata.Size-selection.Offset || !selection.Partial && (selection.Offset != 0 || selection.Length != metadata.Size) {
		return artifact.ErrInvalid
	}
	plan := artifact.DownloadResponsePlan{Version: artifact.DownloadResponseVersion, Selection: selection, WholeFile: selection.Offset == 0 && selection.Length == metadata.Size, WindowReadLimit: readLimit}
	if !plan.Valid() {
		return artifact.ErrInvalid
	}
	if e = finishPreflight(DownloadContentReady); e != nil {
		return e
	}
	// End the socket's short metadata phase before waiting for a fresh body
	// observation. The original response/caller/retention end bounds this idle
	// phase; every actual write still requires its separate current byte lease.
	until = identityvalue.Earlier(until, current.value.AccessUntil)
	if d, ok := work.Deadline(); ok {
		until = identityvalue.Earlier(until, d)
	}
	if receive, ok := destination.(DownloadContentBodyReceiver); ok {
		if e = receive.BeginDownloadContentBody(work, until); e != nil {
			return e
		}
	}
	// Metadata observation has positively joined. Its verified immutable facts
	// remain usable, but its initial identity lease may be nearly exhausted.
	// Close it before admitting content and acquire a distinct current batch;
	// neither the old observation nor Describe is renewed or replayed.
	current.close()
	a, e = current.get(work)
	if e != nil {
		return e
	}
	metadata.ReadUntil = identityvalue.Earlier(metadata.ReadUntil, a.AccessUntil)
	metadata.DeleteBy = identityvalue.Earlier(metadata.DeleteBy, a.DeleteBy)
	until = identityvalue.Earlier(until, metadata.ReadUntil)
	if !t.Now().Before(until) || !metadata.ReadUntil.Before(metadata.DeleteBy) || work.Err() != nil {
		return artifact.ErrDownloadExpired
	}
	work, stopContent := context.WithDeadline(work, until)
	defer stopContent()
	r, e := t.Responses.BeginDownloadResponse(work, session.ID, a, artifact.DownloadResponse{ID: request.ResponseID, SessionID: session.ID, OwnerID: request.OwnerID, Plan: plan, Until: until})
	if e != nil {
		return e
	}
	if !r.Valid() || r.Plan != plan || r.ID != request.ResponseID || r.SessionID != session.ID || r.OwnerID != request.OwnerID || r.Until.After(until) {
		return artifact.ErrIntegrity
	}
	current.response = identityvalue.RefreshResponseBinding{DownloadID: session.ID, ResponseID: r.ID, ResponseOwnerID: r.OwnerID, ResponseGeneration: r.Generation}
	// Always join writes before closing the durable response. Cleanup only closes
	// this exact owner; an unknown close reply never releases accounting credit.
	defer func() {
		source.Close()
		current.close()
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		closeErr := t.Responses.CloseDownloadResponse(cleanup, session.ID, r.ID, r.OwnerID)
		if err == nil {
			err = closeErr
		}
	}()
	sink, e := destination.OpenDownloadResponse(work, metadata, r)
	if e != nil {
		return e
	}
	defer sink.Close()
	fullHash := sha256.New()
	offset := selection.Offset
	for ordinal := int64(1); ordinal <= plan.Windows(); ordinal++ {
		a, e = current.get(work)
		if e != nil {
			return e
		}
		windowID := t.NewID()
		if !authorization.UUID(windowID) {
			return artifact.ErrInvalid
		}
		intent, e := t.Responses.BeginDownloadWindow(work, session.ID, r.ID, r.OwnerID, windowID, a)
		if e != nil {
			return e
		}
		if !intent.Valid() || intent.Response.ID != r.ID || intent.Window.Ordinal != ordinal || intent.Window.Offset != offset || intent.Window.Authority.Scope != session.Scope {
			return artifact.ErrIntegrity
		}
		result, e := t.Objects.CreateDownloadWindowIntent(work, intent)
		if e != nil {
			return e
		}
		if e = t.Audit.AcknowledgeDownloadWindowIntent(work, intent, result); e != nil {
			return e
		}
		var emitted, readWork int64
		var lease artifact.DownloadDeliveryLease
		verified := false
		transferErr := func() error {
			for emitted < intent.Window.Length || intent.Window.Length == 0 && lease.Sequence == 0 {
				a, e = current.get(work)
				if e != nil {
					return e
				}
				if !lease.Valid(t.Now()) {
					lease, e = t.Responses.LeaseDownloadResponse(work, session.ID, r.ID, r.OwnerID, windowID, a)
					if e != nil {
						return e
					}
					if !lease.Valid(t.Now()) || lease.ResponseID != r.ID || lease.WindowID != windowID || lease.OwnerID != r.OwnerID || lease.Generation != r.Generation || lease.Authority.Scope != session.Scope || lease.Until.After(a.ValidUntil) {
						return artifact.ErrIntegrity
					}
				}
				length := min(artifact.DeliveryBytes, intent.Window.Length-emitted)
				piece, stop := context.WithDeadline(work, lease.Until)
				var chunk NativeResponseChunk
				var e error
				if remote, ok := source.(CurrentNativeResponseSource); ok {
					chunk, e = remote.ReadChunkCurrent(piece, current.batch, lease, offset, length)
				} else {
					chunk, e = source.ReadChunk(piece, lease, offset, length)
				}
				if e != nil {
					clear(chunk.Bytes)
					stop()
					return e
				}
				if int64(len(chunk.Bytes)) != length || chunk.ReadWork < 0 || chunk.ReadWork > intent.Window.ReadLimit-readWork || !lease.Allows(offset, length, t.Now()) || piece.Err() != nil {
					clear(chunk.Bytes)
					stop()
					return artifact.ErrIntegrity
				}
				readWork += chunk.ReadWork
				final := offset+length == selection.Offset+selection.Length
				if plan.WholeFile {
					_, _ = fullHash.Write(chunk.Bytes)
				}
				if final && (!chunk.FinalVerified || plan.WholeFile && artifact.Digest(fullHash.Sum(nil)) != metadata.SHA256) {
					clear(chunk.Bytes)
					stop()
					return artifact.ErrIntegrity
				}
				n, writeErr := sink.WriteChunk(piece, lease, offset, chunk.Bytes)
				clear(chunk.Bytes)
				if n < 0 || n > length {
					stop()
					return artifact.ErrIntegrity
				}
				emitted += n
				offset += n
				if writeErr == nil && (n != length || piece.Err() != nil || !lease.Valid(t.Now())) {
					writeErr = artifact.ErrDownloadExpired
				}
				if writeErr == nil {
					if remote, ok := source.(NativeResponseDeliveryAcknowledger); ok {
						writeErr = remote.AcknowledgeNativeChunk(piece, lease, offset-n, n)
						if writeErr == nil && (piece.Err() != nil || !lease.Valid(t.Now())) {
							writeErr = artifact.ErrDownloadExpired
						}
					}
				}
				stop()
				if writeErr != nil {
					return writeErr
				}
				verified = final && chunk.FinalVerified
			}
			return nil
		}()
		// Historical outcome only: joined read/write results can be audited even
		// after cancellation. This does not admit more bytes or refresh identity.
		auditCtx, stop := context.WithDeadline(context.WithoutCancel(ctx), identityvalue.Earlier(intent.Window.WriteUntil, t.Now().Add(5*time.Second)))
		outcome, recordErr := t.Responses.FinishDownloadWindow(auditCtx, intent, artifact.DownloadWindowOutcome{EmittedBytes: emitted, Success: transferErr == nil, VerifiedFinal: verified && transferErr == nil})
		if recordErr == nil {
			var result audit.DownloadWindowWriteResult
			result, recordErr = t.Objects.CreateDownloadWindowOutcome(auditCtx, outcome)
			if recordErr == nil {
				recordErr = t.Audit.AcknowledgeDownloadWindowOutcome(auditCtx, outcome, result)
			}
		}
		stop()
		if transferErr != nil {
			return transferErr
		}
		if recordErr != nil {
			return recordErr
		}
	}
	if offset != selection.Offset+selection.Length {
		return artifact.ErrIntegrity
	}
	// No further bytes; final outcome acknowledgement already gates Completed.
	if e = sink.Finish(work); e != nil {
		return e
	}
	return nil
}
