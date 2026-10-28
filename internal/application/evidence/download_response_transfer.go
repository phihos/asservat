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
	"errors"
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
	// Bootstrap supplies an exact-response ordinary-entitlement owner. Other
	// authority implementations retain their existing fresh-check behavior.
	NewResponseAuthority func(context.Context, artifact.DownloadScope) (CurrentDownloadAuthority, func(), error)
}

func (t DownloadResponseTransfer) valid() bool {
	return t.Sessions != nil && t.Responses != nil && t.Authority != nil && t.Objects != nil && t.Audit != nil && t.Now != nil && t.NewID != nil
}

type responseCurrent struct {
	reader       identities.ReaderIdentity
	authority    CurrentDownloadAuthority
	batch        identities.IdentityBatch
	scope        artifact.DownloadScope
	value        artifact.DownloadAuthority
	now          func() time.Time
	endAuthority func()
}

func (c *responseCurrent) close() {
	c.closeBatch()
	if c.endAuthority != nil {
		c.endAuthority()
		c.endAuthority = nil
	}
}
func (c *responseCurrent) closeBatch() {
	if c.batch != nil {
		c.batch.Close()
		c.batch = nil
	}
}

// localWriteMargin is the least lease time a local source's chunk write starts
// with (ADR-244): a 1 MiB write then needs a client of at least 0.5 MiB/s.
const localWriteMargin = 2 * time.Second

func (c *responseCurrent) get(ctx context.Context) (artifact.DownloadAuthority, error) {
	return c.fresh(ctx, 0)
}

// fresh returns the current authority, observing it again when the retained
// one has less than margin left.
func (c *responseCurrent) fresh(ctx context.Context, margin time.Duration) (artifact.DownloadAuthority, error) {
	if ctx.Err() != nil {
		return artifact.DownloadAuthority{}, ctx.Err()
	}
	if c.batch != nil && c.value.Valid(c.now()) && c.now().Add(margin).Before(c.value.ValidUntil) {
		return c.value, nil
	}
	c.closeBatch()
	b, e := c.begin(ctx)
	if e != nil {
		return artifact.DownloadAuthority{}, e
	}
	c.batch = b
	a, e := c.authority.CheckDownloadCurrent(ctx, b, c.scope)
	if e != nil {
		c.closeBatch()
		return artifact.DownloadAuthority{}, e
	}
	i, e := b.ResolveIdentity(ctx)
	if e != nil || i.Principal != c.scope.Principal {
		c.closeBatch()
		return artifact.DownloadAuthority{}, artifact.ErrDownloadUnavailable
	}
	a.ValidUntil = identityvalue.Earlier(a.ValidUntil, i.ValidUntil)
	if !a.Valid(c.now()) || a.Scope != c.scope || ctx.Err() != nil {
		c.closeBatch()
		return artifact.DownloadAuthority{}, artifact.ErrDownloadExpired
	}
	c.value = a
	return a, nil
}

// sessionBusyWait bounds how long a response waits, with no output, while
// another request (normally the console tab) finishes refreshing the same
// browser session. Nothing is refreshed here.
const sessionBusyWait = 2 * time.Second

// begin starts the next identity batch. A session that is only busy is retried
// until it reads current again, for at most sessionBusyWait and never past the
// original deadline in ctx; then it fails closed with the busy error.
func (c *responseCurrent) begin(ctx context.Context) (identities.IdentityBatch, error) {
	b, e := c.reader.BeginBatch(ctx)
	if !errors.Is(e, identityvalue.ErrSessionBusy) {
		return b, e
	}
	wait, stop := context.WithTimeout(ctx, sessionBusyWait)
	defer stop()
	retry := time.NewTicker(100 * time.Millisecond)
	defer retry.Stop()
	for {
		select {
		case <-wait.Done():
			return nil, e
		case <-retry.C:
		}
		b, e = c.reader.BeginBatch(ctx)
		if !errors.Is(e, identityvalue.ErrSessionBusy) {
			return b, e
		}
	}
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
		return stepped("request", artifact.ErrInvalid)
	}
	// Every refusal names its closed stage for the operator report; the
	// wrapper unwraps unchanged and runs after every other deferred close.
	stage := "identity"
	defer func() { err = stepped(stage, err) }()
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
		stage = "preflight-audit"
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
			checked, e := current.authority.CheckDownloadCurrent(preflightWork, first, current.scope)
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
	stage = "session"
	session, e := t.Sessions.LookupDownload(preflightWork, request.SessionID, i.Principal)
	if e != nil {
		return e
	}
	if !session.Valid() || session.Scope.Principal != i.Principal {
		return artifact.ErrDownloadUnavailable
	}
	current.scope = session.Scope
	stage = "authority"
	if t.NewResponseAuthority != nil {
		owned, close, err := t.NewResponseAuthority(work, session.Scope)
		if err != nil || owned == nil || close == nil {
			if close != nil {
				close()
			}
			return artifact.ErrDownloadUnavailable
		}
		current.authority, current.endAuthority = owned, close
	}
	// get must authorize even though the ingress batch already exists.
	a, e := current.authority.CheckDownloadCurrent(preflightWork, first, session.Scope)
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
	stage = "describe"
	describe, stop := context.WithDeadline(preflightWork, a.ValidUntil)
	var metadata artifact.NativeDownloadMetadata
	var readLimit int64
	if native, ok := source.(*ContextNativeResponse); ok {
		metadata, readLimit, e = native.describeChecked(describe, current.batch, session, a)
	} else if remote, ok := source.(CurrentNativeResponseSource); ok {
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
	stage = "select"
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
	stage = "preflight-finish"
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
	stage = "body"
	if receive, ok := destination.(DownloadContentBodyReceiver); ok {
		if e = receive.BeginDownloadContentBody(work, until); e != nil {
			return e
		}
	}
	// Metadata observation has positively joined. Its verified immutable facts
	// remain usable, but its initial identity lease may be nearly exhausted.
	// Close it before admitting content and acquire a distinct current batch;
	// neither the old observation nor Describe is renewed or replayed.
	current.closeBatch()
	stage = "current"
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
	stage = "response"
	r, e := t.Responses.BeginDownloadResponse(work, session.ID, a, artifact.DownloadResponse{ID: request.ResponseID, SessionID: session.ID, OwnerID: request.OwnerID, Plan: plan, Until: until})
	if e != nil {
		return e
	}
	if !r.Valid() || r.Plan != plan || r.ID != request.ResponseID || r.SessionID != session.ID || r.OwnerID != request.OwnerID || r.Until.After(until) {
		return artifact.ErrIntegrity
	}
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
	stage = "open"
	sink, e := destination.OpenDownloadResponse(work, metadata, r)
	if e != nil {
		return e
	}
	defer sink.Close()
	fullHash := sha256.New()
	offset := selection.Offset
	for ordinal := int64(1); ordinal <= plan.Windows(); ordinal++ {
		stage = "window-current"
		a, e = current.get(work)
		if e != nil {
			return e
		}
		windowID := t.NewID()
		if !authorization.UUID(windowID) {
			return artifact.ErrInvalid
		}
		stage = "window"
		intent, e := t.Responses.BeginDownloadWindow(work, session.ID, r.ID, r.OwnerID, windowID, a)
		if e != nil {
			return e
		}
		if !intent.Valid() || intent.Response.ID != r.ID || intent.Window.Ordinal != ordinal || intent.Window.Offset != offset || intent.Window.Authority.Scope != session.Scope {
			return artifact.ErrIntegrity
		}
		stage = "window-audit"
		result, e := t.Objects.CreateDownloadWindowIntent(work, intent)
		if e != nil {
			return e
		}
		stage = "window-ack"
		if e = t.Audit.AcknowledgeDownloadWindowIntent(work, intent, result); e != nil {
			return e
		}
		var emitted, readWork int64
		var lease artifact.DownloadDeliveryLease
		verified := false
		transferErr := func() error {
			for emitted < intent.Window.Length || intent.Window.Length == 0 && lease.Sequence == 0 {
				stage = "chunk-current"
				a, e = current.fresh(work, localWriteMargin)
				if e != nil {
					return e
				}
				if !lease.Valid(t.Now()) || t.Now().Add(localWriteMargin).After(lease.Until) {
					stage = "lease"
					lease, e = t.Responses.LeaseDownloadResponse(work, session.ID, r.ID, r.OwnerID, windowID, a)
					if e != nil {
						return e
					}
					if !lease.Valid(t.Now()) || lease.ResponseID != r.ID || lease.WindowID != windowID || lease.OwnerID != r.OwnerID || lease.Generation != r.Generation || lease.Authority.Scope != session.Scope || lease.Until.After(a.ValidUntil) {
						return artifact.ErrIntegrity
					}
				}
				length := min(artifact.DeliveryBytes, intent.Window.Length-emitted)
				stage = "read"
				piece, stop := context.WithDeadline(work, lease.Until)
				var chunk NativeResponseChunk
				var e error
				local := false
				if native, ok := source.(*ContextNativeResponse); ok {
					chunk, e = native.readChunkChecked(piece, current.batch, lease, offset, length)
				} else if remote, ok := source.(CurrentNativeResponseSource); ok {
					chunk, e = remote.ReadChunkCurrent(piece, current.batch, lease, offset, length)
				} else {
					chunk, e = source.ReadChunk(piece, lease, offset, length)
					local = true
				}
				if e != nil {
					clear(chunk.Bytes)
					stop()
					return e
				}
				// ADR-244: a local multi-frame source may need longer than the
				// rest of the lease to authenticate its next 8 MiB frame, and a
				// 1 MiB socket write needs time under client backpressure. Reading
				// discloses nothing; a chunk is written only under a lease with at
				// least localWriteMargin left, renewed with fresh current authority
				// when shorter, or cleared. Remote sources keep their chunk
				// acknowledgement bound to the original lease.
				if local && t.Now().Add(localWriteMargin).After(lease.Until) && work.Err() == nil {
					stop()
					stage = "lease"
					if a, e = current.fresh(work, localWriteMargin); e == nil {
						lease, e = t.Responses.LeaseDownloadResponse(work, session.ID, r.ID, r.OwnerID, windowID, a)
					}
					if e == nil && (!lease.Valid(t.Now()) || lease.ResponseID != r.ID || lease.WindowID != windowID || lease.OwnerID != r.OwnerID || lease.Generation != r.Generation || lease.Authority.Scope != session.Scope || lease.Until.After(a.ValidUntil)) {
						e = artifact.ErrIntegrity
					}
					// A renewal that still cannot give the margin (for example an
					// identity about to expire) writes nothing: the client resumes.
					if e == nil && t.Now().Add(localWriteMargin).After(lease.Until) {
						e = artifact.ErrDownloadExpired
					}
					if e != nil {
						clear(chunk.Bytes)
						return e
					}
					piece, stop = context.WithDeadline(work, lease.Until)
				}
				// The exact remote chunk may end before the human lease (worker
				// token/certificate/operation cutoff). Preserve it through the final sink
				// and its ACK, without replacing or extending the SQL delivery lease.
				if !chunk.NativeUntil.IsZero() {
					stop()
					piece, stop = context.WithDeadline(work, identityvalue.Earlier(lease.Until, chunk.NativeUntil))
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
				stage = "write"
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
						stage = "chunk-ack"
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
			stage = "window-outcome"
			return recordErr
		}
	}
	stage = "finish"
	if offset != selection.Offset+selection.Length {
		return artifact.ErrIntegrity
	}
	// No further bytes; final outcome acknowledgement already gates Completed.
	if e = sink.Finish(work); e != nil {
		return e
	}
	stage = "close"
	return nil
}
