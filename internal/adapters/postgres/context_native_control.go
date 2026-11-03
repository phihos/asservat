package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"time"
)

// Native responses use one conversation per bounded transfer window.
// Each positively joined conversation costs one claim/replacement and one
// close; final independently confirmed worker retirement costs another update.
// An unknown close never refunds either allowance or establishes quiescence.
const (
	firstContextObserveTransitions    int64 = 2
	firstContextContentTransitions    int64 = 2
	firstContextRetirementTransitions int64 = 1
)

type contextNativeControl struct {
	nativeBusy, responseBusy, uncertain bool
	remaining                           int64
}

func (c contextNativeControl) canObserve(outputRemaining int64) bool {
	// Before metadata is observed, reserve for the largest supported response
	// that the remaining session output could cover. No native size enters SQL.
	if outputRemaining < 0 {
		return false
	}
	windows := max(int64(1), (min(outputRemaining, artifact.MaxGoTraceBytes)+artifact.DownloadWindowBytes-1)/artifact.DownloadWindowBytes)
	return !c.uncertain && !c.nativeBusy && !c.responseBusy && c.remaining >= firstContextObserveTransitions+windows*firstContextContentTransitions+firstContextRetirementTransitions
}

func (c contextNativeControl) canRespond(plan artifact.DownloadResponsePlan) bool {
	return plan.Valid() && plan.Selection.Length <= artifact.MaxGoTraceBytes && plan.Selection.Offset <= artifact.MaxGoTraceBytes-plan.Selection.Length && !c.uncertain && !c.nativeBusy && !c.responseBusy && c.remaining >= plan.Windows()*firstContextContentTransitions+firstContextRetirementTransitions
}

// This is eligibility for another bounded attempt, not proof that the remote
// worker received the final marker. The next exact fresh Hello still precedes
// key/read effects. A local close, emitted byte count or unacknowledged result
// cannot establish even that eligibility after an attempted first-context read.
func firstContextResponseOutcome(r artifact.DownloadResponse, windows []artifact.DownloadWindow) bool {
	count := r.Plan.Windows()
	if !r.Valid() || !r.Closed || r.Plan.Selection.Length > artifact.MaxGoTraceBytes || r.Plan.Selection.Offset > artifact.MaxGoTraceBytes-r.Plan.Selection.Length || count < 1 || count > 2 || r.WindowCount != count || r.CompletedWindows != count || r.ActiveWindowID != "" || r.EmittedBytes != r.Plan.Selection.Length || int64(len(windows)) != count {
		return false
	}
	offset, remaining := r.Plan.Selection.Offset, r.Plan.Selection.Length
	seen := make(map[string]bool, len(windows))
	for i, w := range windows {
		length := min(artifact.DownloadWindowBytes, remaining)
		final := int64(i)+1 == count
		if !w.Valid() || seen[w.ID] || w.ResponseID != r.ID || w.SessionID != r.SessionID || w.OwnerID != r.OwnerID || w.Generation != r.Generation || w.Ordinal != int64(i)+1 || w.Offset != offset || w.Length != length || !w.IntentAcknowledged || !w.OutcomeAcknowledged || w.Outcome == nil || !w.Outcome.Success || w.Outcome.VerifiedFinal != final || w.Outcome.EmittedBytes != length {
			return false
		}
		seen[w.ID] = true
		offset += length
		remaining -= length
	}
	return remaining == 0
}

// Call only while holding the original session lock. This is a minimized
// availability observation; NativeOwners still enforces all current effect
// checks and exact immutable operation bindings. Expiry is not a joined close.
func readContextNativeControl(ctx context.Context, q *custodydb.Queries, s artifact.DownloadSession, worker string) (contextNativeControl, error) {
	var out contextNativeControl
	row, e := q.ReadSessionNativeBacking(ctx, custodydb.ReadSessionNativeBackingParams{ID: id(s.ID), RootID: id(s.Scope.RootID)})
	if e != nil {
		return out, e
	}
	backing, e := effectiveSessionNativeBacking(row, s)
	if e != nil {
		return out, e
	}
	var policy value.NativeBacking
	if json.Unmarshal(backing.PolicyJson, &policy) != nil || !policy.Valid() || policy.AllocationID != s.AllocationID || policy.RootID != s.Scope.RootID || policy.Rows != backing.RowsLimit || policy.Keys != backing.KeysLimit || policy.TransitionsPerRow != backing.TransitionsPerRow || policy.BackupHorizonSeconds != backing.BackupHorizonSeconds || policy.CleanupSeconds != backing.CleanupSeconds || !policy.ValidUntil.Equal(backing.ValidUntil.Time) || !policy.RetireBy.Equal(backing.RetireBy.Time) || backing.Overdue || !time.Now().Before(policy.ValidUntil) {
		return out, artifact.ErrDownloadUnavailable
	}
	out.remaining = policy.TransitionsPerRow
	native, e := q.ReadNativeOwner(ctx, custodydb.ReadNativeOwnerParams{WorkerID: id(worker), RootID: id(s.Scope.RootID)})
	if e == nil {
		operation, authority, e := decodeNativeOwner(native)
		if e != nil || operation.Reference.SessionID != s.ID || operation.Reference.WorkerID != worker || authority.Scope != s.Scope || native.AllocationID != id(s.AllocationID) || native.Updates < 1 || native.Updates > policy.TransitionsPerRow || native.RetiredAt.Valid {
			return out, artifact.ErrDownloadUnavailable
		}
		out.nativeBusy = !native.Closed
		out.uncertain = out.nativeBusy && !time.Now().Before(native.LeaseUntil.Time)
		out.remaining -= native.Updates
	} else if !errors.Is(e, pgx.ErrNoRows) {
		return out, e
	}
	response, e := q.CurrentDownloadResponse(ctx, custodydb.CurrentDownloadResponseParams{SessionID: id(s.ID), RootID: id(s.Scope.RootID)})
	if e == nil {
		actual, e := decodeResponse(response)
		if e != nil || actual.SessionID != s.ID {
			return out, artifact.ErrDownloadUnavailable
		}
		out.responseBusy = !actual.Closed
		out.uncertain = out.uncertain || (out.responseBusy && !time.Now().Before(actual.LeaseUntil))
		if actual.Closed {
			rows, err := q.ReadFirstContextResponseWindows(ctx, custodydb.ReadFirstContextResponseWindowsParams{ResponseID: id(actual.ID), SessionID: id(s.ID)})
			if err != nil {
				return out, err
			}
			windows := make([]artifact.DownloadWindow, 0, len(rows))
			for _, row := range rows {
				_, window, err := decodeWindow(row)
				if err != nil || window.Authority.Scope != s.Scope {
					return out, artifact.ErrDownloadUnavailable
				}
				windows = append(windows, window)
			}
			out.uncertain = out.uncertain || !firstContextResponseOutcome(actual, windows)
		}
	} else if !errors.Is(e, pgx.ErrNoRows) {
		return out, e
	}
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	return out, nil
}

// These private composition adapters add the first-context coexistence check,
// without changing generic native or intentional response retry semantics.
type FirstContextNativeOperations struct{ *NativeOwners }

func NewFirstContextNativeOperations(s *NativeOwners) (*FirstContextNativeOperations, error) {
	if s == nil || s.workers == nil {
		return nil, artifact.ErrInvalid
	}
	return &FirstContextNativeOperations{s}, nil
}
func (*FirstContextNativeOperations) FirstContextObservationsOnly() {}
func (s *FirstContextNativeOperations) ClaimNativeOperation(ctx context.Context, en value.WorkerEnrollment, a artifact.DownloadAuthority, o value.NativeOperation) (value.NativeOperation, error) {
	if s == nil || s.NativeOwners == nil {
		return value.NativeOperation{}, artifact.ErrInvalid
	}
	return s.NativeOwners.claimNativeOperation(ctx, en, a, o, true)
}

var _ evidence.NativeOperations = (*FirstContextNativeOperations)(nil)

type FirstContextResponses struct{ *Downloads }

func NewFirstContextResponses(s *Downloads) (*FirstContextResponses, error) {
	if s == nil || s.ledger == nil {
		return nil, artifact.ErrInvalid
	}
	return &FirstContextResponses{s}, nil
}
func (*FirstContextResponses) FirstContextResponsesOnly() {}
func (s *FirstContextResponses) BeginDownloadResponse(ctx context.Context, sessionID string, a artifact.DownloadAuthority, r artifact.DownloadResponse) (artifact.DownloadResponse, error) {
	if s == nil || s.Downloads == nil {
		return artifact.DownloadResponse{}, artifact.ErrInvalid
	}
	return s.Downloads.beginDownloadResponse(ctx, sessionID, a, r, true)
}

var _ evidence.DownloadResponses = (*FirstContextResponses)(nil)
