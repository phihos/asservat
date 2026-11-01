package fleet

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/capture"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"time"
)

// History work reuses the installed work signing key and current trust source,
// with a distinct signed purpose and an independently checked effect authority.
type HistoryWorkSigner interface {
	SignHistoryWork(context.Context, HistoryWork) ([]byte, error)
}
type HistoryWorkVerifier interface {
	VerifyHistoryWork(context.Context, []byte, value.APIContextReceiver) (AuthenticatedHistoryWork, error)
}

// HistoryWork binds one separately authorized control-metadata effect to the
// actual retained hub/connector conversation. It is never an API execution.
type HistoryWork struct {
	Channel   value.APIContextChannel
	Authority capture.HistoryOperationAuthority
}

func (w HistoryWork) Valid(now time.Time) bool {
	e := w.Authority.Expectation
	return w.Channel.Valid() && w.Authority.Valid(now) && w.Authority.ExecutorEpoch == w.Channel.Executor.ProcessEpoch && w.Channel.RootID == e.RootID && w.Channel.Connector.Binding.ClusterID == e.Registration.Location.ClusterID
}
func (w HistoryWork) Matches(r value.APIContextReceiver, now time.Time) bool {
	return w.Valid(now) && r.Valid(now) && w.Channel == r.Channel
}

type AuthenticatedHistoryWork struct {
	Work                   HistoryWork
	KeyID                  string
	TrustRevision          identity.Revision
	VerifiedAt, ValidUntil time.Time
}

func (w AuthenticatedHistoryWork) Valid(now time.Time) bool {
	return w.Work.Valid(now) && identity.Text(w.KeyID, 128) && w.TrustRevision.Valid() && identity.Fresh(w.VerifiedAt, w.ValidUntil, now, 5*time.Second) && !w.ValidUntil.After(w.Work.Authority.NotAfter)
}

// HistoryReply contains encrypted control metadata and exact storage receipts;
// no native evidence, plaintext parameters or wrapping roots cross this channel.
type HistoryReply struct {
	Bundle           capture.HistoryCiphertexts
	Copies           artifact.Copies
	WriterCompletion *capture.HistoryWriterCompletion
	DeleteCompletion *capture.HistoryDeleteCompletion
}

// HistorySession owns one selected real connector conversation. Its original
// bound and executor epoch are pinned into the SQL-issued operation before send.
type HistorySession interface {
	ExecutorEpoch() string
	NotAfter() time.Time
	ExecuteHistory(context.Context, capture.HistoryOperationAuthority, capture.HistoryCiphertexts, artifact.Copies) (HistoryReply, error)
	Close()
}
type HistoryDispatcher interface {
	PrepareHistory(context.Context, string, string) (HistorySession, error)
}

// HistoryCopiesMatch accepts no receipts only for independently authorized
// inventory cleanup after the original writer interval. The SQL producer must
// separately prove that no write claim was issued; timing alone is no permit.
func HistoryCopiesMatch(a capture.HistoryOperationAuthority, c artifact.Copies) bool {
	if capture.HistoryCopiesDigest(c) != a.CopiesDigest {
		return false
	}
	if c == (artifact.Copies{}) {
		return a.Operation == "purge" && !a.StartedAt.Before(a.Expectation.Registration.WriteUntil)
	}
	return c.Validate(a.Expectation.Registration) == nil
}
