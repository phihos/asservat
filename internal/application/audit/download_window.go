package audit

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"context"
	"crypto/sha256"
	"encoding/json"
)

// Creation is called only after an acknowledged first ledger reservation. An
// unknown result never creates again. Find is read-only and cannot claim joined
// writer closure or authorize lifecycle credit release.
type DownloadWindowObjects interface {
	CreateDownloadWindowIntent(context.Context, audit.DownloadWindowIntent) (audit.DownloadWindowWriteResult, error)
	FindDownloadWindowIntent(context.Context, audit.DownloadWindowIntent) (audit.Receipt, error)
	CreateDownloadWindowOutcome(context.Context, audit.DownloadWindowAuditOutcome) (audit.DownloadWindowWriteResult, error)
	FindDownloadWindowOutcome(context.Context, audit.DownloadWindowAuditOutcome) (audit.Receipt, error)
}

func DownloadWindowRecordDigest(i audit.DownloadWindowIntent, o *audit.DownloadWindowAuditOutcome) artifact.Digest {
	if !i.Valid() || o != nil && (!o.Valid() || o.Intent != i) {
		return artifact.Digest{}
	}
	var value any = i
	if o != nil {
		value = *o
	}
	b, e := json.Marshal(value)
	if e != nil {
		return artifact.Digest{}
	}
	return sha256.Sum256(b)
}

// Record equality is an application cryptographic fact, not domain authority.
func ValidDownloadWindowCompletion(c audit.DownloadWindowWriteCompletion, i audit.DownloadWindowIntent, o *audit.DownloadWindowAuditOutcome) bool {
	return c.Valid(i, o) && c.RecordDigest == DownloadWindowRecordDigest(i, o)
}
