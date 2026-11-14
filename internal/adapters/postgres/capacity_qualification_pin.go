package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// CapacityQualificationPin is the current capacity qualification the hub-api
// binds its audit profile reads to, with the capture lane's audit policy.
type CapacityQualificationPin struct {
	QualificationID     string          `json:"qualificationID"`
	QualificationDigest string          `json:"qualificationDigest"`
	AccountVersion      string          `json:"accountVersion"`
	CapturePolicy       json.RawMessage `json:"capturePolicy"`
	// OperationRetentionSeconds is the shorter retention of the normal and
	// resolution operation-audit lanes.
	OperationRetentionSeconds int64 `json:"operationRetentionSeconds"`
	// EvidenceStoreID is the one qualified backend's evidence store, the
	// store hub-local download workers read (empty with another layout).
	EvidenceStoreID string `json:"evidenceStoreID,omitempty"`
}

// ErrCapacityQualificationPin reports that no capacity qualification exists
// yet (the hub-worker initializes it) or that it is malformed.
var ErrCapacityQualificationPin = errors.New("capacity qualification unavailable")

// ReadCapacityQualificationPin reads the pin with the capacity profile reader
// role. Callers retry at startup until the hub-worker has initialized it.
func ReadCapacityQualificationPin(ctx context.Context, pool *pgxpool.Pool, root, installation string) (CapacityQualificationPin, error) {
	var out CapacityQualificationPin
	if ctx == nil || pool == nil {
		return out, ErrCapacityQualificationPin
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	var raw []byte
	if err := pool.QueryRow(call, `SELECT read_capacity_qualification_pin($1::uuid,$2::uuid)`, root, installation).Scan(&raw); err != nil || len(raw) == 0 {
		return out, errors.Join(ErrCapacityQualificationPin, err)
	}
	if json.Unmarshal(raw, &out) != nil || out.QualificationID == "" || len(out.QualificationDigest) != 64 || out.AccountVersion == "" || len(out.CapturePolicy) < 2 || out.OperationRetentionSeconds < 60 {
		return CapacityQualificationPin{}, ErrCapacityQualificationPin
	}
	return out, nil
}
