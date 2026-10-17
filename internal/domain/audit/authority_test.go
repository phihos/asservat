package audit

import (
	"asservat.local/asservat/internal/domain/artifact"
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestExistingAuthorityAuditEncodingRemainsByteCompatible(t *testing.T) {
	// Re-encoding a stored pre-automation record must preserve its authenticated
	// plaintext digest. Adding an empty new field would invalidate old receipts.
	type legacy struct {
		ID, RootID, Epoch, Kind string
		Sequence                int64
		InputDigest             artifact.Digest
		CreatedAt               time.Time
		Changes                 []AssignmentChange
		Bootstrap               *PermissionBootstrap
	}
	r := AuthorityRecord{ID: "11111111-1111-4111-8111-111111111111", RootID: "22222222-2222-4222-8222-222222222222", Epoch: "33333333-3333-4333-8333-333333333333", Kind: "permission-reset", InputDigest: artifact.Digest{1}, CreatedAt: time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)}
	if !r.Valid() {
		t.Fatal("invalid historical fixture")
	}
	old, err := json.Marshal(legacy{r.ID, r.RootID, r.Epoch, r.Kind, r.Sequence, r.InputDigest, r.CreatedAt, r.Changes, r.Bootstrap})
	if err != nil {
		t.Fatal(err)
	}
	for _, automation := range [][]AutomationDelegation{nil, {}} {
		r.Automation = automation
		current, err := json.Marshal(r)
		if err != nil || !bytes.Equal(old, current) {
			t.Fatal("old immutable audit digest changed", err)
		}
	}
}
