package postgres

import (
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
)

func TestHistoricalAssignmentAuditStillDecodes(t *testing.T) {
	const event = "11111111-1111-4111-8111-111111111111"
	audience := artifact.AudienceAssignment{Kind: "Group", Issuer: "https://id.example.test", SubjectID: "team-a", Role: "evidence-reader", BasisKind: "AccessBinding", BasisUID: "original", BasisDigest: artifact.Digest{2}, AssignmentID: event}
	// The original member-per-change JSON had no basis summary field.
	old := struct {
		ID, RootID, Epoch, Kind string
		Sequence                int64
		InputDigest             artifact.Digest
		CreatedAt               time.Time
		Changes                 []audit.AssignmentChange
	}{event, event, event, "permission-change", 1, artifact.Digest{1}, time.Unix(10, 0).UTC(), []audit.AssignmentChange{{ID: event, Change: "added", Audience: audience, ScopeDigest: artifact.Digest{3}}}}
	data, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	got, err := decodeAuthority(custodydb.AuthorityAudit{ID: id(event), StreamID: id(event), Epoch: id(event), Sequence: 1, EventKind: "permission-change", EventDigest: sum[:], Record: data})
	if err != nil || len(got.Changes) != 1 || got.Changes[0].Audience != audience || len(got.BasisChanges) != 0 {
		t.Fatal(got, err)
	}
}
