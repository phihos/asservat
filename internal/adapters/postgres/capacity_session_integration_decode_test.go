package postgres

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/jackc/pgx/v5/pgtype"
)

// This is the ordinary production session decoder, not only the standalone
// snapshot codec. Generated SQL54 fields are deliberately required here.
func TestCapacityOrdinarySessionDecodeKeepsOriginalBacking(t *testing.T) {
	b, s := capacitySnapshotFixture()
	scope, err := json.Marshal(s.Scope)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	row := custodydb.ArtifactDownload{ID: id(s.ID), RootID: id(s.Scope.RootID), AllocationID: id(s.AllocationID), ArtifactID: id(s.Scope.ArtifactID), PrincipalKey: principalKey(s.Scope.Principal), ActorKey: digest(s.Scope.Principal), RequestDigest: s.RequestDigest[:], ScopeJson: scope, State: string(s.State), CreatedAt: ts(s.CreatedAt), Deadline: ts(s.Deadline), OutputLimit: s.OutputLimit, ReadLimit: s.ReadLimit, RequestLimit: s.RequestLimit, CapacityAccountID: id(b.AccountID), CapacityBacking: raw, CapacityBackingDigest: capacitySnapshotHash(raw)}
	for _, name := range []string{"original", "legacy", "unknown-account", "missing-snapshot", "missing-digest", "unmanaged-with-snapshot", "later-session", "changed-policy", "zero-native-digest"} {
		t.Run(name, func(t *testing.T) {
			r := row
			r.CapacityBacking = bytes.Clone(raw)
			r.CapacityBackingDigest = bytes.Clone(row.CapacityBackingDigest)
			switch name {
			case "legacy":
				r.CapacityAccountID = pgtype.UUID{}
				r.CapacityBacking = nil
				r.CapacityBackingDigest = nil
			case "unknown-account":
				r.CapacityAccountID = id("22222222-2222-4222-8222-222222222222")
			case "missing-snapshot":
				r.CapacityBacking = nil
			case "missing-digest":
				r.CapacityBackingDigest = nil
			case "unmanaged-with-snapshot":
				r.CapacityAccountID = pgtype.UUID{}
			case "later-session":
				r.Deadline = ts(s.Deadline.Add(time.Second))
			case "changed-policy":
				r.CapacityBacking = bytes.Replace(r.CapacityBacking, []byte(`"TransitionsPerRow":10`), []byte(`"TransitionsPerRow":11`), 1)
			case "zero-native-digest":
				v := b
				v.Native.PolicyDigest = artifact.Digest{}
				r.CapacityBacking, _ = json.Marshal(v)
				r.CapacityBackingDigest = capacitySnapshotHash(r.CapacityBacking)
			}
			got, e := decodeDownload(r)
			if name == "original" || name == "legacy" {
				if e != nil || !got.Deadline.Equal(s.Deadline) {
					t.Fatalf("original session unavailable: %v", e)
				}
			} else if e == nil {
				t.Fatal("invalid managed backing passed ordinary session decoder")
			}
		})
	}
}
