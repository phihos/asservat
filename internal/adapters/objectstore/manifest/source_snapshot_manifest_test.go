package manifest

import (
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"
)

func TestSourceSnapshotManifestRetainsPhysicalSourceWithoutSQLLookup(t *testing.T) {
	v, e, l, c, _ := recorderFixture(t)
	e.ExecutionClass, e.NodeUID, e.NodeBootID = artifact.ContextAPIExecution, "", ""
	scope := json.RawMessage(`{"schemaVersion":"source-window/v1","selection":{"sourceID":"original-source<&"}}`)
	binding := json.RawMessage(`{"NodeUID":"original-node","BootID":"original-boot","CollectorPodUID":"original-collector","CollectorEpoch":"original-epoch"}`)
	e.PlanDigest = artifact.Digest(sha256.Sum256(scope))
	q := artifact.SourceSnapshotRequest{SourceBindingDigest: artifact.Digest(sha256.Sum256(binding)), SourceID: e.Lifecycle.SourceSessionID, Fence: testID(32), SnapshotID: e.Lifecycle.SnapshotID, SourceStartedAt: e.Lifecycle.SourceStartedAt, SourceHardUntil: e.TriggeredAt.Add(time.Hour), T0: e.TriggeredAt, IssuedAt: e.TriggeredAt, StartBy: e.TriggeredAt.Add(time.Second), ProcessingUntil: e.TriggeredAt.Add(15 * time.Second), Before: e.Lifecycle.RequestedBefore, After: e.Lifecycle.After, MaxBytes: 65536}
	e.Snapshot = &q
	e.SourceSnapshotManifest = &artifact.SourceSnapshotManifest{CanonicalScope: scope, Binding: binding}
	e.Registration.NativeLimit = q.MaxBytes
	offset := artifact.SourceSnapshotAnchor(q).Sub(e.Registration.AnchorAt)
	e.Registration.WriteUntil = e.Registration.WriteUntil.Add(offset)
	e.Registration.ExpiresAt = e.Registration.ExpiresAt.Add(offset)
	e.Registration.DeleteBy = e.Registration.DeleteBy.Add(offset)
	e.Registration.AnchorAt = artifact.SourceSnapshotAnchor(q)
	l.Binding = e.Binding()
	b, err := v.MarshalContext(e, l, c, e.Registration.AnchorAt, q.T0.Add(q.After))
	if err != nil {
		t.Fatal(err)
	}
	for _, physical := range [][]byte{[]byte("original-node"), []byte("original-boot"), []byte("original-collector"), []byte("original-epoch"), []byte("original-source<&")} {
		if !bytes.Contains(b, physical) {
			t.Fatalf("lost original encrypted source provenance %s", physical)
		}
	}
	if _, err = v.ParseContext(b, e, c); err != nil {
		t.Fatal(err)
	}
	missing := mutate(t, b, func(m map[string]any) { delete(m, "sourceSnapshotManifest") })
	if _, err = v.ParseContext(missing, e, c); err == nil {
		t.Fatal("accepted missing retained original source")
	}
	substituted := e
	altered := *e.SourceSnapshotManifest
	altered.Binding = json.RawMessage(`{"NodeUID":"replacement-node"}`)
	substituted.SourceSnapshotManifest = &altered
	if evidence.ValidSourceSnapshotManifest(substituted) {
		t.Fatal("accepted source manifest substituted after admission")
	}
}
