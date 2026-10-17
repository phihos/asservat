package postgres

import (
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/capture"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
)

func TestContextResolutionShapePreservesSequentialObservationIntervals(t *testing.T) {
	p := previewTestValue(t)
	start := p.CreatedAt
	q := value.ReplayQuery{RootID: p.RootID, PreviewID: p.ID, IdempotencyKey: "original", SubmissionDigest: app.ContextRequestDigest(p.ID), Identity: identity.Identity{Principal: p.Actor, Policy: identity.Revision{UID: "identity", Generation: 1, Digest: [32]byte{1}}, Scopes: []string{"evidence:read"}, VerifiedAt: start, ValidUntil: start.Add(5 * time.Second)}, Recovery: artifact.RecoveryProof{InstallationID: p.InstallationID, IssuerEpoch: p.IssuerEpoch, Revision: identity.Revision{UID: "recovery", Generation: 1, Digest: [32]byte{2}}, ObservedAt: start.Add(time.Millisecond), FreshUntil: start.Add(5 * time.Second)}}
	if !contextRequestQueryShape(p.RootID, q) {
		t.Fatal("newer recovery incorrectly checked at older identity instant")
	}
	if app.ValidReplayQuery(q, start) {
		t.Fatal("future recovery unexpectedly current")
	}
	if !app.ValidReplayQuery(q, start.Add(2*time.Millisecond)) {
		t.Fatal("overlapping original observations unavailable")
	}
	if app.ValidReplayQuery(q, start.Add(5*time.Second)) {
		t.Fatal("request original deadline extended")
	}
}
