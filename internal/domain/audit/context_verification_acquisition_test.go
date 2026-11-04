package audit

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

func TestContextVerificationAcquisitionIsOptionalPairedAndAudited(t *testing.T) {
	id := "11111111-1111-4111-8111-111111111111"
	d := artifact.Digest{1}
	now := time.Date(2026, 11, 4, 9, 0, 0, 0, time.UTC)
	r := ContextVerification{RootID: id, CaptureID: id, ArtifactID: id, AttemptID: id, PermissionEpoch: id, PermissionSequence: 1, ScopeDigest: d, ExpectationDigest: d, CopiesDigest: d, IntentDigest: d, AuthorityDigest: d, VerifiedAt: now, WriteUntil: now.Add(time.Minute), ExpiresAt: now.Add(time.Hour), DeleteBy: now.Add(2 * time.Hour)}
	old, err := json.Marshal(r)
	if err != nil || !r.Valid() || bytes.Contains(old, []byte("Acquisition")) {
		t.Fatal("legacy verification bytes changed", err)
	}
	// The unqualified source clock may be ahead of the verification clock.
	// This display field must not add a cross-clock authority constraint.
	r.Acquisition = &artifact.AcquisitionWindow{StartedAt: now.Add(time.Second), CompletedAt: now.Add(2 * time.Second)}
	with, err := json.Marshal(r)
	if err != nil || !r.Valid() || !bytes.Contains(with, []byte(`"Acquisition":{"StartedAt":`)) {
		t.Fatal("window missing from immutable audit", err)
	}
	r.Acquisition.CompletedAt = time.Time{}
	if r.Valid() {
		t.Fatal("partial acquisition pair accepted")
	}
	r.Acquisition = nil
	again, err := json.Marshal(r)
	if err != nil || !bytes.Equal(old, again) {
		t.Fatal("legacy unknown round trip changed audit bytes", err)
	}
}
