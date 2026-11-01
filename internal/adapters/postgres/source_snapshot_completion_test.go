package postgres

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	deliveryapp "asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/application/evidence"
	executionapp "asservat.local/asservat/internal/application/execution"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"crypto/sha256"
)

func TestStoredSnapshotProjectionKeepsOriginalAcceptance(t *testing.T) {
	now := time.Date(2026, 10, 30, 1, 0, 0, 0, time.UTC)
	request := artifact.SourceSnapshotRequest{SourceBindingDigest: artifact.Digest{1}, SourceID: "10000000-0000-4000-8000-000000000010", Fence: "10000000-0000-4000-8000-000000000012", SnapshotID: "10000000-0000-4000-8000-000000000011", SourceStartedAt: now.Add(-time.Minute), SourceHardUntil: now.Add(time.Hour), T0: now, IssuedAt: now, StartBy: now.Add(time.Second), ProcessingUntil: now.Add(time.Minute), Before: 30 * time.Second, MaxBytes: 65536}
	e := artifact.ContextExpectation{TriggeredAt: now, Snapshot: &request, Lifecycle: &artifact.OngoingLifecycle{TriggerKind: "policy", SourceSessionID: request.SourceID, SourceStartedAt: request.SourceStartedAt, SnapshotID: request.SnapshotID, RequestedBefore: request.Before, HistoryCoverage: "unknown", WindowCoverage: "unknown", GapReasons: []string{"unknownLoss"}}}
	scopeDoc, bindingDoc := []byte("{}"), []byte("{}")
	e.PlanDigest = artifact.Digest(sha256.Sum256(scopeDoc))
	request.SourceBindingDigest = artifact.Digest(sha256.Sum256(bindingDoc))
	e.Snapshot = &request
	e.SourceSnapshotManifest = &artifact.SourceSnapshotManifest{CanonicalScope: scopeDoc, Binding: bindingDoc}
	original := evidence.ContextExpectationDigest(e)
	coverage := artifact.SourceSnapshotCoverage{Request: request, AcceptedExpectationDigest: original, NativeBytes: 4096, Retained: 2, AvailableFrom: request.SourceStartedAt, CompletedAt: now, InputUnknown: true}
	projected, err := artifact.ProjectSourceSnapshotCoverage(e, original, coverage)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(coverage)
	coverageHash, finalHash := digest(coverage), digest(projected)
	out, err := storedSnapshotProjection(e, raw, coverageHash, finalHash)
	if err != nil || out.Lifecycle.WindowCoverage != "partial" || !reflect.DeepEqual(out.Snapshot, e.Snapshot) || evidence.ContextExpectationDigest(e) != original || bytes.Equal(finalHash, original[:]) {
		t.Fatal("lost immutable admission or authenticated partial result", err)
	}
	// Exact repeated projection is stable; neither a newer clock nor a new digest
	// is selected when reading the same retained completion.
	again, err := storedSnapshotProjection(e, raw, coverageHash, finalHash)
	if err != nil || !reflect.DeepEqual(again, out) {
		t.Fatal("completion read changed", err)
	}
	for name, edit := range map[string]func(*artifact.ContextExpectation, *[]byte, *[]byte, *[]byte){
		"coverage digest": func(_ *artifact.ContextExpectation, _ *[]byte, c *[]byte, _ *[]byte) { (*c)[0] ^= 1 },
		"final digest":    func(_ *artifact.ContextExpectation, _ *[]byte, _ *[]byte, f *[]byte) { (*f)[0] ^= 1 },
		"unbound finite":  func(e *artifact.ContextExpectation, _ *[]byte, _ *[]byte, _ *[]byte) { e.Snapshot = nil },
		"changed original": func(e *artifact.ContextExpectation, _ *[]byte, _ *[]byte, _ *[]byte) {
			e.TriggeredAt = e.TriggeredAt.Add(time.Second)
		},
		"missing coverage":     func(_ *artifact.ContextExpectation, r *[]byte, _ *[]byte, _ *[]byte) { *r = nil },
		"trailing bytes":       func(_ *artifact.ContextExpectation, r *[]byte, _ *[]byte, _ *[]byte) { *r = append(*r, 'x') },
		"oversized":            func(_ *artifact.ContextExpectation, r *[]byte, _ *[]byte, _ *[]byte) { *r = make([]byte, 8193) },
		"missing final digest": func(_ *artifact.ContextExpectation, _ *[]byte, _ *[]byte, f *[]byte) { *f = nil },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := e
			r, c, f := bytes.Clone(raw), bytes.Clone(coverageHash), bytes.Clone(finalHash)
			edit(&candidate, &r, &c, &f)
			if _, err := storedSnapshotProjection(candidate, r, c, f); err == nil {
				t.Fatal("accepted changed completion")
			}
		})
	}
	finite := artifact.ContextExpectation{TriggeredAt: now}
	got, err := storedSnapshotProjection(finite, nil, nil, nil)
	if err != nil || !reflect.DeepEqual(got, finite) {
		t.Fatal("finite expectation changed", err)
	}
}

func TestSnapshotPublicationSeparatesAdmissionAndManifestDigests(t *testing.T) {
	t.Run("64KiB", func(t *testing.T) { checkSnapshotPublicationDigests(t, 64<<10) })
	t.Run("8MiB", func(t *testing.T) { checkSnapshotPublicationDigests(t, artifact.RecordingNativeLimit) })
}
func checkSnapshotPublicationDigests(t *testing.T, nativeLimit int64) {
	t.Helper()
	facts, execution, _ := apiCompletedFixture(t)
	accepted, err := admittedRecord(facts.ContextCapture)
	if err != nil {
		t.Fatal(err)
	}
	e := accepted.Expectation
	now := e.TriggeredAt
	request := artifact.SourceSnapshotRequest{SourceBindingDigest: artifact.Digest{1}, SourceID: "10000000-0000-4000-8000-000000000010", Fence: "10000000-0000-4000-8000-000000000012", SnapshotID: "10000000-0000-4000-8000-000000000011", SourceStartedAt: now, SourceHardUntil: now.Add(time.Hour), T0: now.Add(time.Second), IssuedAt: now.Add(time.Second), StartBy: now.Add(2 * time.Second), ProcessingUntil: e.Registration.WriteUntil, Before: time.Second, MaxBytes: nativeLimit}
	binding := collector.SourceBinding{RootID: execution.RootID, PolicyUID: e.CaptureUID, AcceptanceID: e.OccurrenceID, SourceID: request.SourceID, Fence: request.Fence, ActionID: "a0123456789abcdef01234567", PodUID: e.PodUID, NodeUID: e.CaseID, BootID: e.OccurrenceID, CollectorPodUID: e.CaptureUID, CollectorEpoch: e.CaseID, Scope: [32]byte{1}, ExpectationDigest: [32]byte{2}, ResourceDigest: [32]byte{3}, ProgramDigest: [32]byte{4}, AudienceDigest: [32]byte{5}}
	bindingJSON, _ := json.Marshal(binding)
	request.SourceBindingDigest = artifact.Digest(deliveryapp.SourceBindingDigest(binding))
	e.SourceSnapshotManifest = &artifact.SourceSnapshotManifest{CanonicalScope: bytes.Clone(facts.ContextCapture.ScopeJson), Binding: bindingJSON}
	e.NativeType = artifact.PCAPNGArtifact
	e.ActionID = "a0123456789abcdef01234567"
	e.Registration.NativeLimit = request.MaxBytes
	e.TriggeredAt = request.T0
	e.Snapshot = &request
	e.Lifecycle = &artifact.OngoingLifecycle{TriggerKind: "policy", SourceSessionID: request.SourceID, SourceStartedAt: request.SourceStartedAt, SnapshotID: request.SnapshotID, RequestedBefore: request.Before, HistoryCoverage: "unknown", WindowCoverage: "unknown", GapReasons: []string{"unknownLoss"}}
	if err = e.Validate(); err != nil {
		t.Fatal("snapshot fixture invalid", err)
	}
	facts.ContextCapture.ExpectationJson, _ = json.Marshal(e)
	intent, err := captureIntent(facts.ContextCapture)
	if err != nil {
		t.Fatal(err)
	}
	facts.ContextCapture.IntentDigest = digest(intent)
	execution.ExpectationDigest = evidence.ContextExpectationDigest(e)
	execution.Binding.ActionID = e.ActionID
	execution.Binding.NativeBytes = request.MaxBytes
	coverage := artifact.SourceSnapshotCoverage{Request: request, AcceptedExpectationDigest: execution.ExpectationDigest, NativeBytes: 4096, Retained: 2, AvailableFrom: request.SourceStartedAt, CompletedAt: execution.CompletedAt, InputUnknown: true}
	final, err := artifact.ProjectSourceSnapshotCoverage(e, execution.ExpectationDigest, coverage)
	if err != nil {
		t.Fatal(err)
	}
	facts.ContextCapture.SnapshotCoverage, _ = json.Marshal(coverage)
	facts.ContextCapture.SnapshotCoverageDigest = digest(coverage)
	facts.ContextCapture.SnapshotExpectationDigest = digest(final)
	if !validCompletedAPICapture(execution, final, facts.ContextCapture) {
		t.Fatal("legitimate final projection rejected")
	}
	if validCompletedAPI(execution, final) {
		t.Fatal("test failed to separate initial and final digests")
	}
	authorityDigest := executionapp.APIExecutionDigest(execution)
	verification := custodydb.ContextVerification{CaptureID: facts.ContextCapture.ID, RootID: facts.ContextCapture.RootID, VerifiedAt: ts(execution.CompletedAt.Add(time.Second)), ExpectationDigest: digest(final), CopiesDigest: digest(execution.Copies), IntentDigest: facts.ContextCapture.IntentDigest, AuthorityDigest: authorityDigest[:], PermissionEpoch: facts.ContextCapture.PermissionEpoch, PermissionSequence: 1}
	record, err := verificationRecord(facts.ContextCapture, verification, execution)
	if err != nil || record.APIOutcome == nil || record.ExpectationDigest == execution.ExpectationDigest || record.APIOutcome.ExecutionDigest != authorityDigest {
		t.Fatal("lost original execution versus final manifest audit binding", err)
	}
	changed := execution
	changed.ExpectationDigest = evidence.ContextExpectationDigest(final)
	if validCompletedAPICapture(changed, final, facts.ContextCapture) {
		t.Fatal("completion rewrote accepted execution digest")
	}
	missing := facts.ContextCapture
	missing.SnapshotCoverage = nil
	missing.SnapshotCoverageDigest = nil
	missing.SnapshotExpectationDigest = nil
	if validCompletedAPICapture(execution, final, missing) {
		t.Fatal("snapshot publication lacked retained completion")
	}
	observed, err := acceptedPublication(facts.ContextCapture)
	if err != nil || !reflect.DeepEqual(observed, final) {
		t.Fatal("publication lost independently derived lifecycle", err)
	}
}
