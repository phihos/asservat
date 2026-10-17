package native_test

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// This is the bounded domain superset, not an assertion that synthetic strings
// were accepted as production provenance. Six-byte JSON escaping maximizes
// every bounded text field, including fields whose accepted schema is stricter.
func maximumNativeSource(t *testing.T) evidence.NativeContextSource {
	t.Helper()
	s := flowSourceValue(t)
	e := &s.Expectation
	text := func(n int) string { return strings.Repeat("<", n) }
	var digest artifact.Digest
	for i := range digest {
		digest[i] = 255
	}
	e.ExecutionClass = ""
	e.NodeUID, e.NodeBootID = text(64), nativeID
	e.PodUID, e.Namespace, e.NamespaceUID, e.WorkloadUID = text(64), text(63), text(64), text(64)
	e.CollectorVersion, e.ActionID, e.PurposeRef = text(64), text(63), text(128)
	e.CollectorImageDigest, e.RecipeDigest, e.PlanDigest = digest, digest, digest
	e.RequestedAgeSeconds, e.MaximumAgeSeconds, e.DeletionBudgetSeconds = 315360000, 315360000, 86400
	e.Registration.PoolRevision, e.Registration.AllocationRevision = math.MaxInt64, math.MaxInt64
	e.Registration.AnchorAt = time.Date(9980, 1, 1, 23, 59, 59, 999999000, time.FixedZone("synthetic", 23*3600+59*60))
	e.Registration.WriteUntil = e.Registration.AnchorAt.Add(time.Second)
	e.Registration.ExpiresAt = e.Registration.AnchorAt.Add(time.Duration(e.MaximumAgeSeconds-e.DeletionBudgetSeconds) * time.Second)
	e.Registration.DeleteBy = e.Registration.ExpiresAt.Add(time.Duration(e.DeletionBudgetSeconds) * time.Second)
	e.TriggeredAt = e.Registration.AnchorAt
	e.Audience = make([]artifact.AudienceAssignment, 32)
	for i := range e.Audience {
		e.Audience[i] = artifact.AudienceAssignment{Kind: text(16), Issuer: text(2048), SubjectID: text(256), Role: text(32), BasisKind: text(32), BasisUID: text(64), AssignmentID: nativeID, BasisDigest: digest}
	}
	e.RetentionRules = make([]artifact.RetentionRule, 64)
	for i := range e.RetentionRules {
		e.RetentionRules[i] = artifact.RetentionRule{UID: text(64), Generation: 2147483647, Digest: digest}
	}
	for i := range s.Copies {
		s.Copies[i] = artifact.CopyReceipt{VersionID: text(1024), ETag: text(1024), Bytes: e.Registration.Limits()[i], SHA256: digest}
	}
	if !s.Valid(evidence.ContextCopiesDigest(s.Copies)) {
		t.Fatal("maximal bounded source is invalid")
	}
	return s
}
func TestNativeCommandAcceptsMaximumExistingSource(t *testing.T) {
	source := maximumNativeSource(t)
	b, e := json.Marshal(source)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Date(9980, 1, 1, 23, 59, 59, 999999999, time.FixedZone("synthetic", 23*3600+59*60))
	op := value.NativeOperation{Reference: value.NativeReference{InstallationID: nativeID, SessionID: nativeID, WorkerID: nativeID, OperationID: nativeID, Fence: 1 << 60}, Kind: value.NativeResponse, HubPodUID: nativeID, HubProcessEpoch: nativeID, WorkerPodUID: nativeID, WorkerPublicKey: source.Copies[0].SHA256, SourceVersion: evidence.ContextCopiesDigest(source.Copies), ParentID: nativeID, Generation: math.MaxInt64, StartedAt: now, Until: now.Add(4 * time.Second)}
	op = syntheticProcessingPath(op)
	op.Processing.Location = source.Expectation.Registration.Location
	op.Path.TargetClusterID = op.Processing.Location.ClusterID
	op.Path.StoreID = source.Expectation.Registration.StoreID
	var digest artifact.Digest
	for i := range digest {
		digest[i] = 255
	}
	region := strings.Repeat("<", 63)
	op.Path.StorageRegion, op.Path.AcquisitionRegion, op.Path.ConnectorRegion, op.Path.HubRegion = region, region, region, region
	op.Path.WorkerConfiguration = identity.Revision{UID: nativeID, Generation: 2147483647, Digest: digest}
	op.Path.HubConfiguration = op.Path.WorkerConfiguration
	op.Processing.Sequence, op.Processing.StateDigest = 1<<60, digest
	if !op.CurrentValid(now) {
		t.Fatal("invalid maximal operation")
	}
	operation, e := json.Marshal(op)
	if e != nil {
		t.Fatal(e)
	}
	command := contracts.NativeCommand{Format: contracts.NativeExchangeFormat, Reference: contracts.NativeReference{InstallationID: nativeID, SessionID: nativeID, WorkerID: nativeID, OperationID: nativeID, Fence: 1 << 60}, Nonce: strings.Repeat("A", 43), Kind: string(op.Kind), Source: b, Operation: operation, ParentID: nativeID, Generation: math.MaxInt64, WindowID: nativeID, LeaseSequence: 1 << 60, Offset: 4095, Length: 1, Until: op.Until.Format(time.RFC3339Nano)}
	encoded, e := json.Marshal(command)
	if e != nil {
		t.Fatal(e)
	}
	// The existing 571084 bound is unchanged. New top-level member labels cost
	// 22 bytes. Path costs 212 fixed punctuation/name bytes, six quoted UUIDs,
	// four maximally escaped 63-byte labels, and two bounded revisions. Each
	// revision costs 32 fixed bytes + quoted UUID + 10-digit generation + a
	// 129-byte decimal digest array. Processing costs 141 fixed bytes (including
	// nested Location), six quoted UUIDs, 19-digit sequence, one digest, and
	// two quoted 35-byte RFC3339Nano dates. No evidence/token text is added.
	const pathBound = 212 + 6*38 + 4*(6*63+2) + 2*(32+38+10+129)
	const processingBound = 141 + 6*38 + 19 + 129 + 2*37
	const commandBound = 571084 + 22 + pathBound + processingBound
	if commandBound != 574075 || commandBound >= contracts.NativeCommandBytes {
		t.Fatal("closed command arithmetic exceeds fixed protocol capacity")
	}
	t.Logf("actual Go domain-maximum encoding: source=%d operation=%d command=%d bytes; conservative accepted-domain command bound=%d; fixed command ceiling=%d", len(b), len(operation), len(encoded), commandBound, contracts.NativeCommandBytes)
	if len(encoded) <= contracts.NativeControlBytes || len(encoded) > commandBound {
		t.Fatal("source bound changed; review the closed-field arithmetic", len(encoded))
	}
	if _, e = contracts.DecodeNativeCommand(encoded); e != nil {
		t.Fatal("existing bounded source rejected by command decoder", e)
	}
	var wire bytes.Buffer
	if e = contracts.WriteNativeFrame(&wire, contracts.NativeFrame{Kind: contracts.NativeCommandFrame, Payload: encoded}); e != nil {
		t.Fatal("existing bounded source rejected by framing", e)
	}
	got, e := contracts.ReadNativeFrame(&wire)
	if e != nil || !bytes.Equal(got.Payload, encoded) {
		t.Fatal("command frame changed", e)
	}
}
func TestNativeMaximumExistingSourceCrossesTwoHops(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	source := maximumNativeSource(t)
	now := time.Now()
	target := value.WorkerCredentialTarget{InstallationID: nativeID, SessionID: nativeID, WorkerID: nativeID, PodUID: nativeID, CreatedAt: now, RunUntil: now.Add(time.Minute)}
	reader := &flowSource{}
	result, e := evidence.NewRegionalContextResult(ctx, target, reader, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { result.Close(); _ = result.Wait(context.Background()) }()
	operation, client, _ := flowOperation(t, ctx, source, value.NativePrepare, 1, artifact.DownloadDeliveryLease{})
	done := flowRunWorker(t, ctx, client, target, result)
	if _, e = operation.Prepared(ctx); e != nil {
		t.Fatal("maximum-source preparation", e)
	}
	if e = operation.Commit(ctx); e != nil {
		t.Fatal("maximum-source commit", e)
	}
	if e = <-done; e != nil {
		t.Fatal("maximum-source worker", e)
	}
	if reader.reads.Load() != 1 {
		t.Fatal("preparation replayed")
	}
}
