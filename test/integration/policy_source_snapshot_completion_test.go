//go:build cgo && libpcap

package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/packets"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	captureapp "asservat.local/asservat/internal/application/capture"
	"asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/application/evidence"
	executionapp "asservat.local/asservat/internal/application/execution"
	"asservat.local/asservat/internal/application/planning"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/bootstrap"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/collector"
	executionvalue "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
)

// Real SQL and encrypted object-store composition. Target, process and packet
// observations remain synthetic fixture facts; no collector or native clock
// qualification follows from this test. The caller supplies genuine reviewed
// source admission, occurrence and capture acceptance, never hand-inserted rows.
type sourceSnapshotCompletionState struct {
	ObservationBefore int64
	Executions        *postgres.APIContextExecutions
	Execution         executionvalue.APIExecution
	Process           executionvalue.APIProcessBinding
	Bound             *objectstore.CustodyStore
	Channel           *delivery.NodeChannel
	Peer              delivery.NodePeer
	Holder            *bootstrap.ConnectorRecordings
	Work              collector.Work
	Close             func()
	RecordStored      func(context.Context, evidence.RecordingCollection, artifact.SourceSnapshotOutcome) (executionvalue.APIExecution, error)
	Retention         *privacyapp.RetentionResolver
}

func qualifySourceSnapshotCompletion(t *testing.T, ctx context.Context, f *capacitySQLFixture, policy policySourceAcceptedFixture, snapshot policySourceSnapshotAdmissionFixture, intents auditapp.CaptureOperationPublication, beforeStored ...func(*postgres.APIContextExecutions, executionvalue.APIExecution, executionvalue.APIProcessObservation, artifact.RecoveryProof)) {
	stage := startSourceSnapshotCompletion(t, ctx, f, policy, snapshot, intents)
	defer stage.Close()
	completeSourceSnapshotCompletion(t, ctx, f, policy, snapshot, stage, beforeStored...)
}

func startSourceSnapshotCompletion(t *testing.T, ctx context.Context, f *capacitySQLFixture, policy policySourceAcceptedFixture, snapshot policySourceSnapshotAdmissionFixture, intents auditapp.CaptureOperationPublication) *sourceSnapshotCompletionState {
	t.Helper()
	s, accepted, admission := policy.Scenario, snapshot.Accepted, snapshot.Admission
	e := accepted.Expectation
	// Policy observation is shared across sources. Preserve the actual total
	// around completion; the group admission test separately checks its debit.
	var observationBefore int64
	if err := f.admin.QueryRow(ctx, `SELECT observed_bytes_spent FROM policy_acceptance WHERE root_id=$1 AND id=$2`, admission.RootID, snapshot.Source.Binding.AcceptanceID).Scan(&observationBefore); err != nil {
		t.Fatal("original policy observation spend", err)
	}
	grouped := admission.Plan.Input.Snapshot != nil && admission.Plan.Input.Snapshot.Group != nil
	if !grouped && observationBefore != snapshot.Source.Credit {
		t.Fatal("single-source observation differs from original source credit", observationBefore)
	}
	clock := func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }
	if e.Snapshot == nil || e.Recording != nil {
		t.Fatal("not an admitted existing-source snapshot")
	}
	if _, err := intents.AcknowledgedCaptureIntent(ctx, accepted.CaptureID); err != nil {
		t.Fatal("audited exact snapshot intent", err)
	}
	guards := postgres.EffectTransactionGuards{Recovery: s.recovery.guard, Retention: s.retention.guard}
	hub := f.roles["hub-runtime"]
	executions, err := postgres.NewAPIContextExecutions(ctx, hub, admission.RootID, guards)
	if err != nil {
		t.Fatal(err)
	}
	current, err := postgres.NewAutomationAuthorities(ctx, hub, admission.RootID, policy.Authority.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	process := executionvalue.APIProcessBinding{InstallationID: policy.Authority.InstallationID, ClusterID: policy.Authority.ClusterID, IssuerEpoch: admission.Recovery.IssuerEpoch, NamespaceUID: custodyID(), AccountUID: custodyID(), PodUID: custodyID(), ProcessEpoch: custodyID(), StartupDigest: artifact.Digest{1}, ImageDigest: e.CollectorImageDigest}
	refresh := func() executionapp.APIExecutionCheck {
		t.Helper()
		f.refreshBase(t)
		now := clock()
		verified := authorization.PolicyExecutorIdentity(policy.Authority, now, now.Add(5*time.Second))
		projection, err := current.PolicyAutomationAuthority(ctx, policy.Authority, admission.Eligibility.Target)
		if err != nil {
			t.Fatal(err)
		}
		eligibility := authorization.PolicyContextEligibility(verified, policy.Authority, projection, admission.Eligibility.Target, clock())
		eligibility.DefaultAudience, err = captureapp.SnapshotAudience(admission.Plan.Input.Snapshot, eligibility.DefaultAudience)
		if err != nil || !eligibility.Eligible {
			t.Fatal("current source snapshot audience", err)
		}
		recovery, err := s.recovery.reader.RecoveryState(ctx)
		if err != nil {
			t.Fatal(err)
		}
		work, err := executions.ReadAPIContextWork(ctx, accepted.CaptureID, verified, recovery)
		if err != nil {
			t.Fatal("retained source API work", err)
		}
		policies, err := func() (privacy.PolicySet, error) {
			if admission.Plan.Input.Snapshot.Group != nil {
				return manualGroupRetentionPolicies(ctx, s.retention, admission.Eligibility.Target)
			}
			return s.retention.policies(ctx)
		}()
		if err != nil {
			t.Fatal(err)
		}
		input := admission.Plan.Input
		observed := *input.SnapshotSource
		now = clock()
		until := now.Add(5 * time.Second)
		observed.ObservedAt, observed.FreshUntil = now, until
		observed.Process.ObservedAt, observed.Process.FreshUntil = now, until
		observed.ReportedAt, observed.ReportFreshUntil = now, now.Add(15*time.Second)
		observed.State.ObservedAt, observed.State.FreshUntil = observed.ReportedAt, observed.ReportFreshUntil
		input.SnapshotSource = &observed
		input.Capability.ObservedAt, input.Capability.FreshUntil = now, until
		input.Retention, err = privacy.Resolve(policies, privacy.Input{Target: admission.Eligibility.Target, PrivacyClass: "potentialPersonalData", EvidenceType: "packetCapture", RequestedSeconds: e.RequestedAgeSeconds, AnchorAt: e.Registration.AnchorAt}, clock())
		if err != nil {
			t.Fatal(err)
		}
		plan, err := planning.CompileContext(input, clock())
		if err != nil || plan.ScopeDigest != e.PlanDigest {
			t.Fatal("same immutable source plan", err)
		}
		checked := clock()
		until = identity.Earlier(until, identity.Earlier(eligibility.ValidUntil, identity.Earlier(plan.ValidUntil, recovery.FreshUntil)))
		out := executionapp.APIExecutionCheck{Work: work, Plan: plan, Eligibility: eligibility, Recovery: recovery, Process: executionvalue.APIProcessObservation{Binding: process, CheckedAt: now, ValidUntil: now.Add(5 * time.Second)}, CheckedAt: checked, ValidUntil: until}
		if admission.RecordingSave != nil {
			human := admission.RecordingSave.Initiator.VerifiedIdentity
			permissions, err := s.p.Permissions(ctx, admission.Eligibility.Target)
			if err != nil {
				t.Fatal("current manual initiator permission projection", err)
			}
			initiating := authorization.ContextEligibility(human, permissions, admission.Eligibility.Target, clock())
			if !initiating.Eligible {
				t.Fatal("current manual initiator rights", initiating.Reason)
			}
			out.Initiator = &initiating
			out.ValidUntil = identity.Earlier(out.ValidUntil, initiating.ValidUntil)
		}
		if !out.Valid(clock()) {
			t.Fatal("snapshot execution preflight invalid")
		}
		return out
	}
	check := refresh()
	execution, first, err := executions.PrepareAPIExecution(ctx, check)
	if err != nil || !first {
		t.Fatal("prepare original snapshot", first, err)
	}
	replay, again, err := executions.PrepareAPIExecution(ctx, check)
	if err != nil || again || replay != execution {
		t.Fatal("snapshot preparation replay", again, err)
	}
	execution, err = executions.BindAPIStart(ctx, check, execution, executionvalue.PreparedStart{ObjectUID: custodyID(), ResourceVersion: "1"})
	if err != nil {
		t.Fatal(err)
	}
	execution, err = executions.RecordAPIStart(ctx, check, execution, executionvalue.Disposition{ObjectUID: execution.ObjectUID, ResourceVersion: "2", Phase: executionvalue.StartCommitted, CommittedAt: clock(), MayStart: true, ValidUntil: execution.Binding.NotAfter})
	if err != nil {
		t.Fatal(err)
	}
	bound, err := f.store.ForCustody(e.Registration.StoreID)
	if err != nil {
		t.Fatal(err)
	}
	producer, err := objectstore.NewArtifactProducer(bound, f.keys, recordingJournal{}, clock)
	if err != nil {
		t.Fatal(err)
	}
	preparedArtifact, err := producer.Prepare(ctx, e, "")
	if err != nil {
		t.Fatal(err)
	}
	b := snapshot.Source.Binding
	channel, err := delivery.NewNodeChannel(policyObservationNode{collector.Identity{NodeName: "worker", NodeUID: b.NodeUID, PodUID: b.CollectorPodUID, BootID: b.BootID}}, policyObservationNodeIssuer{}, clock, nil)
	if err != nil {
		t.Fatal(err)
	}
	der, _, _, err := channel.Enroll(ctx, "synthetic-component", []byte("synthetic-token"), []byte("synthetic-csr"), b.BootID, b.CollectorEpoch)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := channel.Peer(sha256.Sum256(der))
	if err != nil {
		t.Fatal(err)
	}
	if err = channel.Report(peer, b.CollectorEpoch, collector.Report{Sequence: 1, ObservedAt: clock(), Facts: collector.Facts{Kernel: collector.KernelVersion{Major: 6, Minor: 8}}, Mechanisms: []collector.Availability{{Mechanism: collector.MechanismPacket, Prerequisites: true, Adapter: collector.AdapterAvailable, Hook: collector.HookTC}}}); err != nil {
		t.Fatal(err)
	}
	holder := bootstrap.NewConnectorRecordings(channel, nil, clock, func(line string) { t.Log(line) })
	channel.SetPacketSink(holder)
	prepared := holder.Prepare(preparedArtifact, e)
	queued := false
	defer func() {
		if !queued {
			prepared.Close()
		}
	}()
	x := collector.SourceSnapshot{Binding: b, CaptureID: accepted.CaptureID, AttemptID: e.Registration.Location.AttemptID, WriterPodUID: process.PodUID, WriterEpoch: process.ProcessEpoch, ExpectationDigest: [32]byte(evidence.ContextExpectationDigest(e)), Request: *e.Snapshot}
	if _, err = prepared.StartSourceSnapshot(ctx, x); err != nil {
		t.Fatal("original source snapshot queue", err)
	}
	work, err := channel.Poll(ctx, peer, b.CollectorEpoch, 0, 0)
	if err != nil || len(work) != 1 || work[0].Snapshot == nil || !work[0].Snapshot.Equal(x) {
		t.Fatal("queued original source snapshot", work, err)
	}

	queued = true
	return &sourceSnapshotCompletionState{ObservationBefore: observationBefore, Executions: executions, Execution: execution, Process: process, Bound: bound, Channel: channel, Peer: peer, Holder: holder, Work: work[0], Close: prepared.Close}
}

func completeSourceSnapshotCompletion(t *testing.T, ctx context.Context, f *capacitySQLFixture, policy policySourceAcceptedFixture, snapshot policySourceSnapshotAdmissionFixture, stage *sourceSnapshotCompletionState, beforeStored ...func(*postgres.APIContextExecutions, executionvalue.APIExecution, executionvalue.APIProcessObservation, artifact.RecoveryProof)) {
	t.Helper()
	s, accepted, admission := policy.Scenario, snapshot.Accepted, snapshot.Admission
	e := accepted.Expectation
	clock := func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }
	executions, execution, process := stage.Executions, stage.Execution, stage.Process
	bound, channel, peer, holder := stage.Bound, stage.Channel, stage.Peer, stage.Holder
	work := []collector.Work{stage.Work}
	b, observationBefore := snapshot.Source.Binding, stage.ObservationBefore
	guards := postgres.EffectTransactionGuards{Recovery: s.recovery.guard, Retention: s.retention.guard}
	hub := f.roles["hub-runtime"]
	var err error

	end := e.Snapshot.T0.Add(e.Snapshot.After)
	if wait := time.Until(end); wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-timer.C:
		}
	}
	var native []byte
	observedUntil := e.Snapshot.T0.Add(49 * time.Millisecond)
	if e.Snapshot.After == 0 {
		// Manual saves contain only existing history.50 nanosecond-spaced synthetic
		// headers end exactly at t0; interface statistics also close at t0.
		first := e.Snapshot.T0.Add(-49 * time.Nanosecond)
		if first.Before(artifact.SourceSnapshotAnchor(*e.Snapshot)) {
			t.Fatal("fixture lacks its49ns historical span")
		}
		native = syntheticFilteredRecording(t, first, policy.Compiled.Recorder.Filter.Program, 2, syntheticRecordingTimes{Step: time.Nanosecond, End: e.Snapshot.T0})
		observedUntil = e.Snapshot.T0
	} else {
		if e.Snapshot.After < 50*time.Millisecond {
			t.Fatal("automatic fixture requires its authored positive post-window")
		}
		native = syntheticFilteredRecording(t, e.Snapshot.T0, policy.Compiled.Recorder.Filter.Program, 2)
	}
	defer clear(native)
	outcome := artifact.SourceSnapshotOutcome{NativeSHA256: artifact.Digest(sha256.Sum256(native)), SourceSnapshotCoverage: artifact.SourceSnapshotCoverage{Request: *e.Snapshot, AcceptedExpectationDigest: evidence.ContextExpectationDigest(e), NativeBytes: int64(len(native)), Retained: 50, AvailableFrom: e.Snapshot.SourceStartedAt, ObservedUntil: observedUntil, CompletedAt: clock(), InputUnknown: true}}
	final, err := artifact.ProjectSourceSnapshot(e, evidence.ContextExpectationDigest(e), outcome)
	if err != nil {
		t.Fatal(err)
	}
	result := collector.PacketResult{Snapshot: &outcome, WorkID: work[0].ID, CaptureID: accepted.CaptureID, StartedAt: artifact.SourceSnapshotAnchor(*e.Snapshot), EndedAt: end, Seen: 50, Retained: 50, CapturedBytes: int64(len(native)), Snaplen: artifact.RecordingSnaplen, ProgramDigest: b.ProgramDigest}
	if err = channel.DeliverPacket(ctx, peer, b.CollectorEpoch, result, bytes.NewReader(native)); err != nil {
		t.Fatal("actual snapshot channel/producer", err)
	}
	if err = channel.DeliverPacket(ctx, peer, b.CollectorEpoch, result, bytes.NewReader(native)); err == nil {
		t.Fatal("snapshot uploaded twice")
	}
	collected, err := holder.Collect(fleet.APIContextWork{CaptureID: accepted.CaptureID, AttemptID: e.Registration.Location.AttemptID, ExpectationDigest: evidence.ContextExpectationDigest(e)})
	if err != nil || collected.State != evidence.RecordingStored || collected.SnapshotCoverage == nil {
		t.Fatal("joined snapshot producer completion", collected, err)
	}
	completion := collected.Completion
	execution.Copies = completion.Copies
	execution.Phase, execution.AcquiredAt, execution.CompletedAt = "stored", collected.Acquired, completion.StoredAt
	now := clock()
	processObservation := executionvalue.APIProcessObservation{Binding: process, CheckedAt: now, ValidUntil: now.Add(5 * time.Second)}
	recovery, err := s.recovery.reader.RecoveryState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = executions.RecordAPIStoredCompletion(ctx, execution, completion, processObservation, recovery); err == nil {
		t.Fatal("snapshot used finite completion")
	}
	for _, hook := range beforeStored {
		hook(executions, execution, processObservation, recovery)
	}
	if stage.RecordStored != nil {
		execution, err = stage.RecordStored(ctx, collected, outcome)
	} else {
		execution, err = executions.RecordAPIStoredSnapshotCompletion(ctx, execution, completion, outcome.SourceSnapshotCoverage, processObservation, recovery)
	}
	if err != nil {
		t.Fatal("atomic snapshot completion", err)
	}
	if _, err = executions.RecordAPIStoredSnapshotCompletion(ctx, execution, completion, outcome.SourceSnapshotCoverage, processObservation, recovery); err != nil {
		t.Fatal("exact completion replay", err)
	}
	changed := outcome.SourceSnapshotCoverage
	changed.Retained++
	if _, err = executions.RecordAPIStoredSnapshotCompletion(ctx, execution, completion, changed, processObservation, recovery); err == nil {
		t.Fatal("completion replay replaced actual coverage")
	}
	var originalRaw, recordedDigest, writerDigest []byte
	if err = f.admin.QueryRow(ctx, `SELECT c.expectation_json,e.expectation_digest,w.expectation_digest FROM context_capture c JOIN context_execution e ON e.root_id=c.root_id AND e.capture_id=c.id JOIN context_writer_completion w ON w.root_id=c.root_id AND w.capture_id=c.id WHERE c.root_id=$1 AND c.id=$2`, admission.RootID, accepted.CaptureID).Scan(&originalRaw, &recordedDigest, &writerDigest); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(e)
	initialDigest := evidence.ContextExpectationDigest(e)
	finalDigest := evidence.ContextExpectationDigest(final)
	if !bytes.Equal(originalRaw, encoded) || !bytes.Equal(recordedDigest, initialDigest[:]) || !bytes.Equal(writerDigest, finalDigest[:]) || initialDigest == finalDigest {
		t.Fatal("completion overwrote accepted identity")
	}
	if _, err = hub.Exec(ctx, `UPDATE context_capture SET snapshot_coverage=snapshot_coverage || $3 WHERE root_id=$1 AND id=$2`, admission.RootID, accepted.CaptureID, []byte("x")); capacitySQLState(err) != "23514" {
		t.Fatal("immutable coverage replacement", err)
	}
	publications := func(purpose string) *postgres.ContextPublications {
		p, err := postgres.NewContextPublications(ctx, f.roles[purpose], admission.RootID, guards)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	verify, audit, publish := publications("context-verify"), publications("context-verification-audit"), publications("context-publish")
	retentionResolver := privacyapp.RetentionResolver{RetainedPolicies: s.retention, Now: time.Now}
	if admission.Plan.Input.Snapshot.Group != nil {
		retentionResolver.RetainedPolicies = manualGroupRetainedPolicies{fixture: s.retention}
	}
	if stage.Retention != nil {
		retentionResolver = *stage.Retention
	}
	gate, err := postgres.NewAPIContextPublicationGate(ctx, f.roles["publication-gate"], admission.RootID, guards, retentionResolver, s.recovery.reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := objectstore.NewContextVerifier(bound, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	checkedHeaders := 0
	verifier.WithStreamCheck(artifact.PCAPNGArtifact, func() objectstore.StreamCheck { checkedHeaders++; return packets.NewHeadersCheck() })
	unwraps := qualifyContextKeyUnwraps(t, ctx, f.admin, f.fixturePool, s, final, accepted.CaptureID)
	f.refreshBase(t)
	publisher := evidence.ContextPublisher{Ledger: evidence.ContextPublicationFacets{ContextAcceptanceReader: verify, ContextVerificationRecorder: verify, ContextVerificationAuditor: audit, ContextCatalogPublisher: publish}, Authority: gate, Verifier: verifier, Audit: &objectstore.ContextVerificationObjects{Store: f.store, Seal: f.keys, Open: f.keys}, Now: time.Now}
	published, err := publisher.Publish(ctx, accepted.CaptureID, execution.Copies)
	if err != nil {
		t.Fatal("semantic snapshot publication", err)
	}
	if checkedHeaders == 0 {
		t.Fatal("publication skipped independent headers-only privacy check")
	}
	unwraps.afterPublication(ctx, accepted.CaptureID)
	// PCAPNG uses the existing bounded framed native source. ReadContext is
	// deliberately the historical pod-status-only small-buffer reader.
	source, err := verifier.OpenNative(ctx, published.Expectation, published.Copies, time.Now().Add(4*time.Second))
	if err != nil {
		t.Fatal("snapshot native open", err)
	}
	defer source.Close()
	metadata := source.Metadata()
	if metadata.Size < 1 || metadata.Size > e.Snapshot.MaxBytes || metadata.Size > published.Expectation.Type().DownloadLimit() || metadata.Filename != published.Expectation.Type().Filename(published.Expectation.Registration.Location.ArtifactID) || metadata.Format != artifact.PCAPNGFormat || metadata.SHA256 != artifact.Digest(sha256.Sum256(native)) || metadata.Coverage != published.Expectation.Type().CoverageFor(published.Expectation.Lifecycle) || !metadata.ReadUntil.Equal(published.Expectation.Registration.ExpiresAt) || !metadata.DeleteBy.Equal(published.Expectation.Registration.DeleteBy) {
		t.Fatal("snapshot native metadata", metadata)
	}
	got := make([]byte, 0, int(metadata.Size))
	defer func() { clear(got) }()
	finalVerified := false
	for offset := int64(0); offset < metadata.Size; {
		chunk, verified, readErr := source.ReadNext(ctx, offset, min(artifact.DeliveryBytes, metadata.Size-offset))
		if readErr != nil || len(chunk) == 0 {
			clear(chunk)
			t.Fatal("snapshot native read", readErr)
		}
		got = append(got, chunk...)
		offset += int64(len(chunk))
		clear(chunk)
		finalVerified = verified
	}
	if !finalVerified || artifact.Digest(sha256.Sum256(got)) != metadata.SHA256 || !bytes.Equal(got, native) || evidence.ContextExpectationDigest(published.Expectation) != finalDigest || initialDigest == finalDigest || published.Expectation.Lifecycle.WindowCoverage != "partial" {
		t.Fatal("snapshot native bytes/final coverage")
	}
	var observedCredit int64
	if err = f.admin.QueryRow(ctx, `SELECT observed_bytes_spent FROM policy_acceptance WHERE root_id=$1 AND id=$2`, admission.RootID, snapshot.Source.Binding.AcceptanceID).Scan(&observedCredit); err != nil || observedCredit != observationBefore {
		t.Fatal("save changed prepaid observation spend", observedCredit, err)
	}
	t.Logf("actual snapshot SQL/encrypted publication/native bytes=%d; original/final digests distinct, exact replay, unchanged source credit; source/process/packet/clock observations synthetic", len(native))
}
