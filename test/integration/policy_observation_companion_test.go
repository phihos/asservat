package integration

import (
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/application/evidence"
	executionapp "asservat.local/asservat/internal/application/execution"
	"asservat.local/asservat/internal/bootstrap"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/collector"
	executionvalue "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"github.com/jackc/pgx/v5/pgxpool"
	"reflect"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/transport/conversion"
)

const policyRawExpression = "tcp[13] & 2 != 0"

// The exact pinned libpcap program, independently compared with the real dead-
// handle compiler in the libpcap-tagged test. This is not a general compiler.
var policyRawProgram = []value.BPFInstruction{
	{Code: 0x28, K: 12}, {Code: 0x15, Jf: 8, K: 0x800}, {Code: 0x30, K: 23}, {Code: 0x15, Jf: 6, K: 6},
	{Code: 0x28, K: 20}, {Code: 0x45, Jt: 4, K: 0x1fff}, {Code: 0xb1, K: 14}, {Code: 0x50, K: 27},
	{Code: 0x45, Jf: 1, K: 2}, {Code: 6, K: 65535}, {Code: 6},
}

type policyRawFilters struct{}

func (policyRawFilters) CompileFilter(expression string) (value.CompiledFilter, error) {
	if expression != policyRawExpression {
		return value.CompiledFilter{}, value.ErrInvalid
	}
	return value.CompiledFilter{LinkType: value.FilterLinkType, Snaplen: value.FilterSnaplen, Program: append([]value.BPFInstruction(nil), policyRawProgram...)}, nil
}
func policyRawCompile(raw json.RawMessage) (value.PolicyRecorderConfiguration, error) {
	var wire contracts.CaptureComposition
	if err := json.Unmarshal(raw, &wire); err != nil {
		return value.PolicyRecorderConfiguration{}, err
	}
	composition, err := conversion.CompositionFromWire(wire)
	if err != nil || composition == nil {
		return value.PolicyRecorderConfiguration{}, value.ErrInvalid
	}
	return planning.CompilePolicyRecorder(*composition, policyRawFilters{})
}

// Actual companion transaction with real accepted policy/occurrence/grant and
// frozen raw scope, typed queue, encrypted producer and audited retirement.
// Target/process/node trust and packet inputs remain synthetic component facts;
// neither runtime raw gate is opened and no collector/engine runs.
func qualifyPolicyObservationCompanion(t *testing.T, ctx context.Context, admin, hub *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, s captureAdmissionScenario, admissions *postgres.ContextAdmissions, current *postgres.AutomationAuthorities, authority authorization.AcceptedPolicyAuthority, admission capture.Admission, accepted capture.Accepted, acceptance, grant string, before *policyObservationGraphSample, protected ...policyRecorderProtectedCase) {
	t.Helper()
	clock := func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }
	guard := postgres.EffectTransactionGuards{Recovery: s.recovery.guard, Retention: s.retention.guard}
	executions, err := postgres.NewAPIContextExecutions(ctx, hub, s.a.RootID, guard)
	if err != nil {
		t.Fatal(err)
	}
	if len(protected) > 0 {
		if err = protected[0].Intent(ctx, accepted.CaptureID); err != nil {
			t.Fatal("protected intent", err)
		}
	} else {
		intentPool := poolFor("capture_audit_runtime", "synthetic-capture-audit")
		defer intentPool.Close()
		intent, err := postgres.NewCaptureIntentAudits(ctx, intentPool, s.a.RootID)
		if err != nil {
			t.Fatal(err)
		}
		if err = (auditapp.CaptureIntentPublisher{Ledger: intent, Objects: &objectstore.CaptureIntentObjects{Store: store, Seal: keys, Open: keys}}).PublishCaptureIntents(ctx); err != nil {
			t.Fatal("raw companion acknowledged capture intent", err)
		}
	}
	e := accepted.Expectation
	program := admission.Plan.Input.Recorder.Filters[0].Filter.Program
	process := executionvalue.APIProcessBinding{InstallationID: authority.InstallationID, ClusterID: authority.ClusterID, IssuerEpoch: admission.Recovery.IssuerEpoch, NamespaceUID: custodyID(), AccountUID: custodyID(), PodUID: custodyID(), ProcessEpoch: custodyID(), StartupDigest: artifact.Digest{1}, ImageDigest: e.CollectorImageDigest}
	node, boot, collectorPod, epoch := custodyID(), custodyID(), custodyID(), custodyID()
	// The actual queue is exercised with explicitly synthetic attestation and
	// issuance. No native collector, certificate or Kubernetes proof is claimed.
	channel, err := delivery.NewNodeChannel(policyObservationNode{collector.Identity{NodeName: "worker", NodeUID: node, PodUID: collectorPod, BootID: boot}}, policyObservationNodeIssuer{}, clock, nil)
	if err != nil {
		t.Fatal(err)
	}
	der, _, nodeIdentity, err := channel.Enroll(ctx, "synthetic-component", []byte("synthetic-token"), []byte("synthetic-csr"), boot, epoch)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := channel.Peer(sha256.Sum256(der))
	if err != nil {
		t.Fatal(err)
	}
	if err = channel.Report(peer, epoch, collector.Report{Sequence: 1, ObservedAt: clock(), Facts: collector.Facts{Kernel: collector.KernelVersion{Major: 6, Minor: 8}}, Mechanisms: []collector.Availability{{Mechanism: collector.MechanismPacket, Prerequisites: true, Adapter: collector.AdapterAvailable, Hook: collector.HookTC}}}); err != nil {
		t.Fatal(err)
	}

	var previewID string
	if err := admin.QueryRow(ctx, `SELECT preview_id::text FROM context_capture WHERE root_id=$1 AND id=$2`, s.a.RootID, accepted.CaptureID).Scan(&previewID); err != nil {
		t.Fatal("actual raw admission preview", err)
	}
	replayChecked := false
	refresh := func() (executionapp.APIExecutionCheck, targets.PacketSourceObservation) {
		t.Helper()
		n := clock()
		s.batch.ObservedAt, s.batch.FreshUntil, s.batch.Initial = n, n.Add(5*time.Second), nil
		if err := s.p.RefreshPermissions(ctx, s.batch); err != nil {
			t.Fatal("companion current permission facts", err)
		}
		verified := authorization.PolicyExecutorIdentity(authority, n, n.Add(5*time.Second))
		projection, err := current.PolicyAutomationAuthority(ctx, authority, admission.Eligibility.Target)
		if err != nil {
			t.Fatal(err)
		}
		eligible := authorization.PolicyContextEligibility(verified, authority, projection, admission.Eligibility.Target, clock())
		if !eligible.Eligible {
			t.Fatal("companion accepted team eligibility", eligible.Reason)
		}
		recovery, err := s.recovery.reader.RecoveryState(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !replayChecked {
			replay, found, err := admissions.LookupContextAdmission(ctx, capture.ReplayQuery{RootID: s.a.RootID, PreviewID: previewID, IdempotencyKey: admission.IdempotencyKey, SubmissionDigest: admission.SubmissionDigest, Identity: verified, Recovery: recovery})
			if err != nil || !found || !replay.Replay || replay.CaptureID != accepted.CaptureID || replay.ScopeDigest != accepted.ScopeDigest || !replay.Deadline.Equal(accepted.Deadline) || replay.Expectation.Recording == nil || replay.Expectation.Recording.RequireApproval {
				t.Fatal("actual raw policy admission replay with require-all false", found, err)
			}
			replayChecked = true
			t.Log("actual raw policy admission replay retained capture/scope/deadline and require-all=false")
		}
		work, err := executions.ReadAPIContextWork(ctx, accepted.CaptureID, verified, recovery)
		if err != nil {
			t.Fatal("actual raw API work", err)
		}
		policies, err := s.retention.policies(ctx)
		if err != nil {
			t.Fatal(err)
		}
		input := admission.Plan.Input
		targetAt := clock()
		input.Target.ObservedAt, input.Target.FreshUntil = targetAt, targetAt.Add(5*time.Second)
		input.Capability.ObservedAt, input.Capability.FreshUntil = targetAt, targetAt.Add(5*time.Second)
		input.Retention, err = privacy.Resolve(policies, privacy.Input{Target: input.Target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: e.Type().EvidenceType, RequestedSeconds: e.RequestedAgeSeconds, AnchorAt: e.Registration.AnchorAt}, clock())
		if err != nil {
			t.Fatal(err)
		}
		input.Recorder, err = planning.RecorderContextFor(e.Recording)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := planning.CompileContext(input, clock())
		if err != nil || plan.ScopeDigest != e.PlanDigest {
			t.Fatal("actual raw frozen context plan", err)
		}
		observed := executionvalue.APIProcessObservation{Binding: process, CheckedAt: targetAt, ValidUntil: targetAt.Add(5 * time.Second)}
		checked := clock()
		until := checked.Add(5 * time.Second)
		for _, bound := range []time.Time{eligible.ValidUntil, plan.ValidUntil, recovery.FreshUntil, observed.ValidUntil} {
			until = identity.Earlier(until, bound)
		}
		check := executionapp.APIExecutionCheck{Work: work, Plan: plan, Eligibility: eligible, Recovery: recovery, Process: observed, CheckedAt: checked, ValidUntil: until}
		source := targets.PacketSourceObservation{PodUID: e.PodUID, NodeUID: node, BootID: boot, CollectorPodUID: collectorPod, CollectorEpoch: epoch, ObservedAt: targetAt, FreshUntil: until}
		if !check.Valid(clock()) || !source.Valid(clock()) || source.FreshUntil.After(input.Target.FreshUntil) {
			t.Fatal("assembled actual raw companion preflight invalid")
		}
		return check, source
	}
	read := func(want int64) {
		t.Helper()
		var acceptedSpend, grantSpend, preparations, sessions int64
		err := admin.QueryRow(ctx, `SELECT a.observed_bytes_spent,g.policy_observed_bytes_spent,
   (SELECT count(*) FROM context_execution x WHERE x.root_id=a.root_id AND x.capture_id=$3),
   (SELECT count(*) FROM policy_observation_session o WHERE o.root_id=a.root_id AND o.capture_id=$3)
   FROM policy_acceptance a JOIN access_grant g ON g.root_id=a.root_id AND g.id=$4 WHERE a.root_id=$1 AND a.id=$2`, s.a.RootID, acceptance, accepted.CaptureID, grant).Scan(&acceptedSpend, &grantSpend, &preparations, &sessions)
		wantRows := int64(0)
		if want > 0 {
			wantRows = 1
		}
		if err != nil || acceptedSpend != want || grantSpend != want || preparations != wantRows || sessions != wantRows {
			t.Fatalf("independent companion commit/rollback read: accepted=%d grant=%d API=%d observation=%d want=%d err=%v", acceptedSpend, grantSpend, preparations, sessions, want, err)
		}
	}
	read(0)
	check, source := refresh()
	source.FreshUntil = clock().Add(400 * time.Millisecond)
	if source.FreshUntil.After(check.ValidUntil) {
		t.Fatal("fixture lost original source-expiry distinction")
	}
	blocker, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(context.Background())
	if _, err = blocker.Exec(ctx, "SELECT id FROM access_grant WHERE root_id=$1 AND id=$2 FOR UPDATE", s.a.RootID, grant); err != nil {
		t.Fatal(err)
	}
	type result struct {
		execution executionvalue.APIExecution
		first     bool
		permit    collector.ObservationPermit
		err       error
	}
	done := make(chan result, 1)
	go func() {
		r, first, p, err := executions.PreparePolicyRecording(ctx, check, source)
		done <- result{r, first, p, err}
	}()
	joined := false
	defer func() {
		if !joined {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = blocker.Rollback(cleanup)
			select {
			case <-done:
			case <-cleanup.Done():
				t.Error("actual companion did not join after lock release")
			}
		}
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		var waiting bool
		if err = admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename=$1 AND wait_event_type='Lock' AND query LIKE '%access_grant%')`, hub.Config().ConnConfig.User).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case early := <-done:
			joined = true
			t.Fatal("companion did not reach held original grant", early.err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("companion never reached actual original-grant lock wait")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if wait := time.Until(source.FreshUntil.Add(50 * time.Millisecond)); wait > 0 {
		time.Sleep(wait)
	}
	if err = blocker.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if !clock().Before(check.ValidUntil) {
		t.Fatal("fixture no longer distinguishes source cutoff from original live check")
	}
	select {
	case refused := <-done:
		joined = true
		if refused.err == nil || refused.first || refused.permit != (collector.ObservationPermit{}) {
			t.Fatal("companion issued after original source cutoff", refused.first, refused.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("companion did not finish after original grant unlock")
	}
	read(0)
	t.Log("ACTUAL companion held original grant beyond source cutoff: independent API/session NULL and both observed spends zero after rollback; original caller/identity interval remained live")
	check, source = refresh()
	source.FreshUntil = source.FreshUntil.Add(-250 * time.Millisecond)
	r, first, permit, err := executions.PreparePolicyRecording(ctx, check, source)
	if err != nil || !first || !permit.ValidFinite(clock()) || !r.Binding.NotAfter.Equal(check.ValidUntil) || r.Binding.NotAfter.Equal(source.FreshUntil) {
		t.Fatalf("actual finite companion preparation/unchanged identity: first=%v API=%+v permit=%+v err=%v", first, r.Binding, permit, err)
	}
	const credit = int64(32 << 20)
	if permit.Credit != credit || permit.BytesPerSecond != 16<<20 || permit.Duration != time.Second || permit.Binding.CaptureID != accepted.CaptureID || permit.Binding.ActionID != e.ActionID || permit.Binding.ExpectationDigest != [32]byte(evidence.ContextExpectationDigest(e)) || permit.Binding.ProgramDigest != [32]byte(planning.FilterProgramDigest(program)) {
		t.Fatal("actual companion bound wrong original values", permit)
	}
	read(credit)
	originalSource := source
	again, second, original, err := executions.PreparePolicyRecording(ctx, check, source)
	if err != nil || second || !reflect.DeepEqual(again, r) || original != permit {
		t.Fatal("actual exact companion replay rearmed/refilled", second, err)
	}
	read(credit)
	if !check.Valid(clock()) || !source.Valid(clock()) {
		t.Fatal("fixture lost live facts before epoch-only refusal")
	}
	source.CollectorEpoch = custodyID()
	if _, first, p, err := executions.PreparePolicyRecording(ctx, check, source); err == nil || first || p != (collector.ObservationPermit{}) {
		t.Fatal("actual companion rebound original session to replacement epoch", first, err)
	}
	read(credit)
	t.Logf("ACTUAL companion initial/replay: one API preparation +one session; accepted/grant input reservation=%d each, sequence1, canonical program+expectation matched, original start/end unchanged", credit)
	// Reuse only the original positively acknowledged receipt. The passive replay
	// above never creates keys, queues a second work item or issues more input.
	bound, err := store.ForCustody(e.Registration.StoreID)
	if err != nil {
		t.Fatal(err)
	}
	producer, err := objectstore.NewArtifactProducer(bound, keys, recordingJournal{}, clock)
	if err != nil {
		t.Fatal(err)
	}
	preparedArtifact, err := producer.Prepare(ctx, e, "")
	if err != nil {
		t.Fatal("raw component output preparation", err)
	}
	holder := bootstrap.NewConnectorRecordings(channel, nil, clock, func(line string) { t.Log(line) })
	channel.SetPacketSink(holder)
	prepared := holder.Prepare(preparedArtifact, e)
	defer prepared.Close()
	r, err = executions.BindAPIStart(ctx, check, r, executionvalue.PreparedStart{ObjectUID: custodyID(), ResourceVersion: "1"})
	if err != nil {
		t.Fatal(err)
	}
	disposition := executionvalue.Disposition{ObjectUID: r.ObjectUID, ResourceVersion: "2", Phase: executionvalue.StartCommitted, CommittedAt: clock(), MayStart: true, ValidUntil: r.Binding.NotAfter}
	r, err = executions.RecordAPIStart(ctx, check, r, disposition)
	if err != nil {
		t.Fatal(err)
	}
	if !originalSource.Valid(clock()) || !permit.ValidFinite(clock()) {
		t.Fatal("fixture consumed original source/start before typed holder")
	}
	queued, err := prepared.StartPolicyRecording(ctx, accepted.Pin, r.StartedAt, disposition.ValidUntil, originalSource, permit)
	if err != nil {
		t.Fatal("actual typed policy holder", err)
	}
	work, err := channel.Poll(ctx, peer, epoch, 0, 0)
	if err != nil || len(work) != 1 || work[0].Packet.Observation == nil || *work[0].Packet.Observation != permit || !work[0].NotAfter.Equal(permit.StartBy) {
		t.Fatal("actual queue original finite work", work, err)
	}
	// Synthetic PCAPNG enters the actual producer path after the finite interval.
	// This is not a Gadget run, metered input measurement or native qualification.
	native := syntheticFilteredRecording(t, queued.Add(100*time.Millisecond), program, 2)
	resultPacket := collector.PacketResult{WorkID: work[0].ID, CaptureID: accepted.CaptureID, StartedAt: queued.Add(100 * time.Millisecond), EndedAt: queued.Add(1100 * time.Millisecond), Seen: 50, Retained: 50, CapturedBytes: int64(len(native)), Snaplen: artifact.RecordingSnaplen, ProgramDigest: work[0].Packet.ProgramDigest}
	if !resultPacket.Valid() {
		t.Fatal("assembled synthetic packet result invalid", resultPacket)
	}
	if wait := time.Until(resultPacket.EndedAt); wait > 0 {
		time.Sleep(wait)
	}
	if err = channel.DeliverPacket(ctx, peer, epoch, resultPacket, bytes.NewReader(native)); err != nil {
		t.Fatal("actual channel/holder storage", err)
	}
	if err = channel.DeliverPacket(ctx, peer, epoch, resultPacket, bytes.NewReader(native)); err == nil {
		t.Fatal("duplicate finite delivery accepted")
	}
	signed := fleet.APIContextWork{CaptureID: accepted.CaptureID, AttemptID: e.Registration.Location.AttemptID, ExpectationDigest: evidence.ContextExpectationDigest(e)}
	collected, err := holder.Collect(signed)
	if err != nil || collected.State != evidence.RecordingStored || !collected.Completion.Valid(e.Registration) {
		t.Fatal("actual stored/joined completion", collected, err)
	}
	// Outcome facts refresh only this same process/recovery observation. They do
	// not reissue the grant, source, lease, packet action or observation credit.
	processAt := clock()
	currentRecovery, err := s.recovery.reader.RecoveryState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	r.CompletedAt = collected.Completion.StoredAt
	r.Phase = "stored"
	r.Copies = collected.Completion.Copies
	r.AcquiredAt = collected.Acquired
	r, err = executions.RecordAPIStoredCompletion(ctx, r, collected.Completion, executionvalue.APIProcessObservation{Binding: process, CheckedAt: processAt, ValidUntil: processAt.Add(5 * time.Second)}, currentRecovery)
	if err != nil {
		t.Fatal("actual finite stored completion ACK", err)
	}
	t.Logf("ACTUAL companion -> typed holder -> exact channel -> joined encrypted producer -> stored SQL ACK; synthetic node/process/packet inputs, node=%s, synthetic PCAPNG bytes=%d, INPUT RESERVATION=%d unchanged", nodeIdentity.NodeUID, len(native), credit)
	if len(protected) > 0 {
		protected[0].Stored(policyObservationRetirementInput{Scenario: s, Accepted: accepted, Execution: r, Completion: collected.Completion, Permit: permit, AcceptanceID: acceptance, GrantID: grant, Before: before})
		return
	}
	qualifyPolicyObservationRetirement(t, ctx, admin, poolFor, store, keys, policyObservationRetirementInput{Scenario: s, Accepted: accepted, Execution: r, Completion: collected.Completion, Permit: permit, AcceptanceID: acceptance, GrantID: grant, Before: before})
	// A new caller may observe current facts, but cannot turn the terminal
	// original attempt back into a preparation or create a replacement session.
	check, source = refresh()
	if !check.Valid(clock()) || !source.Valid(clock()) {
		t.Fatal("terminal-refusal preflight lost fresh original-identity facts")
	}
	if _, first, p, err := executions.PreparePolicyRecording(ctx, check, source); err == nil || first || p != (collector.ObservationPermit{}) {
		t.Fatal("retired original attempt rearmed with fresh caller facts", first, err)
	}
	var children, apiRows, acceptedInput, grantInput int64
	if err = admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM policy_observation_session WHERE root_id=$1 AND capture_id=$2),
       (SELECT count(*) FROM context_execution WHERE root_id=$1 AND capture_id=$2 AND phase='stored'),a.observed_bytes_spent,g.policy_observed_bytes_spent
       FROM policy_acceptance a JOIN access_grant g ON g.root_id=a.root_id AND g.id=$4 WHERE a.root_id=$1 AND a.id=$3`, s.a.RootID, accepted.CaptureID, acceptance, grant).Scan(&children, &apiRows, &acceptedInput, &grantInput); err != nil || children != 0 || apiRows != 1 || acceptedInput != credit || grantInput != credit {
		t.Fatal("terminal refusal changed retained receipt or spend", children, apiRows, acceptedInput, grantInput, err)
	}
	t.Log("ACTUAL companion fresh-input terminal refusal retains original stored API receipt, zero observation children and unchanged conservative INPUT RESERVATIONS")
}

// Synthetic node trust exists only in this SQL/storage component fixture. The
// queue, source comparison, result ownership and holder storage are real code.
type policyObservationNode struct{ identity collector.Identity }

func (n policyObservationNode) PrecheckNode([]byte) error { return nil }
func (n policyObservationNode) AttestNode(context.Context, []byte, string) (collector.Identity, error) {
	return n.identity, nil
}

type policyObservationNodeIssuer struct{}

func (policyObservationNodeIssuer) IssueNode([]byte, collector.Identity, time.Time) ([]byte, [32]byte, error) {
	b := []byte("synthetic-policy-component-certificate")
	return b, sha256.Sum256(b), nil
}

func TestPolicyObservationSyntheticPacketProgram(t *testing.T) {
	// Construct through the maintained recorder using the exact reviewed program,
	// with SYN set in every synthetic frame. This opens no device or socket.
	if out := syntheticFilteredRecording(t, time.Now(), policyRawProgram, 2); len(out) == 0 {
		t.Fatal("missing synthetic filtered PCAPNG")
	}
}
