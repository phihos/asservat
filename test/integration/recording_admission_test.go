package integration

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/packets"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/application/evidence"
	executionapp "asservat.local/asservat/internal/application/execution"
	"asservat.local/asservat/internal/application/planning"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/bootstrap"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/collector"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/fleet"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"github.com/jackc/pgx/v5/pgxpool"
)

// recordingProgram is libpcap 1.11.0's "tcp dst port 80" on EN10MB (the
// feasibility corpus); the hub compiler itself is tested under the libpcap tag.
var recordingProgram = []planvalue.BPFInstruction{{Code: 0x28, K: 12}, {Code: 0x15, Jf: 4, K: 0x86dd}, {Code: 0x30, K: 20}, {Code: 0x15, Jf: 11, K: 6}, {Code: 0x28, K: 56},
	{Code: 0x15, Jt: 8, Jf: 9, K: 80}, {Code: 0x15, Jf: 8, K: 0x800}, {Code: 0x30, K: 23}, {Code: 0x15, Jf: 6, K: 6}, {Code: 0x28, K: 20}, {Code: 0x45, Jt: 4, K: 0x1fff},
	{Code: 0xb1, K: 14}, {Code: 0x48, K: 16}, {Code: 0x15, Jf: 1, K: 80}, {Code: 0x06, K: 65535}, {Code: 0x06}}

type recordingCompiler struct{}

func (recordingCompiler) CompileFilter(string) (planvalue.CompiledFilter, error) {
	return planvalue.CompiledFilter{LinkType: planvalue.FilterLinkType, Snaplen: planvalue.FilterSnaplen, Program: append([]planvalue.BPFInstruction(nil), recordingProgram...)}, nil
}

// recordingNodes stands in for the node channel: one current node that offers
// the packet recorder; queued work is recorded.
type recordingNodes struct {
	work []collector.Work
}

func (n *recordingNodes) NodeByName(name string) (delivery.NodeView, bool) {
	r := &collector.Report{Mechanisms: []collector.Availability{{Mechanism: collector.MechanismPacket, Prerequisites: true, Adapter: collector.AdapterAvailable, Hook: collector.HookTC}}}
	return delivery.NodeView{Identity: collector.Identity{NodeName: name, NodeUID: "node-uid"}, Report: r, Current: true}, name == "worker"
}

func (n *recordingNodes) EnqueuePacket(uid string, p collector.PacketCapture, startBy time.Time) (collector.Work, error) {
	w := collector.Work{ID: custodyID(), Sequence: uint64(len(n.work) + 1), Kind: collector.WorkPacketCapture, NotAfter: startBy, Packet: &p}
	n.work = append(n.work, w)
	return w, nil
}

type recordingPods struct{}

func (recordingPods) PodNode(context.Context, artifact.PinnedPod) (string, error) {
	return "worker", nil
}

type recordingJournal struct{}

func (recordingJournal) AdvanceStreaming(context.Context, artifact.StreamingPlan, artifact.StreamingStep) (artifact.StreamingState, bool, error) {
	return artifact.StreamingState{}, false, artifact.ErrInvalid
}

type recordingProcess struct{ p value.APIProcessObservation }

func (r *recordingProcess) ReadAPIProcess(context.Context) (value.APIProcessObservation, error) {
	n := time.Now().UTC().Truncate(time.Microsecond)
	r.p.CheckedAt, r.p.ValidUntil = n, n.Add(5*time.Second)
	return r.p, nil
}

type recordingCollect struct {
	h *bootstrap.ConnectorRecordings
	w fleet.APIContextWork
}

func (c recordingCollect) CollectRecording(context.Context) (evidence.RecordingCollection, error) {
	return c.h.Collect(c.w)
}

// syntheticRecording is a headers-only PCAPNG of synthetic TCP frames, as
// the node's recorder writes it.
func syntheticRecording(t *testing.T, started time.Time) []byte {
	t.Helper()
	return syntheticFilteredRecording(t, started, recordingProgram, 0)
}

func syntheticFilteredRecording(t *testing.T, started time.Time, program []planvalue.BPFInstruction, flags byte) []byte {
	t.Helper()
	rec, err := packets.NewRecorder(program, 1<<20, started, "synthetic")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		ip := []byte{0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2}
		tcp := make([]byte, 20)
		binary.BigEndian.PutUint16(tcp[0:2], 40000)
		binary.BigEndian.PutUint16(tcp[2:4], 80)
		tcp[12] = 5 << 4
		tcp[13] = flags
		payload := strings.Repeat("SYNTHETIC-MARKER", 8)
		binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)+len(tcp)+len(payload)))
		f := append(append(append([]byte{0, 1, 2, 3, 4, 5, 0, 1, 2, 3, 4, 6, 8, 0}, ip...), tcp...), payload...)
		rec.Add(f[:packets.Snaplen], uint32(len(f)), started.Add(time.Duration(i)*time.Millisecond))
	}
	out, counters, err := rec.Close(started.Add(time.Second), 0)
	if err != nil || counters.Retained != 50 {
		t.Fatal(counters, err)
	}
	return append([]byte(nil), out...)
}

// qualifyRecordingTransactions is ADR-248's component path on real
// PostgreSQL/S3: admission of an accepted manual networkHeaders recording,
// the ADR-171 execution up to the committed start, the connector holder
// (queue on the node, encrypted store of the node's PCAPNG, collect), the
// stored completion, publication with the headers-only recheck and a native
// read of the exact bytes.
func qualifyRecordingTransactions(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, create func(*testing.T) captureAdmissionScenario) {
	t.Helper()
	qualifyApprovedRecording(t, ctx, admin, poolFor, create)
	t.Run("recording-admission-collect-publish-native-read", func(t *testing.T) {
		s := create(t)
		if s.a.Registration.NativeLimit != artifact.RecordingNativeLimit {
			t.Fatal("recording scenario limit", s.a.Registration.NativeLimit)
		}
		in := s.a.Plan.Input
		in.Target.ExecutionClass, in.Capability.ExecutionClass = artifact.ContextAPIExecution, artifact.ContextAPIExecution
		in.Target.NodeUID, in.Target.NodeBootID, in.Target.Pin.NodeName = "", "", ""
		policies, err := s.retention.policies(ctx)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		retention, err := privacy.Resolve(policies, privacy.Input{Target: in.Target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: "packetCapture", AnchorAt: s.a.Registration.AnchorAt}, now)
		if err != nil {
			t.Fatal(err)
		}
		in.Retention = retention
		composition := planvalue.ProfileComposition{Components: []planvalue.ProfileComponent{{ID: "net", Profile: planvalue.ProfileRef{Catalog: "builtin", Name: "network-connections", Version: "v1"},
			Edits: []planvalue.ProfileEdit{{ActionID: "sample", Field: "packetFilter", Text: "tcp dst port 80"}, {ActionID: "sample", Field: "packetAfter", Text: "2s"}}}}, MaxTotalBytes: 16 << 20, MaxDuration: "20s"}
		reviewed, err := planning.CompileRecorder(planvalue.RecorderInput{CaptureID: in.CaptureID, Executor: in.Executor, Target: in.Target, Composition: composition, Retention: retention, Deadline: in.Deadline, NodeRecorder: true}, recordingCompiler{}, now)
		if err != nil {
			t.Fatal(err)
		}
		if in.Recorder, err = planning.RecorderContextFromScope(composition, reviewed.CanonicalScope); err != nil {
			t.Fatal(err)
		}
		if s.a.Plan, err = planning.CompileContext(in, now); err != nil || s.a.Plan.ScopeDigest != reviewed.ScopeDigest {
			t.Fatal("accepted plan differs from the reviewed recorder plan", err)
		}
		s.a.Registration.ExpiresAt, s.a.Registration.DeleteBy = retention.ExpiresAt, retention.DeleteBy
		accepted, err := s.s.AdmitContext(ctx, s.a)
		if err != nil {
			t.Fatal(err)
		}
		e := accepted.Expectation
		if e.NativeType != artifact.PCAPNGArtifact || e.Recording == nil || e.Recording.Filter == nil || e.Recording.DurationMillis != 2000 || e.Recording.MaxBytes != artifact.RecordingNativeLimit || e.ActionID != reviewed.Actions[0].ID {
			t.Fatalf("accepted recording %+v", e)
		}
		initializeProcessingTestFixture(t, ctx, poolFor, store, keys, s, e)
		pool := func(user, password string) *pgxpool.Pool { p := poolFor(user, password); t.Cleanup(p.Close); return p }
		sharedPools, _ := compiledOrdinaryHubPools(t, ctx, admin, poolFor)
		t.Cleanup(func() {
			sharedPools.ordinary.Close()
			for _, reserved := range sharedPools.resolution {
				reserved.Close()
			}
		})
		guards := postgres.EffectTransactionGuards{Retention: s.retention.guard, Recovery: s.recovery.guard}
		executions, err := postgres.NewAPIContextExecutions(ctx, sharedPools.ordinary, s.a.RootID, guards)
		if err != nil {
			t.Fatal(err)
		}
		intents, err := postgres.NewCaptureIntentAudits(ctx, pool("capture_audit_runtime", "synthetic-capture-audit"), s.a.RootID)
		if err != nil {
			t.Fatal(err)
		}
		if err = (auditapp.CaptureIntentPublisher{Ledger: intents, Objects: &objectstore.CaptureIntentObjects{Store: store, Seal: keys, Open: keys}}).PublishCaptureIntents(ctx); err != nil {
			t.Fatal(err)
		}
		// The ADR-171 check of a recording recompiles its recorder plan with
		// the retention of its own evidence type.
		n := time.Now().UTC().Truncate(time.Microsecond)
		s.batch.ObservedAt, s.batch.FreshUntil, s.batch.Initial = n, n.Add(5*time.Second), nil
		if err = s.p.RefreshPermissions(ctx, s.batch); err != nil {
			t.Fatal(err)
		}
		verified := s.a.Eligibility.VerifiedIdentity
		verified.VerifiedAt, verified.ValidUntil = n, n.Add(5*time.Second)
		recovery, err := s.recovery.reader.RecoveryState(ctx)
		if err != nil {
			t.Fatal(err)
		}
		work, err := executions.ReadAPIContextWork(ctx, accepted.CaptureID, verified, recovery)
		if err != nil {
			t.Fatal(err)
		}
		projection, err := s.p.Permissions(ctx, s.a.Eligibility.Target)
		if err != nil {
			t.Fatal(err)
		}
		eligible := authorization.ContextEligibility(verified, projection, s.a.Eligibility.Target, time.Now())
		current := s.a.Plan.Input
		current.Target.ObservedAt, current.Target.FreshUntil = n, n.Add(5*time.Second)
		current.Capability.ObservedAt, current.Capability.FreshUntil = n, n.Add(5*time.Second)
		if current.Retention, err = privacy.Resolve(policies, privacy.Input{Target: current.Target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: e.Type().EvidenceType, RequestedSeconds: e.RequestedAgeSeconds, AnchorAt: e.Registration.AnchorAt}, time.Now()); err != nil {
			t.Fatal(err)
		}
		recorder, err := planning.RecorderContextFor(e.Recording)
		if err != nil {
			t.Fatal(err)
		}
		current.Recorder = recorder
		plan, err := planning.CompileContext(current, time.Now())
		if err != nil || plan.ScopeDigest != e.PlanDigest {
			t.Fatal("execution plan of the recording", err)
		}
		process := value.APIProcessObservation{Binding: value.APIProcessBinding{InstallationID: recovery.InstallationID, ClusterID: current.Target.Target().ClusterID, IssuerEpoch: recovery.IssuerEpoch, NamespaceUID: custodyID(), AccountUID: custodyID(), PodUID: custodyID(), ProcessEpoch: custodyID(), StartupDigest: artifact.Digest{1}, ImageDigest: e.CollectorImageDigest}, CheckedAt: n, ValidUntil: n.Add(5 * time.Second)}
		until := n.Add(5 * time.Second)
		for _, d := range []time.Time{eligible.ValidUntil, plan.ValidUntil, recovery.FreshUntil, process.ValidUntil} {
			if d.Before(until) {
				until = d
			}
		}
		check := executionapp.APIExecutionCheck{Work: work, Plan: plan, Eligibility: eligible, Recovery: recovery, Process: process, CheckedAt: n, ValidUntil: until.Truncate(time.Microsecond)}
		if !check.Valid(time.Now()) {
			t.Fatal("invalid recording execution check")
		}
		execution, first, err := executions.PrepareAPIExecution(ctx, check)
		if err != nil || !first || execution.Binding.NativeBytes != artifact.RecordingNativeLimit || execution.Binding.ActionID != e.ActionID {
			t.Fatalf("recording preparation %+v %v %v", execution.Binding, first, err)
		}
		// The connector prepares the attempt's keys and holds them for the
		// recording; no SQL streaming journal exists there.
		bound, err := store.ForCustody(e.Registration.StoreID)
		if err != nil {
			t.Fatal(err)
		}
		producer, err := objectstore.NewArtifactProducer(bound, keys, recordingJournal{}, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		preparedArtifact, err := producer.Prepare(ctx, e, "")
		if err != nil {
			t.Fatal(err)
		}
		nodes := &recordingNodes{}
		holder := bootstrap.NewConnectorRecordings(nodes, recordingPods{}, time.Now, func(line string) { t.Log(line) })
		prepared := holder.Prepare(preparedArtifact, e)
		if execution, err = executions.BindAPIStart(ctx, check, execution, value.PreparedStart{ObjectUID: custodyID(), ResourceVersion: "1"}); err != nil {
			t.Fatal(err)
		}
		d := value.Disposition{ObjectUID: execution.ObjectUID, ResourceVersion: "2", Phase: value.StartCommitted, CommittedAt: time.Now().UTC().Truncate(time.Microsecond), MayStart: true, ValidUntil: execution.Binding.NotAfter}
		if execution, err = executions.RecordAPIStart(ctx, check, execution, d); err != nil {
			t.Fatal(err)
		}
		queued, err := prepared.StartRecording(ctx, accepted.Pin, execution.StartedAt, d.ValidUntil)
		if err != nil || len(nodes.work) != 1 {
			t.Fatal("start recording", err)
		}
		w := nodes.work[0]
		if p := w.Packet; p.CaptureID != accepted.CaptureID || p.PodUID != e.PodUID || p.Duration != 2*time.Second || p.MaxBytes != artifact.RecordingNativeLimit || len(p.Program) != len(recordingProgram) || p.ProgramDigest != [32]byte(planning.FilterProgramDigest(recordingProgram)) {
			t.Fatalf("node work %+v", w.Packet)
		}
		// Collect before the node delivered: still recording.
		signed := fleet.APIContextWork{CaptureID: accepted.CaptureID, AttemptID: e.Registration.Location.AttemptID, ExpectationDigest: evidence.ContextExpectationDigest(e)}
		if c, err := holder.Collect(signed); err != nil || c.State != evidence.RecordingPending {
			t.Fatal("pending collect", c, err)
		}
		listed, err := executions.StartedRecordings(ctx, time.Now(), 16)
		if err != nil || len(listed) != 1 || listed[0] != accepted.CaptureID {
			t.Fatal("started recordings", listed, err)
		}
		// The node delivers its headers-only PCAPNG.
		native := syntheticRecording(t, queued.Add(100*time.Millisecond))
		result := collector.PacketResult{WorkID: w.ID, CaptureID: accepted.CaptureID, StartedAt: queued.Add(100 * time.Millisecond), EndedAt: queued.Add(1100 * time.Millisecond), Seen: 50, Retained: 50, CapturedBytes: int64(len(native)), Snaplen: packets.Snaplen, ProgramDigest: w.Packet.ProgramDigest}
		for time.Now().Before(result.EndedAt) {
			time.Sleep(50 * time.Millisecond)
		}
		if err = holder.DeliverPacket(ctx, collector.Identity{NodeName: "worker", NodeUID: "node-uid"}, result, bytes.NewReader(native)); err != nil {
			t.Fatal(err)
		}
		if err = holder.DeliverPacket(ctx, collector.Identity{NodeName: "worker", NodeUID: "node-uid"}, result, bytes.NewReader(native)); err == nil {
			t.Fatal("a second delivery was stored")
		}
		readWork, readExecution, err := executions.ReadRecordingWork(ctx, accepted.CaptureID, recovery)
		if err != nil || readExecution.Phase != "started" || readWork.Accepted.CaptureID != accepted.CaptureID {
			t.Fatal("read recording work", err)
		}
		runner := executionapp.APIContextRunner{Record: executions, Process: &recordingProcess{process}, Recovery: s.recovery.reader, Now: time.Now}
		got, err := runner.CollectRecording(ctx, readWork, readExecution, recordingCollect{holder, signed})
		if err != nil || got.State != "StoredPendingVerification" {
			t.Fatal("collect", got, err)
		}
		if listed, err = executions.StartedRecordings(ctx, time.Now(), 16); err != nil || len(listed) != 0 {
			t.Fatal("a stored recording is still listed", listed, err)
		}
		var phase string
		var copies []byte
		if err = admin.QueryRow(ctx, "SELECT phase,copies_json FROM context_execution WHERE capture_id=$1", accepted.CaptureID).Scan(&phase, &copies); err != nil || phase != "stored" {
			t.Fatal("stored phase", phase, err)
		}
		// Publication: full verification with the headers-only recheck.
		publication := func(user, password string) *postgres.ContextPublications {
			p, e := postgres.NewContextPublications(ctx, pool(user, password), s.a.RootID, guards)
			if e != nil {
				t.Fatal(e)
			}
			return p
		}
		verify := publication("context_verify_runtime", "synthetic-context-verify")
		audit := publication("context_verification_audit_runtime", "synthetic-context-audit")
		publish := publication("context_publish_runtime", "synthetic-context-publish")
		gate, err := postgres.NewAPIContextPublicationGate(ctx, pool("api_publication_gate_runtime", "synthetic-api-publication-gate"), s.a.RootID, guards, privacyapp.RetentionResolver{RetainedPolicies: s.retention, Now: time.Now}, s.recovery.reader)
		if err != nil {
			t.Fatal(err)
		}
		verifier, err := objectstore.NewContextVerifier(bound, keys)
		if err != nil {
			t.Fatal(err)
		}
		checked := 0
		verifier.WithStreamCheck(artifact.PCAPNGArtifact, func() objectstore.StreamCheck { checked++; return packets.NewHeadersCheck() })
		s.batch.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
		s.batch.FreshUntil = s.batch.ObservedAt.Add(5 * time.Second)
		if err = s.p.RefreshPermissions(ctx, s.batch); err != nil {
			t.Fatal(err)
		}
		unwraps := qualifyContextKeyUnwraps(t, ctx, admin, poolFor, s, e, accepted.CaptureID)
		p := evidence.ContextPublisher{Ledger: evidence.ContextPublicationFacets{ContextAcceptanceReader: verify, ContextVerificationRecorder: verify, ContextVerificationAuditor: audit, ContextCatalogPublisher: publish}, Authority: gate, Verifier: verifier, Audit: &objectstore.ContextVerificationObjects{Store: store, Seal: keys, Open: keys}, Now: time.Now}
		col := got.Copies
		published, err := p.Publish(ctx, accepted.CaptureID, col)
		if err != nil {
			t.Fatal("publication of the recording", err)
		}
		unwraps.afterPublication(ctx, accepted.CaptureID)
		if checked != 1 {
			t.Fatal("headers-only recheck not run", checked)
		}
		source, err := verifier.OpenNative(ctx, published.Expectation, published.Copies, time.Now().Add(30*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		defer source.Close()
		if m := source.Metadata(); !strings.HasSuffix(m.Filename, ".pcapng") || m.Format != artifact.PCAPNGFormat {
			t.Fatalf("native metadata %+v", m)
		}
		var read []byte
		for offset := int64(0); ; {
			chunk, verified, err := source.ReadNext(ctx, offset, min(int64(1<<20), source.Metadata().Size-offset))
			if err != nil || !verified {
				t.Fatal(err)
			}
			read = append(read, chunk...)
			offset += int64(len(chunk))
			if offset == source.Metadata().Size {
				break
			}
		}
		if !bytes.Equal(read, native) || bytes.Contains(read, []byte("SYNTHETIC-MARKER")) {
			t.Fatal("downloaded PCAPNG differs from the node's capture")
		}
		if n, err := packets.CheckHeadersOnly(bytes.NewReader(read)); err != nil || n != 50 {
			t.Fatal(n, err)
		}
		_ = io.EOF
	})
}
