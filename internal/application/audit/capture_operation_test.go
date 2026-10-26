package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

func captureOperationFixture(t *testing.T) (value.OperationIntent, *OperationMAC) {
	t.Helper()
	in, mac, e := captureOperationFixtureFor(t, nil)
	if e != nil || !in.Valid() {
		t.Fatal("synthetic accepted intent", e)
	}
	return in, mac
}

func captureOperationFixtureFor(t *testing.T, actor *identity.Principal) (value.OperationIntent, *OperationMAC, error) {
	t.Helper()
	base := auditIntent()
	if actor != nil {
		base.Actor = *actor
	}
	base.CreatedAt = time.Now().UTC().Truncate(time.Microsecond)
	base.Name = value.CaptureOperationName
	c := value.CaptureIntent{RootID: base.RootID, CaptureID: base.ID, CaseID: base.RootID, OccurrenceID: base.ID, ArtifactID: base.RootID, AttemptID: base.ID, Actor: base.Actor, Target: authorization.Target{ClusterID: base.RootID, NamespaceUID: "namespace", WorkloadUID: "workload", PodUID: "pod"}, ScopeDigest: artifact.Digest{1}, SubmissionDigest: artifact.Digest{2}, ExpectationDigest: artifact.Digest{3}, PermissionEpoch: base.RootID, PermissionSequence: 1, IdentityRevision: identity.Revision{UID: "identity", Generation: 1, Digest: artifact.Digest{4}}, CreatedAt: base.CreatedAt, Deadline: base.CreatedAt.Add(30 * time.Second), ExpiresAt: base.CreatedAt.Add(time.Minute), DeleteBy: base.CreatedAt.Add(2 * time.Minute), ReservedBytes: 4096}
	mac, e := NewOperationMAC("input-v1", bytes.Repeat([]byte{1}, 32), "account-v1", bytes.Repeat([]byte{2}, 32))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(mac.Close)
	p := healthyPolicy(base)
	p.Lane = "capture"
	p.History.Layout = value.CaptureOperationHistoryLayout
	b, w := p.History.SlotBacking(p.MaxPurgeLeases)
	p.BackupReservedBytes = b * p.MetadataSlots
	p.WALReservedBytes = w * p.MetadataSlots
	d, e := mac.CaptureAccount(p.InstallationID, c.RootID, c.RootID)
	if e != nil {
		t.Fatal(e)
	}
	a := value.CaptureAuditAccount{RootID: c.RootID, AllocationID: c.RootID, AccountVersion: mac.AccountVersion(), AccountDigest: d, Revision: 1, Records: 10, RetainedSeconds: 3600, Policy: p}
	in, e := PrepareCaptureOperation(c, a, mac, c.CreatedAt.Add(5*time.Second))
	return in, mac, e
}

// ADR-228: an accepted policy's exact executor is a capture actor; any other
// workload identity is not.
func TestCaptureOperationAcceptsOnlyTheExactPolicyExecutor(t *testing.T) {
	executor := authorization.PolicyPrincipal("11111111-1111-4111-8111-111111111111", "policy-uid")
	if in, _, e := captureOperationFixtureFor(t, &executor); e != nil || !in.Valid() || in.Capture.Actor != executor {
		t.Fatal("policy executor capture intent refused", e)
	}
	other := executor
	other.ClientID = "connector"
	if in, _, e := captureOperationFixtureFor(t, &other); e == nil && in.Valid() {
		t.Fatal("arbitrary workload accepted as capture actor")
	}
}
func TestCaptureOperationClosedPrivatePayload(t *testing.T) {
	in, _ := captureOperationFixture(t)
	for _, change := range []func(*value.OperationIntent){
		func(x *value.OperationIntent) { x.Name = "request_capture" },
		func(x *value.OperationIntent) { x.Capture = nil },
		func(x *value.OperationIntent) { x.Actor.Subject = "another" },
		func(x *value.OperationIntent) { x.ID = x.RootID },
		func(x *value.OperationIntent) { x.InputFormat = "context-input/v1" },
		func(x *value.OperationIntent) { x.WriteUntil = x.Capture.Deadline.Add(time.Microsecond) },
		func(x *value.OperationIntent) { p := *x.Lifecycle; p.Policy.Lane = "normal"; x.Lifecycle = &p },
		func(x *value.OperationIntent) {
			p := *x.Lifecycle
			q := *p.Policy.History
			q.Layout = value.OperationVerificationHistoryLayout
			p.Policy.History = &q
			x.Lifecycle = &p
		},
	} {
		copy := in
		change(&copy)
		if copy.Valid() {
			t.Fatal("private intent accepted a changed binding")
		}
	}
	old := auditIntent()
	b, e := json.Marshal(old)
	if e != nil || bytes.Contains(b, []byte("Capture")) {
		t.Fatal("historical absent-field bytes changed")
	}
}

type capturePublicationFixture struct {
	*healthyFixture
	reads           map[string]int
	failRead        bool
	paired          int
	now             time.Time
	afterRead       func()
	afterAck        func()
	writeUntil      time.Time
	passiveOverride *CaptureOperationIntentSnapshot
	passiveErr      error
	afterPassive    func()
	journalReads    int
	readUntil       time.Time
}

func (f *capturePublicationFixture) ReadCaptureOperationIntent(_ context.Context, id string) (CaptureOperationIntentSnapshot, error) {
	out := CaptureOperationIntentSnapshot{Intent: *f.snap.Intent.Capture, OperationID: f.snap.Intent.ID}
	if f.paired > 0 {
		r := receipt(f.snap.Intent, "intent")
		out.Receipt = &r
	}
	if f.passiveOverride != nil {
		out = *f.passiveOverride
	}
	if f.afterPassive != nil {
		f.afterPassive()
	}
	return out, f.passiveErr
}
func (f *capturePublicationFixture) ReadCaptureOperation(_ context.Context, id string) (value.OperationSnapshot, error) {
	f.journalReads++
	if id != f.snap.Intent.ID {
		return value.OperationSnapshot{}, ErrUnavailable
	}
	return f.snap, nil
}
func (f *capturePublicationFixture) ClaimCaptureReconciliation(_ context.Context, in value.OperationIntent, phase string) (value.CaptureReconciliationClaim, error) {
	if f.reads == nil {
		f.reads = map[string]int{}
	}
	if f.reads[phase] >= value.CaptureOperationReconcileAttempts {
		return value.CaptureReconciliationClaim{}, ErrUnavailable
	}
	f.reads[phase]++
	until := in.WriteUntil
	if !f.readUntil.IsZero() {
		until = f.readUntil
	}
	return value.CaptureReconciliationClaim{Attempt: int64(f.reads[phase]), Until: until}, nil
}
func (f *capturePublicationFixture) AcknowledgeReconciledCapture(ctx context.Context, in value.OperationIntent, phase string, r value.Receipt, c value.CaptureReconciliationClaim) error {
	if !c.Valid() || !f.now.Before(c.Until) {
		return ErrUnavailable
	}
	return f.AcknowledgeOperation(ctx, in, phase, r)
}
func (f *capturePublicationFixture) AcknowledgeCapturePair(_ context.Context, in value.OperationIntent) error {
	if f.snap.IntentReceipt == nil || f.snap.OutcomeReceipt == nil || !sameOperationRecord(in, f.snap.Intent) {
		return ErrUnavailable
	}
	f.paired++
	return nil
}
func (f *capturePublicationFixture) FindOperationIntent(_ context.Context, in value.OperationIntent) (value.Receipt, error) {
	f.finds++
	if f.afterRead != nil {
		f.afterRead()
	}
	if f.failRead {
		return value.Receipt{}, ErrUnavailable
	}
	return receipt(in, "intent"), nil
}
func (f *capturePublicationFixture) FindOperationOutcome(_ context.Context, in value.OperationOutcome) (value.Receipt, error) {
	f.finds++
	if f.failRead {
		return value.Receipt{}, ErrUnavailable
	}
	return receipt(in.Intent, "outcome"), nil
}
func capturePublisher(t *testing.T) (CaptureOperationPublication, *capturePublicationFixture, value.OperationIntent) {
	in, mac := captureOperationFixture(t)
	f := &capturePublicationFixture{healthyFixture: &healthyFixture{operationFixture: &operationFixture{snap: value.OperationSnapshot{Intent: in}}}, now: in.CreatedAt}
	return CaptureOperationPublication{RootID: in.RootID, Completed: f, Journal: f, Acknowledgements: f, Writer: f, Reader: f, MAC: mac, Now: func() time.Time { return f.now }}, f, in
}
func TestCaptureOperationUnknownWriteReceiptNeverManufacturesClosure(t *testing.T) {
	s, f, in := capturePublisher(t)
	f.lose = true
	if _, e := s.AcknowledgedCaptureIntent(context.Background(), in.ID); !errors.Is(e, ErrUnavailable) {
		t.Fatal("lost PUT accepted", e)
	}
	if f.writes != 1 || f.finds != 0 || f.saved["intent"].Protocol != "" {
		t.Fatal("lost write fabricated acknowledgement")
	}
	f.lose = false
	if _, e := s.AcknowledgedCaptureIntent(context.Background(), in.ID); e != nil {
		t.Fatal(e)
	}
	if f.writes != 2 || f.reads["intent"] != 1 || f.saved["intent"].Protocol != "" || f.saved["outcome"].Protocol == "" || f.paired != 1 {
		t.Fatal("reconciliation duplicated intent or manufactured closure")
	}
	if _, e := s.AcknowledgedCaptureIntent(context.Background(), in.ID); e != nil || f.writes != 2 || f.finds != 1 {
		t.Fatal("acknowledged pair performed another object operation", e)
	}
}
func TestCaptureOperationReconciliationIsFiniteAndKeepsUnknownSpend(t *testing.T) {
	s, f, in := capturePublisher(t)
	f.snap.IntentStarted = true
	f.failRead = true
	for i := 0; i < 5; i++ {
		if _, e := s.AcknowledgedCaptureIntent(context.Background(), in.ID); !errors.Is(e, ErrUnavailable) {
			t.Fatal("missing uncertain object accepted")
		}
	}
	if f.writes != 0 || f.finds != 2 || f.reads["intent"] != 2 || !f.snap.IntentStarted || f.paired != 0 {
		t.Fatal("unknown reconciliation restored spend or exceeded read allowance")
	}
}
func TestCaptureOperationPreservesOriginalDeadlineAfterRead(t *testing.T) {
	s, f, in := capturePublisher(t)
	f.snap.IntentStarted = true
	f.afterRead = func() { f.now = in.WriteUntil }
	if _, e := s.AcknowledgedCaptureIntent(context.Background(), in.ID); !errors.Is(e, ErrUnavailable) || f.acks != 0 || f.paired != 0 {
		t.Fatal("late read acknowledged", e)
	}
}
func TestCaptureOperationCancellationDoesNotDetachWrites(t *testing.T) {
	s, f, in := capturePublisher(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := s.AcknowledgedCaptureIntent(ctx, in.ID); !errors.Is(e, ErrUnavailable) || f.writes != 0 || f.finds != 0 {
		t.Fatal("canceled caller acquired work", e)
	}
}

func TestCaptureOperationMaximumCanonicalIdentityFitsPrivateBounds(t *testing.T) {
	in, _ := captureOperationFixture(t)
	// Backslash is the largest JSON expansion per admissible text byte once HTML
	// escaping is disabled. UUIDs and closed enum values retain their exact sizes.
	for _, ch := range []string{"\\", "<", "&", "\u2028"} {
		fill := func(n int) string {
			var b bytes.Buffer
			for b.Len()+len(ch) <= n {
				b.WriteString(ch)
			}
			for b.Len() < n {
				b.WriteByte('x')
			}
			return b.String()
		}
		x := in
		c := *x.Capture
		x.Capture = &c
		x.Actor = identity.Principal{Issuer: fill(2048), Subject: fill(256), ClientID: fill(256), Kind: identity.Human}
		c.Actor = x.Actor
		c.Target.NamespaceUID = fill(64)
		c.Target.WorkloadUID = fill(64)
		c.Target.PodUID = fill(64)
		c.IdentityRevision.UID = fill(64)
		c.IdentityRevision.Generation = 2147483647
		c.PermissionSequence = 1<<63 - 1
		c.ReservedBytes = (16 << 20) - 1
		for i := range c.ScopeDigest {
			c.ScopeDigest[i] = 255
			c.SubmissionDigest[i] = 255
			c.ExpectationDigest[i] = 255
			c.IdentityRevision.Digest[i] = 255
			x.PrincipalDigest[i] = 255
			x.InputDigest[i] = 255
		}
		x.MACVersion = fill(64)
		x.AccountVersion = fill(64)
		p := *x.Lifecycle
		h := *p.Policy.History
		p.Policy.History = &h
		x.Lifecycle = &p
		p.Policy.BackingRevision = 1 << 60
		p.Policy.BackupReservedBytes = 1<<63 - 1
		p.Policy.WALReservedBytes = 1<<63 - 1
		p.Policy.MaxPurgeLeases = 32
		h.MaximumRowFootprintBytes = 16 << 20
		h.MaximumTransitionWALBytes = 64 << 20
		h.BackupCopies = 64
		h.WALCopies = 64
		for i := range h.Digest {
			h.Digest[i] = 255
			p.Policy.PolicyDigest[i] = 255
			p.Policy.BackupProfileDigest[i] = 255
		}
		if !x.Valid() {
			t.Fatal("max-field private record invalid")
		}
		raw, e := EncodeCaptureOperationIntent(x)
		if e != nil || len(raw) > 16<<10 {
			t.Fatal("valid private identity exceeds intent budget", len(raw), e)
		}
		var round value.OperationIntent
		if json.Unmarshal(raw, &round) != nil || !sameOperationRecord(round, x) {
			t.Fatal("private format truncated accepted fields")
		}
		cRaw, e := captureEncoding(c, 8<<10)
		if e != nil || len(cRaw) > 8<<10 {
			t.Fatal("valid capture payload exceeds bound", len(cRaw), e)
		}
		out := value.OperationOutcome{Intent: x, Status: "success", Reason: "prepared", Effect: "accepted", ClientReceipt: "unknown", CaptureIDs: []string{x.ID}, OutputDigest: artifact.Digest{255}, RecordedAt: x.CreatedAt, MetadataUntil: x.RequestUntil}
		rawOut, e := EncodeCaptureOperationOutcome(out)
		if e != nil || len(rawOut) > 24<<10 {
			t.Fatal("valid private outcome exceeds budget", len(rawOut), e)
		}
		if OperationLifecycleDigest(&x) != OperationLifecycleDigest(x) || OperationLifecycleDigest(&out) != OperationLifecycleDigest(out) {
			t.Fatal("stored lifecycle verification changed completion digest")
		}
		if OperationLifecycleDigest(x) == (artifact.Digest{}) || OperationLifecycleDigest(out) == (artifact.Digest{}) {
			t.Fatal("maximum private record lost positive completion digest")
		}
		t.Logf("maximum bounded text: capture=%d intent=%d outcome=%d bytes", len(cRaw), len(raw), len(rawOut))
		x.Actor.Issuer += "x"
		c.Actor = x.Actor
		if _, e = EncodeCaptureOperationIntent(x); e == nil {
			t.Fatal("oversize identity silently truncated or accepted")
		}
	}
}

func (f *capturePublicationFixture) ClaimCaptureWrite(ctx context.Context, in value.OperationIntent, phase string) (value.CaptureWriteClaim, error) {
	fresh, e := f.ClaimOperationWrite(ctx, in, phase)
	until := in.WriteUntil
	if phase == "intent" {
		until = in.RequestUntil
	}
	if !f.writeUntil.IsZero() {
		until = f.writeUntil
	}
	return value.CaptureWriteClaim{Fresh: fresh, Until: until}, e
}
func TestCaptureOperationWriteClaimKeepsShorterRecoveryDeadline(t *testing.T) {
	s, f, in := capturePublisher(t)
	f.writeUntil = in.CreatedAt.Add(-time.Microsecond)
	if _, e := s.AcknowledgedCaptureIntent(context.Background(), in.ID); !errors.Is(e, ErrUnavailable) || f.writes != 0 || f.paired != 0 {
		t.Fatal("expired recovery write claim performed I/O", e)
	}
}
func TestCaptureOperationReadClaimDoesNotRenewDuringAcknowledgement(t *testing.T) {
	s, f, in := capturePublisher(t)
	f.snap.IntentStarted = true
	first := in.CreatedAt.Add(time.Second)
	f.readUntil = first
	f.afterRead = func() { f.now = first; f.readUntil = in.CreatedAt.Add(2 * time.Second) }
	if _, e := s.AcknowledgedCaptureIntent(context.Background(), in.ID); !errors.Is(e, ErrUnavailable) || f.acks != 0 || f.paired != 0 {
		t.Fatal("later read interval renewed first acknowledgement", e)
	}
}

func (f *capturePublicationFixture) AcknowledgeOperation(ctx context.Context, in value.OperationIntent, phase string, r value.Receipt) error {
	e := f.healthyFixture.AcknowledgeOperation(ctx, in, phase, r)
	if f.afterAck != nil {
		f.afterAck()
	}
	return e
}
func TestCaptureOperationFinalAcknowledgementRetainsFirstWriteDeadline(t *testing.T) {
	s, f, in := capturePublisher(t)
	f.afterAck = func() { f.now = in.RequestUntil }
	if _, e := s.AcknowledgedCaptureIntent(context.Background(), in.ID); !errors.Is(e, ErrUnavailable) || f.paired != 0 || f.snap.Outcome != nil {
		t.Fatal("intent acknowledgement continued after original write claim", e)
	}
}

func TestCaptureCompletionDigestCanonicalVersionAndLegacyCompatibility(t *testing.T) {
	in, _ := captureOperationFixture(t)
	raw, e := EncodeCaptureOperationIntent(in)
	if e != nil {
		t.Fatal(e)
	}
	canonical := append([]byte("asservat-capture-completion/v1\x00intent\x00"), raw...)
	if got := OperationLifecycleDigest(in); got != (artifact.Digest(sha256.Sum256(canonical))) {
		t.Fatal("private completion canonical version changed")
	}
	old := struct{ HTML string }{"<legacy>&"}
	b, e := json.Marshal(old)
	if e != nil {
		t.Fatal(e)
	}
	if got := OperationLifecycleDigest(old); got != (artifact.Digest(sha256.Sum256(b))) {
		t.Fatal("legacy semantic digest changed")
	}
	bad := in
	bad.Actor.Subject = ""
	if OperationLifecycleDigest(bad) != (artifact.Digest{}) {
		t.Fatal("invalid capture received a completion digest")
	}
}

func TestCaptureOperationCompletedReadOutlivesWriteCutoffWithoutEffects(t *testing.T) {
	s, f, in := capturePublisher(t)
	f.paired = 1
	f.now = in.WriteUntil.Add(time.Second)
	got, e := s.AcknowledgedCaptureIntent(context.Background(), in.ID)
	if e != nil || got != *in.Capture {
		t.Fatal("complete receipt stranded after original write cutoff", e)
	}
	if f.journalReads != 0 || f.writes != 0 || f.finds != 0 || f.acks != 0 || f.paired != 1 {
		t.Fatal("completed read entered active journal/object path")
	}
	s.Journal = nil
	s.Acknowledgements = nil
	s.Writer = nil
	s.Reader = nil
	s.MAC = nil
	if _, e = s.AcknowledgedCaptureIntent(context.Background(), in.ID); e != nil {
		t.Fatal("historical provenance required writer dependencies", e)
	}
}
func TestCaptureOperationCompletedReadFailureNeverFallsThrough(t *testing.T) {
	for _, mode := range []string{"wrong-protocol", "wrong-root", "wrong-id", "legacy-key", "read-error", "expired-read", "cancelled-read", "pending-expired"} {
		t.Run(mode, func(t *testing.T) {
			s, f, in := capturePublisher(t)
			r := receipt(in, "intent")
			out := CaptureOperationIntentSnapshot{Intent: *in.Capture, OperationID: in.ID, Receipt: &r}
			f.passiveOverride = &out
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "wrong-protocol":
				out.OperationID = in.RootID
			case "wrong-root":
				out.Intent.RootID = in.ID
			case "wrong-id":
				out.Intent.CaptureID = in.RootID
			case "legacy-key":
				r.Key = value.CaptureIntentKey(in.RootID, in.ID)
			case "read-error":
				f.passiveErr = ErrUnavailable
			case "expired-read":
				f.afterPassive = func() { f.now = f.now.Add(5 * time.Second) }
			case "cancelled-read":
				f.afterPassive = cancel
			case "pending-expired":
				out.Receipt = nil
				f.now = in.WriteUntil
			}
			if _, e := s.AcknowledgedCaptureIntent(ctx, in.ID); !errors.Is(e, ErrUnavailable) {
				t.Fatal("invalid retained acknowledgement accepted", e)
			}
			if mode != "pending-expired" && f.journalReads != 0 {
				t.Fatal("malformed/failed read entered active path")
			}
			if f.writes != 0 || f.finds != 0 || f.acks != 0 || f.paired != 0 {
				t.Fatal("invalid retained read acquired effects")
			}
		})
	}
}
