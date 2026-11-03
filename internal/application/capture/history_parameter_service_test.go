package capture

import (
	auditapp "asservat.local/asservat/internal/application/audit"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	privacy "asservat.local/asservat/internal/domain/privacy"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// These fakes isolate composed request ordering. They confer no SQL, storage
// or key authority; the real encrypted custody path has its own native test.
type parameterReadFixture struct {
	f                              *investigationFixture
	storage                        value.HistoryStorage
	params                         value.HistoryParameters
	calls, prepares, opens, closes int
	failInitial, failFinal         bool
	afterOpen                      func()
	originalBound                  time.Time
	// writable opens the write path (ADR-280 retries): failPrepares and
	// failExecutes fail that many attempts first; completed records success.
	writable                   bool
	failPrepares, failExecutes int
	executes                   int
	completed                  bool
	// exclusive refuses a session while another is open, as the router
	// refuses a second attachment for the same capture.
	exclusive bool
	open      int
}

var fixtureHistoryBundle = value.HistoryCiphertexts{[]byte{1}, []byte{2}, []byte{3}, []byte{4}}

func (h *parameterReadFixture) ReserveHistoryParameters(_ context.Context, in value.HistoryReservation) (value.HistoryStorage, error) {
	if !h.writable {
		return value.HistoryStorage{}, value.ErrUnavailable
	}
	return value.HistoryStorage{Expectation: in.Expectation}, nil
}
func (h *parameterReadFixture) ClaimHistoryWrite(ctx context.Context, in value.HistoryWriteRequest) (value.HistoryOperationAuthority, error) {
	if !h.writable {
		return value.HistoryOperationAuthority{}, value.ErrUnavailable
	}
	until, _ := ctx.Deadline()
	return value.HistoryOperationAuthority{Expectation: in.Storage.Expectation, Operation: "write", RequestID: in.RequestID, ExecutorEpoch: in.ExecutorEpoch, StartedAt: h.f.now, NotAfter: until, BundleDigest: in.BundleDigest}, nil
}
func (h *parameterReadFixture) CompleteHistoryWrite(context.Context, value.HistoryWriteResult) error {
	if !h.writable {
		return value.ErrUnavailable
	}
	h.completed = true
	return nil
}
func (h *parameterReadFixture) ReadHistoryStorage(context.Context, value.SettingsQuery) (value.HistoryStorage, bool, error) {
	if h.failInitial {
		return value.HistoryStorage{}, true, value.ErrSettingsUnavailable
	}
	return h.storage, true, nil
}
func (h *parameterReadFixture) AuthorizeHistoryRead(ctx context.Context, in value.HistoryReadRequest) (value.HistoryReadPermission, error) {
	h.calls++
	if h.failFinal && h.calls > 1 {
		return value.HistoryReadPermission{}, value.ErrDenied
	}
	deadline, ok := ctx.Deadline()
	if !ok || deadline.After(h.originalBound) {
		return value.HistoryReadPermission{}, value.ErrInvalid
	}
	s := h.storage
	s.ObservedAt = h.f.now
	return value.HistoryReadPermission{Storage: s, Authority: value.HistoryOperationAuthority{Expectation: s.Expectation, Operation: "read", RequestID: in.RequestID, ExecutorEpoch: in.ExecutorEpoch, StartedAt: h.f.now, NotAfter: deadline, CopiesDigest: value.HistoryCopiesDigest(s.Copies)}}, nil
}
func (h *parameterReadFixture) PrepareHistory(context.Context, string, string) (fleetapp.HistorySession, error) {
	h.prepares++
	if h.prepares <= h.failPrepares || h.exclusive && h.open > 0 {
		return nil, value.ErrUnavailable
	}
	h.open++
	return h, nil
}
func (h *parameterReadFixture) ExecutorEpoch() string { return fixtureID(99) }
func (h *parameterReadFixture) NotAfter() time.Time   { return h.originalBound }
func (h *parameterReadFixture) Close() {
	h.closes++
	if h.open > 0 {
		h.open--
	}
}
func (h *parameterReadFixture) ExecuteHistory(ctx context.Context, a value.HistoryOperationAuthority, _ value.HistoryCiphertexts, _ artifact.Copies) (fleetapp.HistoryReply, error) {
	if a.NotAfter.After(h.originalBound) || ctx.Err() != nil {
		return fleetapp.HistoryReply{}, value.ErrDenied
	}
	if a.Operation == "write" {
		h.executes++
		if h.executes <= h.failExecutes {
			return fleetapp.HistoryReply{}, value.ErrUnavailable
		}
		var copies artifact.Copies
		for i, b := range fixtureHistoryBundle {
			copies[i] = artifact.CopyReceipt{VersionID: "v", ETag: "e", Bytes: int64(len(b)), SHA256: artifact.Digest(sha256.Sum256(b))}
		}
		e := a.Expectation
		c := value.HistoryWriterCompletion{RootID: e.RootID, CaptureID: e.CaptureID, AttemptID: e.Registration.Location.AttemptID, OperationID: a.RequestID, ProcessEpoch: a.ExecutorEpoch, ExpectationDigest: value.HistoryExpectationDigest(e), CopiesDigest: value.HistoryCopiesDigest(copies), CompletedAt: h.f.now, NotAfter: a.NotAfter}
		return fleetapp.HistoryReply{Copies: copies, WriterCompletion: &c}, nil
	}
	return fleetapp.HistoryReply{Bundle: value.HistoryCiphertexts{[]byte{1}, []byte{2}, []byte{3}, []byte{4}}}, nil
}
func (h *parameterReadFixture) SealHistory(context.Context, value.HistoryExpectation, value.HistoryParameters) (value.HistoryCiphertexts, error) {
	if !h.writable {
		return value.HistoryCiphertexts{}, value.ErrUnavailable
	}
	return fixtureHistoryBundle, nil
}
func (h *parameterReadFixture) OpenHistory(context.Context, value.HistoryExpectation, artifact.Copies, value.HistoryCiphertexts) (value.HistoryParameters, error) {
	h.opens++
	if h.afterOpen != nil {
		h.afterOpen()
	}
	return h.params, nil
}
func (h *parameterReadFixture) ResolveCaseMetadata(ctx context.Context, in privacy.Input) (privacy.Resolution, error) {
	return h.f.Resolve(ctx, in)
}
func (h *parameterReadFixture) ResolveRetainedCaseMetadata(context.Context, privacy.Input, privacy.Deadlines, []artifact.RetentionRule) (privacy.RetainedResolution, error) {
	return privacy.RetainedResolution{Target: h.storage.Target, Deadlines: h.storage.Effective, ValidUntil: h.originalBound}, nil
}

func newParameterReadFixture(t *testing.T) (HistoryParameterService, *parameterReadFixture, value.SettingsQuery) {
	t.Helper()
	f := newInvestigationFixture()
	source := f.source(t, t.Context())
	i, err := source.ResolveIdentity(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	r, _ := f.RecoveryState(t.Context())
	mac, err := auditapp.NewOperationMAC("input-v1", bytes.Repeat([]byte{1}, 32), "account-v1", bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mac.Close)
	expect := value.HistoryExpectation{RootID: f.svc.RootID, CaptureID: fixtureID(90), Registration: artifact.Registration{Location: artifact.Location{ClusterID: fixtureID(4), ArtifactID: fixtureID(91), AttemptID: fixtureID(92)}, StoreID: fixtureID(7), AllocationID: fixtureID(8), PoolRevision: 1, AllocationRevision: 1, NativeLimit: value.MaxHistoryParameters, AnchorAt: f.now, WriteUntil: f.now.Add(30 * time.Second), ExpiresAt: f.now.Add(time.Minute), DeleteBy: f.now.Add(70 * time.Second)}, SelectorKey: artifact.Digest{1}, SettingsKey: artifact.Digest{2}, MACVersion: "account-v1", OriginalExecutionDigest: artifact.Digest{3}}
	h := &parameterReadFixture{f: f, originalBound: f.now.Add(2 * time.Second), storage: value.HistoryStorage{Expectation: expect, Origin: value.HistoryManual, State: "available", Target: f.target.Target(), SummaryExpiresAt: f.now.Add(time.Hour), Effective: privacy.Deadlines{AnchorAt: f.now, ExpiresAt: f.now.Add(time.Minute), DeleteBy: f.now.Add(70 * time.Second)}}}
	h.params = value.HistoryParameters{Format: value.HistoryParametersFormat, Target: f.intent().Target, NamespaceUID: "ns", WorkloadUID: "deployment", Diagnostic: value.ContextDiagnosticName, RecipeJSON: json.RawMessage(`{"actions":[]}`), DependencyJSON: json.RawMessage(`[]`), RequestedSeconds: 120, OriginalEffectiveSeconds: 60, OriginalExecutionDigest: artifact.Digest{3}}
	svc := HistoryParameterService{RootID: f.svc.RootID, InstallationID: f.svc.InstallationID, Ledger: h, Regional: h, Codec: h, Keys: mac, Recovery: f, Retention: h, Limits: value.DefaultHistoryLimits(), Now: func() time.Time { return f.now }, NewID: func() string { return fixtureID(93) }}
	return svc, h, value.SettingsQuery{RootID: f.svc.RootID, CaptureID: expect.CaptureID, Identity: i, Recovery: r}
}
func TestHistoryReadUsesFinalExpiryAndOriginalSelectedSession(t *testing.T) {
	svc, h, q := newParameterReadFixture(t)
	shortened := h.f.now.Add(30 * time.Second)
	h.afterOpen = func() { h.storage.Effective.ExpiresAt = shortened }
	got, err := svc.ReadCaptureSettings(t.Context(), q)
	if err != nil || !got.ExpiresAt.Equal(shortened) || got.ValidUntil.After(h.originalBound) || h.calls != 2 || h.prepares != 1 || h.opens != 1 || h.closes != 1 {
		t.Fatalf("read escaped final expiry/session: got=%+v err=%v calls=%d", got, err, h.calls)
	}
}
func TestHistoryReadRefusesPostDecryptRevocationAndNeverFallsBack(t *testing.T) {
	svc, h, q := newParameterReadFixture(t)
	h.failFinal = true
	got, err := svc.ReadCaptureSettings(t.Context(), q)
	if !errors.Is(err, value.ErrSettingsUnavailable) || got.CaptureID != "" || h.opens != 1 || h.closes != 1 {
		t.Fatal("decrypted settings escaped final revocation", got, err)
	}
	svc, h, q = newParameterReadFixture(t)
	h.failInitial = true
	got, err = svc.ReadCaptureSettings(t.Context(), q)
	if !errors.Is(err, value.ErrSettingsUnavailable) || got.CaptureID != "" || h.prepares != 0 || h.opens != 0 {
		t.Fatal("missing encrypted snapshot attempted an object lookup/fallback", err)
	}
}

type historyPersistenceOutage struct {
	started *submissionFixture
	calls   int
}

func (h *historyPersistenceOutage) Persist(context.Context, value.Accepted, identity.Identity, value.HistoryParameters, *value.HistoryLineage) error {
	h.calls++
	if h.started.starts != 0 {
		return value.ErrInvalid
	}
	return value.ErrHistoryUnavailable
}
func TestSubmissionHistoryOutageKeepsAcceptedCaptureAndStart(t *testing.T) {
	f, start, svc, p := submissionTest(t)
	start.current = f.source(t, t.Context())
	outage := &historyPersistenceOutage{started: start}
	svc.History = outage
	got, err := svc.Request(t.Context(), start.current, p.ID, "history-outage")
	if err != nil || got.CaptureID == "" || start.starts != 1 || outage.calls != 1 || !got.HistoryUnavailable || got.HistoryParameters != nil {
		t.Fatal("history outage changed admission/acquisition", got, err, start.starts, outage.calls)
	}
	replay, err := svc.Request(t.Context(), start.current, p.ID, "history-outage")
	if err != nil || replay.CaptureID != got.CaptureID || !replay.Replay || start.starts != 1 || outage.calls != 1 {
		t.Fatal("history outage replay restarted work", replay, err)
	}
}

// A deterministic two-region scheduling regression, not evidence of a
// production outage. All authority and receipts below are explicit fakes.
type retirementPageFixture struct {
	*parameterReadFixture
	rows                []value.HistoryRetirementCandidate
	after               []string
	attempted, finished []string
	onPrepare           func(int)
}

func (h *retirementPageFixture) HistoryRetirementCandidates(_ context.Context, _ time.Time, after string) ([]value.HistoryRetirementCandidate, error) {
	h.after = append(h.after, after)
	var page []value.HistoryRetirementCandidate
	for _, row := range h.rows {
		if row.CaptureID > after {
			page = append(page, row)
		}
		if len(page) == 16 {
			break
		}
	}
	return page, nil
}
func (h *retirementPageFixture) ExpireHistorySummaries(context.Context, artifact.RecoveryProof) error {
	return nil
}
func (h *retirementPageFixture) PrepareHistory(_ context.Context, cluster, captureID string) (fleetapp.HistorySession, error) {
	h.attempted = append(h.attempted, captureID)
	if h.onPrepare != nil {
		h.onPrepare(len(h.attempted))
	}
	if cluster == fixtureID(4) {
		return nil, value.ErrUnavailable
	}
	return &retirementSessionFixture{h}, nil
}
func (h *retirementPageFixture) ClaimHistoryDeletion(_ context.Context, in value.HistoryDeleteRequest) (value.HistoryDeletePermission, error) {
	e := h.storage.Expectation
	e.CaptureID = in.CaptureID
	return value.HistoryDeletePermission{Authority: value.HistoryOperationAuthority{Expectation: e, Operation: "purge", RequestID: in.RequestID, ExecutorEpoch: in.ExecutorEpoch, StartedAt: h.f.now, NotAfter: h.originalBound, CopiesDigest: artifact.Digest{9}, DeletionFence: 1}}, nil
}
func (h *retirementPageFixture) FinishHistoryDeletion(_ context.Context, a value.HistoryOperationAuthority, c value.HistoryDeleteCompletion, _ artifact.RecoveryProof) error {
	if !c.Valid(a) {
		return artifact.ErrIntegrity
	}
	h.finished = append(h.finished, a.Expectation.CaptureID)
	return nil
}

type retirementSessionFixture struct{ *retirementPageFixture }

func (h *retirementSessionFixture) ExecuteHistory(_ context.Context, a value.HistoryOperationAuthority, _ value.HistoryCiphertexts, _ artifact.Copies) (fleetapp.HistoryReply, error) {
	e := a.Expectation
	return fleetapp.HistoryReply{DeleteCompletion: &value.HistoryDeleteCompletion{RootID: e.RootID, CaptureID: e.CaptureID, AttemptID: e.Registration.Location.AttemptID, OperationID: a.RequestID, ProcessEpoch: a.ExecutorEpoch, ExpectationDigest: value.HistoryExpectationDigest(e), CopiesDigest: a.CopiesDigest, DeletionFence: a.DeletionFence, CompletedAt: h.f.now, NotAfter: a.NotAfter}}, nil
}
func TestHistoryCleanupAdvancesPastUnavailableRegionWithoutRefundOrStarvation(t *testing.T) {
	svc, base, _ := newParameterReadFixture(t)
	h := &retirementPageFixture{parameterReadFixture: base}
	for n := 100; n < 116; n++ {
		h.rows = append(h.rows, value.HistoryRetirementCandidate{CaptureID: fixtureID(n), ClusterID: fixtureID(4), State: "available"})
	}
	last := fixtureID(116)
	h.rows = append(h.rows, value.HistoryRetirementCandidate{CaptureID: last, ClusterID: fixtureID(5), State: "available"})
	svc.Ledger, svc.Regional = h, h
	after, more, err := svc.sweep(t.Context(), "")
	if !errors.Is(err, value.ErrUnavailable) || more || after != fixtureID(115) || len(h.attempted) != 16 || len(h.finished) != 0 {
		t.Fatal("failed page did not advance conservatively", after, more, err)
	}
	after, more, err = svc.sweep(t.Context(), after)
	if err != nil || more || after != "" || len(h.finished) != 1 || h.finished[0] != last || h.after[1] != fixtureID(115) || base.closes != 1 {
		t.Fatal("available second region starved or exact completion omitted", h, err)
	}
	_, _, _ = svc.sweep(t.Context(), after)
	if h.after[2] != "" || len(h.finished) != 1 {
		t.Fatal("cycle failed to return to still-charged failed candidates")
	}
}

func TestHistoryCleanupBudgetExhaustionResumesAfterLastAttemptedCandidate(t *testing.T) {
	svc, base, _ := newParameterReadFixture(t)
	h := &retirementPageFixture{parameterReadFixture: base}
	for n := 100; n < 116; n++ {
		h.rows = append(h.rows, value.HistoryRetirementCandidate{CaptureID: fixtureID(n), ClusterID: fixtureID(4), State: "available"})
	}
	svc.Ledger, svc.Regional = h, h
	ctx, cancel := context.WithCancel(t.Context())
	h.onPrepare = func(n int) {
		if n == 2 {
			cancel()
		}
	}
	after, more, err := svc.sweep(ctx, "")
	if !errors.Is(err, context.Canceled) || more || after != fixtureID(101) || len(h.attempted) != 2 || len(h.finished) != 0 {
		t.Fatal("bounded pass replayed its slow first candidates", after, more, err)
	}
	h.onPrepare = nil
	_, _, _ = svc.sweep(t.Context(), after)
	if h.attempted[2] != fixtureID(102) || len(h.finished) != 0 {
		t.Fatal("original obligations lost or partial page did not advance")
	}
}

// A deterministic elapsed-start regression: the accepted start can consume
// the remaining original invocation even when its eventual reply is unknown.
// This fixture grants no durable SQL/object authority or renewed deadline.
type submissionHistoryBudget struct {
	f            *investigationFixture
	started      *submissionFixture
	until        time.Time
	calls, saved int
	consume      bool
}

// ADR-272: history runs after the start with its own deadline, never beyond
// the original request window.
func (h *submissionHistoryBudget) Persist(ctx context.Context, a value.Accepted, _ identity.Identity, p value.HistoryParameters, _ *value.HistoryLineage) error {
	h.calls++
	until, ok := ctx.Deadline()
	if !ok || !until.Equal(h.until) || a.CaptureID == "" || p.OriginalExecutionDigest != a.ScopeDigest {
		return value.ErrInvalid
	}
	if ctx.Err() != nil || !h.f.now.Before(until) {
		return value.ErrHistoryUnavailable
	}
	if h.started.starts != 1 || h.started.intentReads != 1 {
		return value.ErrInvalid
	}
	if h.consume {
		h.f.now = h.until.Add(time.Microsecond)
		return value.ErrHistoryUnavailable
	}
	h.saved++
	return nil
}

// A slow, failed start no longer starves history: history runs after it with
// its own budget, still bounded by the caller's identity (here five seconds)
// and the original request window.
func TestSubmissionHistoryHasOwnBudgetAfterSlowStart(t *testing.T) {
	f, start, svc, p := submissionTest(t)
	start.current = f.source(t, t.Context())
	window := f.now.Add(identity.RecordingSaveRequestWindow)
	ctx, cancel := context.WithDeadline(t.Context(), window)
	defer cancel()
	identityUntil := f.now.Add(5 * time.Second)
	elapsed := f.now.Add(3 * time.Second)
	history := &submissionHistoryBudget{f: f, started: start, until: identityUntil.Add(-historyReplyReserve)}
	svc.History = history
	start.startHook = func() { f.now = elapsed }
	start.startErr = context.DeadlineExceeded
	got, err := svc.Request(ctx, start.current, p.ID, "history-after-slow-start")
	if !errors.Is(err, context.DeadlineExceeded) || got.CaptureID == "" || start.starts != 1 || f.admissions.Load() != 1 || history.calls != 1 || history.saved != 1 || !got.HistoryRecorded || got.HistoryUnavailable || got.HistoryParameters != nil {
		t.Fatalf("start starved advisory history: err=%v starts=%d attempts=%d saved=%d recorded=%t unavailable=%t", err, start.starts, history.calls, history.saved, got.HistoryRecorded, got.HistoryUnavailable)
	}
}

// History ends a reply reserve before the original request window and stays
// advisory: a slow history neither delays the start nor costs its reply.
func TestSubmissionSlowHistoryAfterStartStaysAdvisory(t *testing.T) {
	f, start, svc, p := submissionTest(t)
	start.current = f.source(t, t.Context())
	window := f.now.Add(3 * time.Second)
	ctx, cancel := context.WithDeadline(t.Context(), window)
	defer cancel()
	history := &submissionHistoryBudget{f: f, started: start, until: window.Add(-historyReplyReserve), consume: true}
	svc.History = history
	got, err := svc.Request(ctx, start.current, p.ID, "history-exhausted-budget")
	if err != nil || got.CaptureID == "" || start.starts != 1 || f.admissions.Load() != 1 || history.calls != 1 || history.saved != 0 || got.HistoryRecorded || !got.HistoryUnavailable || got.HistoryParameters != nil {
		t.Fatalf("slow history extended the window or failed the start: err=%v starts=%d calls=%d saved=%d recorded=%t unavailable=%t", err, start.starts, history.calls, history.saved, got.HistoryRecorded, got.HistoryUnavailable)
	}
}

func TestHistoryReadReportsClosedStageAndContextState(t *testing.T) {
	for _, phase := range []string{"storage", "final", "cancelled"} {
		t.Run(phase, func(t *testing.T) {
			svc, h, q := newParameterReadFixture(t)
			var reports []string
			svc.ReportFailure = func(stage string) { reports = append(reports, stage) }
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			want := "read/" + phase + "/live"
			switch phase {
			case "storage":
				h.failInitial = true
			case "final":
				h.failFinal = true
			case "cancelled":
				h.failInitial = true
				cancel()
				want = "read/storage/canceled"
			}
			_, err := svc.ReadCaptureSettings(ctx, q)
			if err == nil || len(reports) != 1 || reports[0] != want {
				t.Fatal("history phase diagnostic", err, reports)
			}
		})
	}
}

func TestHistoryWriteReportsReservationStageWithoutDependencyText(t *testing.T) {
	svc, h, q := newParameterReadFixture(t)
	preview := h.f.preview(t)
	accepted, err := h.f.svc.Request(t.Context(), h.f.source(t, t.Context()), preview.ID, "history-reservation-diagnostic")
	if err != nil || accepted.HistoryParameters == nil {
		t.Fatal("history diagnostic admission", err)
	}
	var reports []string
	svc.ReportFailure = func(stage string) { reports = append(reports, stage) }
	err = svc.Persist(t.Context(), accepted, q.Identity, *accepted.HistoryParameters, nil)
	if err == nil || len(reports) != 1 || reports[0] != "write/reserve/live" {
		t.Fatal("history reservation diagnostic", err, reports)
	}
}

// ADR-280: a failed regional session open (before any claim) and a failed
// execution of the claimed write are each retried once; a second failure stays
// a failure.
func TestHistoryWriteRetriesSessionAndExecutionOnce(t *testing.T) {
	for _, c := range []struct {
		name                      string
		prepares, executes        int
		ok                        bool
		wantPrepares, wantExecute int
	}{
		{"prepare", 1, 0, true, 2, 1},
		{"execute", 0, 1, true, 2, 2},
		{"execute-twice", 0, 2, false, 2, 2},
	} {
		t.Run(c.name, func(t *testing.T) {
			svc, h, q := newParameterReadFixture(t)
			preview := h.f.preview(t)
			accepted, err := h.f.svc.Request(t.Context(), h.f.source(t, t.Context()), preview.ID, "history-retry-"+c.name)
			if err != nil || accepted.HistoryParameters == nil {
				t.Fatal("admission", err)
			}
			h.writable, h.failPrepares, h.failExecutes, h.prepares, h.executes, h.exclusive = true, c.prepares, c.executes, 0, 0, true
			err = svc.Persist(t.Context(), accepted, q.Identity, *accepted.HistoryParameters, nil)
			if (err == nil) != c.ok || h.completed != c.ok || h.prepares != c.wantPrepares || h.executes != c.wantExecute {
				t.Fatalf("err=%v completed=%t prepares=%d executes=%d", err, h.completed, h.prepares, h.executes)
			}
		})
	}
}
