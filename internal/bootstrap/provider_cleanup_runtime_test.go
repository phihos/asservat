package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/artifact"
	auditvalue "asservat.local/asservat/internal/domain/audit"
)

// Exercise the actual pending-return branch rather than fabricating a worker
// success. Refused refresh stays pending and retains the provider error class.
func TestProviderCleanupRefusedRefreshReportsStageWithoutStoppingActor(t *testing.T) {
	d := &CaptureCleanupWorkerDeployment{providers: &kms.InstalledConfigurationProviderEffects{}}
	attempted, err, current := d.advanceProviderCleanupGroup(t.Context(), []string{"10000000-0000-4000-8000-000000000001"}, nil)
	if attempted != 0 || !current || !errors.Is(err, kms.ErrKeyService) || cleanupRuntimeEvent(err) != "provider-refresh/unavailable" {
		t.Fatalf("pending refresh stage/class/current changed: %s/%t", cleanupRuntimeEvent(err), current)
	}
}

type privateCleanupError struct{}

func (privateCleanupError) Error() string     { panic("provider text must not enter diagnostics") }
func (privateCleanupError) FixedStep() string { panic("provider diagnostic must not enter event keys") }
func TestProviderCleanupDiagnosticsKeepOnlyLocalStageAndClass(t *testing.T) {
	private := privateCleanupError{}
	err := &cleanupRuntimeError{"healthy", private}
	var out bytes.Buffer
	report := eventLog(&out, "operation cleanup")
	for range 5 {
		report(cleanupRuntimeEvent(err))
	}
	if !errors.Is(err, private) || out.String() != "operation cleanup: healthy/unavailable (1)\noperation cleanup: healthy/unavailable (2)\noperation cleanup: healthy/unavailable (4)\n" {
		t.Fatal("private diagnostics or repeated pending failure escaped bounded log")
	}
}

func TestProviderCleanupReportsOnlyApplicationOwnedInnerStage(t *testing.T) {
	err := (auditapp.OperationCleanup{}).Advance(t.Context(), "never-selected-row")
	if !errors.Is(err, auditapp.ErrUnavailable) || cleanupRuntimeEvent(&cleanupRuntimeError{"healthy", err}) != "healthy/input/unavailable" {
		t.Fatal("application refusal stage lost")
	}
	if auditapp.OperationCleanupFailureStep(privateCleanupError{}) != "" {
		t.Fatal("foreign stage accepted")
	}
}

// This is the existing history finalizer port, with synthetic outcomes only.
// It does not supply native projection or SQL recovery/effect authority.
type cleanupHistoryFinalizerFunc func(context.Context, auditvalue.OperationHistoryKey) (auditvalue.OperationHistoryRelease, error)

func (f cleanupHistoryFinalizerFunc) ReleaseOperationHistory(ctx context.Context, key auditvalue.OperationHistoryKey) (auditvalue.OperationHistoryRelease, error) {
	return f(ctx, key)
}

func cleanupHistoryPageKeys() []auditvalue.OperationHistoryKey {
	now := time.Now().UTC().Truncate(time.Microsecond)
	keys := make([]auditvalue.OperationHistoryKey, 16)
	for i := range keys {
		keys[i] = auditvalue.OperationHistoryKey{RootID: "10000000-0000-4000-8000-000000000001", Lane: "normal", PrincipalDigest: artifact.Digest{byte(i + 1)}, ReleaseAt: now.Add(-2 * time.Hour), DeleteBy: now.Add(-time.Hour)}
	}
	return keys
}

func TestCleanupHistoryPagePreservesSixteenExactOverdueKeysAndContinuesAfterFailure(t *testing.T) {
	keys := cleanupHistoryPageKeys()
	originalEnd := time.Now().Add(5 * time.Second)
	ctx, cancel := context.WithDeadline(t.Context(), originalEnd)
	defer cancel()
	first, later := errors.New("synthetic unknown release"), errors.New("synthetic later release")
	var observed []auditvalue.OperationHistoryKey
	var work context.Context
	finalizer := cleanupHistoryFinalizerFunc(func(call context.Context, key auditvalue.OperationHistoryKey) (auditvalue.OperationHistoryRelease, error) {
		if work == nil {
			work = call
		} else if work != call {
			t.Fatal("history page replaced its child context")
		}
		until, ok := call.Deadline()
		if !ok || !until.Equal(originalEnd.Add(-time.Second)) {
			t.Fatal("history page renewed its original work end")
		}
		observed = append(observed, key)
		if len(observed) == 2 {
			return auditvalue.OperationHistoryRelease{}, first
		}
		if len(observed) == 12 {
			return auditvalue.OperationHistoryRelease{}, later
		}
		return auditvalue.OperationHistoryRelease{Records: 1, Overdue: true}, nil
	})
	// The outer deadline is earlier than the supplied end and must win.
	attempted, err := releaseCleanupHistoryPage(ctx, originalEnd.Add(time.Hour), keys, finalizer)
	if attempted != 16 || !errors.Is(err, first) || !reflect.DeepEqual(observed, keys) {
		t.Fatal("history page lost first unknown outcome, exact keys or later-key fairness", err, len(observed))
	}
	if work.Err() == nil || ctx.Err() != nil {
		t.Fatal("history page did not close only its own child")
	}
}

func TestCleanupHistoryPageStopsOnCancellationWithoutReplayingKeys(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	until, _ := ctx.Deadline()
	calls := 0
	finalizer := cleanupHistoryFinalizerFunc(func(context.Context, auditvalue.OperationHistoryKey) (auditvalue.OperationHistoryRelease, error) {
		calls++
		if calls == 2 {
			cancel()
		}
		return auditvalue.OperationHistoryRelease{}, nil
	})
	attempted, err := releaseCleanupHistoryPage(ctx, until, cleanupHistoryPageKeys(), finalizer)
	if !errors.Is(err, context.Canceled) || calls != 2 || attempted != 2 {
		t.Fatal("canceled history page started another key", err, calls)
	}
}

func TestCleanupHistoryPageRetainsOriginalFinalNativeCheckTail(t *testing.T) {
	for _, remaining := range []time.Duration{1040 * time.Millisecond, 500 * time.Millisecond} {
		t.Run(remaining.String(), func(t *testing.T) {
			originalEnd := time.Now().Add(remaining)
			ctx, cancel := context.WithDeadline(t.Context(), originalEnd)
			defer cancel()
			calls := 0
			finalizer := cleanupHistoryFinalizerFunc(func(call context.Context, _ auditvalue.OperationHistoryKey) (auditvalue.OperationHistoryRelease, error) {
				calls++
				until, _ := call.Deadline()
				if !until.Equal(originalEnd.Add(-time.Second)) {
					t.Fatal("child work did not preserve the original one-second tail")
				}
				<-call.Done()
				return auditvalue.OperationHistoryRelease{}, call.Err()
			})
			attempted, err := releaseCleanupHistoryPage(ctx, originalEnd, cleanupHistoryPageKeys(), finalizer)
			want := 1
			if remaining < time.Second {
				want = 0
			}
			retained, _ := ctx.Deadline()
			if !errors.Is(err, context.DeadlineExceeded) || calls != want || attempted != want || ctx.Err() != nil || !retained.Equal(originalEnd) {
				t.Fatal("work expiry consumed or renewed the original native-check tail", err, calls)
			}
		})
	}
}

func TestCleanupHistoryPageRejectsWholeInvalidPageBeforeAdmission(t *testing.T) {
	keys := cleanupHistoryPageKeys()
	invalid := append([]auditvalue.OperationHistoryKey{}, keys...)
	invalid[15].RootID = "invalid"
	for _, page := range [][]auditvalue.OperationHistoryKey{append(append([]auditvalue.OperationHistoryKey{}, keys...), keys[0]), invalid} {
		calls := 0
		finalizer := cleanupHistoryFinalizerFunc(func(context.Context, auditvalue.OperationHistoryKey) (auditvalue.OperationHistoryRelease, error) {
			calls++
			return auditvalue.OperationHistoryRelease{}, nil
		})
		// A native attempt would panic through these absent admission/reader
		// dependencies. Every key, including the last, must be checked first.
		d := &CaptureCleanupWorkerDeployment{history: auditapp.OperationHistoryCleanup{Finalizer: finalizer}}
		attempted, err, current := d.releaseProviderHistoryPage(t.Context(), page)
		if attempted != 0 || current || cleanupRuntimeEvent(err) != "history-input/unavailable" || calls != 0 {
			t.Fatal("invalid history page entered admission or released a prefix")
		}
		if attempted, err := releaseCleanupHistoryPage(t.Context(), time.Now().Add(5*time.Second), page, finalizer); err == nil || calls != 0 || attempted != 0 {
			t.Fatal("invalid history page released a prefix")
		}
	}
}

func cleanupLifecycleGroupIDs() []string {
	return []string{"10000000-0000-4000-8000-000000000001", "10000000-0000-4000-8000-000000000002"}
}

func TestCleanupLifecycleGroupKeepsTwoExactIDsAndContinuesAfterFailure(t *testing.T) {
	ids := cleanupLifecycleGroupIDs()
	originalEnd := time.Now().Add(5 * time.Second)
	ctx, cancel := context.WithDeadline(t.Context(), originalEnd)
	defer cancel()
	first, later := errors.New("synthetic first effect unknown"), errors.New("synthetic second effect unknown")
	var observed []string
	var work context.Context
	attempted, err := advanceCleanupLifecycleGroup(ctx, originalEnd.Add(time.Hour), ids, func(call context.Context, id string) error {
		if work == nil {
			work = call
		} else if work != call {
			t.Fatal("lifecycle group replaced its original work context")
		}
		until, ok := call.Deadline()
		if !ok || !until.Equal(originalEnd.Add(-time.Second)) {
			t.Fatal("lifecycle work renewed its parent deadline")
		}
		observed = append(observed, id)
		if len(observed) == 1 {
			return first
		}
		return later
	})
	if attempted != 2 || !errors.Is(err, first) || !reflect.DeepEqual(observed, ids) || ctx.Err() != nil || work.Err() == nil {
		t.Fatal("group lost exact IDs, later-ID fairness or first pending result", attempted, len(observed))
	}
}

func TestCleanupLifecycleGroupCancellationStopsBeforeNextID(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	until, _ := ctx.Deadline()
	ids := cleanupLifecycleGroupIDs()
	var observed []string
	attempted, err := advanceCleanupLifecycleGroup(ctx, until, ids, func(_ context.Context, id string) error {
		observed = append(observed, id)
		cancel()
		return nil
	})
	if attempted != 1 || !errors.Is(err, context.Canceled) || !reflect.DeepEqual(observed, ids[:1]) {
		t.Fatal("canceled lifecycle group started another ID", attempted, len(observed))
	}
}

func TestCleanupLifecycleGroupPartialAndZeroWorkKeepOriginalTailAndCursor(t *testing.T) {
	ids := cleanupLifecycleGroupIDs()
	for _, remaining := range []time.Duration{1040 * time.Millisecond, 500 * time.Millisecond} {
		t.Run(remaining.String(), func(t *testing.T) {
			originalEnd := time.Now().Add(remaining)
			ctx, cancel := context.WithDeadline(t.Context(), originalEnd)
			defer cancel()
			var observed []string
			attempted, err := advanceCleanupLifecycleGroup(ctx, originalEnd, ids, func(call context.Context, id string) error {
				observed = append(observed, id)
				until, _ := call.Deadline()
				if !until.Equal(originalEnd.Add(-time.Second)) {
					t.Fatal("work discarded original native-check tail")
				}
				<-call.Done()
				return call.Err()
			})
			want := 1
			cursor := "10000000-0000-4000-8000-000000000000"
			wantCursor := ids[0]
			if remaining < time.Second {
				want, wantCursor = 0, cursor
			}
			end, _ := ctx.Deadline()
			if attempted != want || len(observed) != want || !errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil || !end.Equal(originalEnd) {
				t.Fatal("lifecycle group consumed or renewed final native tail", attempted, len(observed))
			}
			if got := cleanupLifecycleCursor(cursor, ids, attempted); got != wantCursor {
				t.Fatal("partial lifecycle page skipped unattempted selected IDs", got, wantCursor)
			}
		})
	}
}

func TestCleanupLifecycleCursorWrapsOnlyAfterCompleteShortPage(t *testing.T) {
	ids := cleanupLifecycleGroupIDs()
	if got := cleanupLifecycleCursor(ids[0], ids, len(ids)); got != "" {
		t.Fatal("complete short lifecycle page did not wrap")
	}
	full := make([]string, 16)
	for i := range full {
		full[i] = ids[i%2]
	}
	// The transition depends only on page size/attempted prefix. SQL separately
	// validates strictly increasing real IDs before any native admission.
	if got := cleanupLifecycleCursor(ids[0], full, len(full)); got != full[15] {
		t.Fatal("full lifecycle page wrapped before reading its later IDs")
	}
	if got := cleanupLifecycleCursor(ids[0], nil, 0); got != "" {
		t.Fatal("exhausted lifecycle cursor did not wrap")
	}
}

func TestCleanupLifecycleGroupRejectsInvalidOrOversizedInputBeforeAdmission(t *testing.T) {
	ids := cleanupLifecycleGroupIDs()
	for _, input := range [][]string{nil, {ids[0], "invalid"}, {ids[0], ids[1], ids[0]}} {
		d := &CaptureCleanupWorkerDeployment{}
		attempted, err, current := d.advanceProviderCleanupGroup(t.Context(), input, nil)
		if attempted != 0 || current || cleanupRuntimeEvent(err) != "lifecycle-group-input/unavailable" {
			t.Fatal("invalid lifecycle group entered credential/native work")
		}
	}
}
