package gadget

import (
	"asservat.local/asservat/internal/domain/collector"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func argumentRequest(now time.Time) ArgumentRequest {
	return ArgumentRequest{AccountingRule: collector.ArgumentObservationAccountingRule(), PodUID: "11111111-1111-4111-8111-111111111111", Names: []string{"read", "write"}, CaptureBuffers: true, MaxBytesPerEvent: 256, MaxTrackedThreads: 4096, Events: 1000, Bytes: 1000000, EventsPerSecond: 1000, BytesPerSecond: 512 * 100, Deadline: now.Add(time.Second), StartBy: now.Add(time.Second)}
}
func TestArgumentBudgetPreservesBothAuthoredRates(t *testing.T) {
	now := time.Now()
	r := argumentRequest(now)
	b, err := ArgumentBudgetFor(r, now, 100)
	if err != nil || b.MaxProbeBytes != 512 || b.RateIntervalNS != 10_000_000 || b.RateBurstNS != 990_000_000 || b.Events != r.Events || b.Bytes != r.Bytes || b.DeadlineBootNS != 1_000_000_100 {
		t.Fatal(b, err)
	}
	r.EventsPerSecond = 3
	b, err = ArgumentBudgetFor(r, now, 100)
	if err != nil || b.RateIntervalNS != 333333334 || b.RateBurstNS != 666666668 {
		t.Fatal(b, err)
	}
	r.BytesPerSecond = 511
	if _, err = ArgumentBudgetFor(r, now, 100); err == nil {
		t.Fatal("zero effective rate")
	}
	r = argumentRequest(now)
	if _, err = ArgumentBudgetFor(r, r.Deadline, 100); err == nil {
		t.Fatal("renewed expired deadline")
	}
	if _, err = ArgumentBudgetFor(r, now, ^uint64(0)); err == nil {
		t.Fatal("boot deadline overflow")
	}
}
func TestArgumentRecorderIsOneUseEvenBeforeLoad(t *testing.T) {
	r, err := NewArgumentRecorder(argumentRequest(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err = r.Capture(ctx, func([]byte) {}, nil); err != ErrArgumentRequest {
		t.Fatal(err)
	}
	if _, err = r.Capture(t.Context(), func([]byte) {}, nil); err != ErrArgumentReplay {
		t.Fatal(err)
	}
}

func TestArgumentObjectPinTracksBuildInputs(t *testing.T) {
	raw, err := os.ReadFile("../../../experiments/syscall-argument-budget/pins.json")
	if err != nil {
		t.Fatal(err)
	}
	var pins struct {
		SHA string `json:"compiled_object_sha256"`
	}
	if err = json.Unmarshal(raw, &pins); err != nil || pins.SHA != ArgumentObjectSHA256 {
		t.Fatal(pins, err)
	}
	if binary.Size(ArgumentBudget{}) != 64 {
		t.Fatal("kernel budget ABI changed")
	}
}

func TestArgumentRecorderRefusesAnotherAccountingRule(t *testing.T) {
	r := argumentRequest(time.Now())
	r.AccountingRule = [32]byte{}
	if _, err := NewArgumentRecorder(r); err != ErrArgumentRequest {
		t.Fatal(err)
	}
	r.AccountingRule = collector.ArgumentObservationAccountingRule()
	r.AccountingRule[0] ^= 1
	if _, err := NewArgumentRecorder(r); err != ErrArgumentRequest {
		t.Fatal(err)
	}
}

// Latest admission and the running observation endpoint are independent bounds.
// Starting early may finish the requested window before the latest start time.
func TestArgumentBudgetAllowsEarlyStartWithoutExtendingObservation(t *testing.T) {
	now := time.Now()
	r := argumentRequest(now)
	r.StartBy = now.Add(10 * time.Second)
	r.Deadline = now.Add(5 * time.Second)
	if _, err := NewArgumentRecorder(r); err != nil {
		t.Fatal("early-start request refused", err)
	}
	b, err := ArgumentBudgetFor(r, now, 100)
	if err != nil || b.DeadlineBootNS != 5_000_000_100 {
		t.Fatal("observation endpoint changed", b, err)
	}
	if _, err = ArgumentBudgetFor(r, r.Deadline, 100); err == nil {
		t.Fatal("latest start extended completed observation")
	}
	r.StartBy = now.Add(time.Second)
	if _, err = ArgumentBudgetFor(r, r.StartBy, 100); err == nil {
		t.Fatal("running endpoint extended expired start permission")
	}
}

func TestArgumentFailureReportsOnlyFixedStage(t *testing.T) {
	private := errors.New("synthetic private provider detail")
	wrapped := &argumentFailure{stage: "object-verifier", cause: private}
	if ArgumentFailureStage(wrapped) != "object-verifier" || !errors.Is(wrapped, private) || strings.Contains(wrapped.Error(), private.Error()) {
		t.Fatal("failure stage lost cause or exposed details")
	}
	if ArgumentFailureStage(ErrArgumentRequest) != "request" || ArgumentFailureStage(private) != "runtime" {
		t.Fatal("unexpected public diagnostic category")
	}
}
