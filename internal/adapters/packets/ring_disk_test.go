package packets

import (
	"context"
	"os"
	"testing"
	"time"

	planning "asservat.local/asservat/internal/domain/planning"
)

// ringTestDir switches testNewRing to the encrypted-disk medium (ADR-278).
var ringTestDir string

func testNewRing(ctx context.Context, b RingBounds, l RingLimits, p []planning.BPFInstruction) (*Ring, error) {
	return NewRingOn(ctx, b, l, p, ringTestDir)
}

// Every ring behaviour holds unchanged on the encrypted-disk medium.
func TestRingSuiteOnEncryptedDisk(t *testing.T) {
	ringTestDir = t.TempDir()
	defer func() { ringTestDir = "" }()
	for name, test := range map[string]func(*testing.T){
		"TestRingSanitizedCopiedRecordsAndMaintainedPCAPNG":           TestRingSanitizedCopiedRecordsAndMaintainedPCAPNG,
		"TestRingOriginalRecordDoesNotAliasInputOrLiveRotation":       TestRingOriginalRecordDoesNotAliasInputOrLiveRotation,
		"TestRingQuietAgingNeverRestampsOldSegments":                  TestRingQuietAgingNeverRestampsOldSegments,
		"TestRingQuietCoverageRequiresExplicitOwnerObservation":       TestRingQuietCoverageRequiresExplicitOwnerObservation,
		"TestRingEvictionAndInputGapsAreDistinctAndCanWarmAgain":      TestRingEvictionAndInputGapsAreDistinctAndCanWarmAgain,
		"TestRingBoundsAndStoppedSource":                              TestRingBoundsAndStoppedSource,
		"TestRingCopyCapsAndCloseNextSynchronization":                 TestRingCopyCapsAndCloseNextSynchronization,
		"TestRingInputAndConstructorNegatives":                        TestRingInputAndConstructorNegatives,
		"TestRingOutOfOrderTimesAndOriginalWireFilter":                TestRingOutOfOrderTimesAndOriginalWireFilter,
		"TestRingIndependentFrozenAndCountCaps":                       TestRingIndependentFrozenAndCountCaps,
		"TestRingInvalidArrivalClockCannotLeaveCompleteCoverage":      TestRingInvalidArrivalClockCannotLeaveCompleteCoverage,
		"TestRingFirstObservationCannotBackfillQuietOrFutureCoverage": TestRingFirstObservationCannotBackfillQuietOrFutureCoverage,
		"TestRingFutureRequestedWindowPreservesOnlyAvailableCopy":     TestRingFutureRequestedWindowPreservesOnlyAvailableCopy,
		"TestRingUnacquiredHistoryIsNotReportedAsEviction":            TestRingUnacquiredHistoryIsNotReportedAsEviction,
		"TestRingDecoderBorrowEndsWhenAddReturns":                     TestRingDecoderBorrowEndsWhenAddReturns,
		"TestRingWindowOneReservation":                                TestRingWindowOneReservation,
		"TestRingWindowStopExpiryAndCancellation":                     TestRingWindowStopExpiryAndCancellation,
		"TestRingWindowCapacityAndConcurrentClose":                    TestRingWindowCapacityAndConcurrentClose,
		"TestRingWindowPreEvictionDoesNotEraseCopiedCoverage":         TestRingWindowPreEvictionDoesNotEraseCopiedCoverage,
		"TestRingWindowAfterZeroHasNoNewAcquisition":                  TestRingWindowAfterZeroHasNoNewAcquisition,
		"TestRingWindowCopyCancellationChecks":                        TestRingWindowCopyCancellationChecks,
		"TestRingWindowInvalidCompletionDoesNotSeal":                  TestRingWindowInvalidCompletionDoesNotSeal,
		"TestRingWindowNextChecksProcessingAfterLockWait":             TestRingWindowNextChecksProcessingAfterLockWait,
		"TestRingWindowRetainsLatePreAtFinalCut":                      TestRingWindowRetainsLatePreAtFinalCut,
		"TestRingWindowEvictedLatePreIsPartial":                       TestRingWindowEvictedLatePreIsPartial,
		"TestRingWindowArrivalCutDelayedAndAfterZero":                 TestRingWindowArrivalCutDelayedAndAfterZero,
		"TestRingArrivalSequenceExhaustionRefuses":                    TestRingArrivalSequenceExhaustionRefuses,
		"TestRingAfterZeroFinalCutPreservesUnknownInput":              TestRingAfterZeroFinalCutPreservesUnknownInput,
		"TestRingAfterZeroRetainsKnownStop":                           TestRingAfterZeroRetainsKnownStop,
		"TestRingWindowRetainsKnownCloseWithoutNaturalStop":           TestRingWindowRetainsKnownCloseWithoutNaturalStop,
		"TestRingSparseRecordsSurviveOlderRecordsAgingOut":            TestRingSparseRecordsSurviveOlderRecordsAgingOut,
		"TestRingAddRecordBypassesPacketDecoder":                      TestRingAddRecordBypassesPacketDecoder,
	} {
		t.Run(name, test)
	}
}

// Closing erases: the key is gone and the files are removed; a tampered or
// unreadable sealed segment shows as evicted history, never as data.
func TestEncryptedDiskRingErasesAndFailsClosed(t *testing.T) {
	dir := t.TempDir()
	start := time.Unix(1000, 0)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Hour))
	defer cancel()
	limits := RingLimits{MaxAge: time.Minute, MaxBytes: 4 << 10, SegmentBytes: 1 << 10, MaxSegments: 4, MaxFrozenBytes: 4 << 10, MaxConcurrentSnapshots: 1}
	r, err := NewRingOn(ctx, RingBounds{StartedAt: start, Until: start.Add(time.Hour)}, limits, nil, dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.State().LiveBytes; got != limits.SegmentBytes+4*ringSegmentHeader {
		t.Fatal("resident bytes", got)
	}
	record := make([]byte, 120)
	for i := 0; i < 20; i++ {
		if err := r.AddRecord(record, start.Add(time.Duration(i)*time.Millisecond), start.Add(time.Duration(i)*time.Millisecond)); err != nil {
			t.Fatal(i, err)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatal("ring directory", len(entries))
	}
	sealed, _ := os.ReadDir(dir + "/" + entries[0].Name())
	if len(sealed) == 0 {
		t.Fatal("no sealed segments")
	}
	raw, _ := os.ReadFile(dir + "/" + entries[0].Name() + "/" + sealed[0].Name())
	raw[len(raw)-1] ^= 1
	if err := os.WriteFile(dir+"/"+entries[0].Name()+"/"+sealed[0].Name(), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	visited := 0
	r.mu.Lock()
	r.walk(RingWindow{From: start, Until: start.Add(time.Second)}, func([]byte) { visited++ })
	r.mu.Unlock()
	if visited >= 20 || r.State().HistoryEvicted == 0 {
		t.Fatal("tampered segment read as history", visited, r.State().HistoryEvicted)
	}
	_ = r.Close()
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatal("files survive close", len(entries))
	}
}

func TestEncryptedDiskRingFullVolumeIsMediumUnavailable(t *testing.T) {
	if _, err := newSealedSegments(""); err != ErrMediumUnavailable {
		t.Fatal(err)
	}
	dir := t.TempDir()
	start := time.Unix(1000, 0)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Hour))
	defer cancel()
	limits := RingLimits{MaxAge: time.Minute, MaxBytes: 4 << 10, SegmentBytes: 1 << 10, MaxSegments: 4, MaxFrozenBytes: 4 << 10, MaxConcurrentSnapshots: 1}
	r, err := NewRingOn(ctx, RingBounds{StartedAt: start, Until: start.Add(time.Hour)}, limits, nil, dir)
	if err != nil {
		t.Fatal(err)
	}
	// An unwritable ring directory stands in for a full volume.
	if err := os.Chmod(r.disk.dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(r.disk.dir, 0o700)
	var last error
	for i := 0; i < 20 && last == nil; i++ {
		last = r.AddRecord(make([]byte, 120), start.Add(time.Duration(i)*time.Millisecond), start.Add(time.Duration(i)*time.Millisecond))
	}
	if last != ErrMediumUnavailable || !r.State().Closed {
		t.Fatal("full volume", last, r.State().Closed)
	}
}

// The disk budget charges whole blocks: a tiny segment still costs a block.
func TestSealedRingBytesRoundsToBlocks(t *testing.T) {
	if got := SealedRingBytes(RingLimits{SegmentBytes: 100, MaxSegments: 2}); got != 3*4096 {
		t.Fatal(got)
	}
	if got := SealedRingBytes(RingLimits{SegmentBytes: 4096, MaxSegments: 4}); got != 4*8192+4096 {
		t.Fatal(got)
	}
}
