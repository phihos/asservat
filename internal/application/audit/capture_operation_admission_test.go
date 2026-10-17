package audit

import (
	value "asservat.local/asservat/internal/domain/audit"
	"testing"
	"time"
)

func captureAdmissionAccount(in value.OperationIntent, mac *OperationMAC) value.CaptureAuditAccount {
	return value.CaptureAuditAccount{RootID: in.RootID, AllocationID: in.RootID, AccountVersion: mac.AccountVersion(), AccountDigest: in.PrincipalDigest, Revision: 1, Records: 10, RetainedSeconds: 3600, Policy: in.Lifecycle.Policy}
}

func TestCaptureOperationAdmissionRoundsOnlyLiveRequestBoundDown(t *testing.T) {
	original, mac := captureOperationFixture(t)
	account := captureAdmissionAccount(original, mac)
	for _, offset := range []time.Duration{time.Second + time.Nanosecond, 5*time.Second - time.Nanosecond, 5 * time.Second, 5*time.Second + time.Nanosecond} {
		t.Run(offset.String(), func(t *testing.T) {
			bound := original.CreatedAt.Add(offset)
			got, err := PrepareCaptureOperation(*original.Capture, account, mac, bound)
			if err != nil {
				t.Fatalf("live request bound rejected: %v", err)
			}
			want := bound.UTC().Truncate(time.Microsecond)
			if cap := original.CreatedAt.Add(5 * time.Second); want.After(cap) {
				want = cap
			}
			if !got.RequestUntil.Equal(want) || got.RequestUntil.After(bound) {
				t.Fatal("request interval lengthened or not normalized downward")
			}
			expected := original
			expected.RequestUntil = want
			if !sameOperationRecord(got, expected) {
				t.Fatal("normalizing live bound changed immutable capture, write, retention or lifecycle facts")
			}
		})
	}
}

func TestCaptureOperationAdmissionRejectsCollapsedOrInvalidOriginalDates(t *testing.T) {
	original, mac := captureOperationFixture(t)
	account := captureAdmissionAccount(original, mac)
	for _, offset := range []time.Duration{-time.Nanosecond, 0, time.Nanosecond, 999 * time.Nanosecond} {
		if _, err := PrepareCaptureOperation(*original.Capture, account, mac, original.CreatedAt.Add(offset)); err != ErrUnavailable {
			t.Fatal("collapsed or expired live interval acquired a new microsecond", offset, err)
		}
	}
	c := *original.Capture
	c.CreatedAt = c.CreatedAt.Add(time.Nanosecond)
	if _, err := PrepareCaptureOperation(c, account, mac, original.RequestUntil); err != ErrUnavailable {
		t.Fatal("invalid original admission time was silently normalized", err)
	}
}
