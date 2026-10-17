package audit

import (
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/audit"
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"testing"
)

func TestOverdueCapabilityIsExplicitFrozenAndSeparatelyQualified(t *testing.T) {
	in := auditIntent()
	old := healthyPolicy(in)
	bound, e := BindOperationLifecycle(in, old)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(bound)
	if bytes.Contains(raw, []byte("OverdueTerminal")) {
		t.Fatal("legacy JSON changed")
	}
	next := old
	next.OverdueTerminal = value.OperationOverdueTerminal
	newer, e := BindOperationLifecycle(in, next)
	if e != nil {
		t.Fatal(e)
	}
	if !newer.Lifecycle.OriginalPurgeAt.Equal(bound.Lifecycle.OriginalPurgeAt) || !newer.Lifecycle.CertificatePurgeAt.Equal(bound.Lifecycle.CertificatePurgeAt) || !newer.RetainUntil.Equal(bound.RetainUntil) {
		t.Fatal("capability moved dates")
	}
	if _, e = BindOperationLifecycle(bound, next); e == nil {
		t.Fatal("existing reviewed binding silently upgraded")
	}
	next.BackupHorizonSeconds = 1
	q := value.OperationHistoryQualification{ID: in.ID, Digest: artifact.Digest{1}, Layout: value.OperationHistoryLayout, MaximumRowFootprintBytes: 128 << 10, MaximumTransitionWALBytes: 128 << 10, BackupCopies: 1, WALCopies: 1}
	next.History = &q
	b, w := q.SlotBacking(next.MaxPurgeLeases)
	next.BackupReservedBytes = b * next.MetadataSlots
	next.WALReservedBytes = w * next.MetadataSlots
	if next.Valid() {
		t.Fatal("old layout accepted new metadata transitions")
	}
	q.Layout = value.OperationOverdueHistoryLayout
	if next.Valid() {
		t.Fatal("old WAL backing accepted")
	}
	b, w = q.SlotBacking(next.MaxPurgeLeases)
	next.BackupReservedBytes = b * next.MetadataSlots
	next.WALReservedBytes = w * next.MetadataSlots
	if !next.Valid() {
		t.Fatal("qualified next profile rejected")
	}
	next.OverdueTerminal = ""
	if next.Valid() {
		t.Fatal("v2 profile silently selected old policy")
	}
}

type overdueOrder struct {
	events []string
	fail   string
}

func (f *overdueOrder) step(s string) error {
	f.events = append(f.events, s)
	if f.fail == s {
		return ErrUnavailable
	}
	return nil
}
func (f *overdueOrder) BeginOperationPurge(_ context.Context, _ string, phase string) (value.OperationPurgeLease, error) {
	if phase != "overdueOriginal" {
		panic("wrong phase")
	}
	return value.OperationPurgeLease{}, f.step("fence")
}
func (f *overdueOrder) PurgeOperationObjects(context.Context, value.OperationPurgeLease) error {
	return f.step("purge")
}
func (f *overdueOrder) RecordOverdueOperationPurge(context.Context, value.OperationPurgeLease) (value.OperationOverduePurge, error) {
	return value.OperationOverduePurge{}, f.step("persist")
}
func (f *overdueOrder) VerifyOperationAbsence(context.Context, value.OperationPurgeLease) error {
	return f.step("independent")
}
func (f *overdueOrder) AcknowledgeOverdueOperationPurge(context.Context, value.OperationPurgeLease, value.OperationOverduePurge) error {
	return f.step("ack")
}
func (f *overdueOrder) RetireOperationAudit(context.Context, string) error { return f.step("retire") }
func TestOverduePurgeDoesNotWaitForVerifierOrRefundUnknown(t *testing.T) {
	steps := []string{"fence", "purge", "persist", "independent", "ack", "retire"}
	for i, stop := range append(append([]string{}, steps...), "") {
		t.Run(stop, func(t *testing.T) {
			f := &overdueOrder{fail: stop}
			s := OperationOverdueCleanup{f, f, f, f, f}
			e := s.Advance(context.Background(), "synthetic")
			count := i + 1
			if stop == "" {
				count = len(steps)
			}
			if !reflect.DeepEqual(f.events, steps[:count]) || (stop == "") != (e == nil) {
				t.Fatal("wrong effects after failure", e, f.events)
			}
		})
	}
}
