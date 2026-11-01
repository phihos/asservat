package node

import (
	deliveryapp "asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"encoding/hex"
	"time"
)

func WireSnapshotRequest(s artifact.SourceSnapshotRequest) contracts.NodeSnapshotRequest {
	return contracts.NodeSnapshotRequest{RequireApproval: s.RequireApproval, SourceBindingDigest: hex.EncodeToString(s.SourceBindingDigest[:]), SourceID: s.SourceID, Fence: s.Fence, SnapshotID: s.SnapshotID, SourceStartedAt: s.SourceStartedAt.UTC(), SourceHardUntil: s.SourceHardUntil.UTC(), T0: s.T0.UTC(), IssuedAt: s.IssuedAt.UTC(), StartBy: s.StartBy.UTC(), ProcessingUntil: s.ProcessingUntil.UTC(), BeforeNanos: int64(s.Before), AfterNanos: int64(s.After), MaxBytes: s.MaxBytes}
}
func DomainSnapshotRequest(s contracts.NodeSnapshotRequest) (artifact.SourceSnapshotRequest, bool) {
	d, ok := digestHex(s.SourceBindingDigest)
	r := artifact.SourceSnapshotRequest{RequireApproval: s.RequireApproval, SourceBindingDigest: artifact.Digest(d), SourceID: s.SourceID, Fence: s.Fence, SnapshotID: s.SnapshotID, SourceStartedAt: s.SourceStartedAt.UTC(), SourceHardUntil: s.SourceHardUntil.UTC(), T0: s.T0.UTC(), IssuedAt: s.IssuedAt.UTC(), StartBy: s.StartBy.UTC(), ProcessingUntil: s.ProcessingUntil.UTC(), Before: time.Duration(s.BeforeNanos), After: time.Duration(s.AfterNanos), MaxBytes: s.MaxBytes}
	return r, ok && r.Valid()
}
func WireSourceSnapshot(s collector.SourceSnapshot) contracts.NodeSourceSnapshot {
	return contracts.NodeSourceSnapshot{AttemptID: s.AttemptID, WriterPodUID: s.WriterPodUID, WriterEpoch: s.WriterEpoch, Binding: WireSourceBinding(s.Binding), CaptureID: s.CaptureID, ExpectationDigest: hex.EncodeToString(s.ExpectationDigest[:]), Request: WireSnapshotRequest(s.Request)}
}
func DomainSourceSnapshot(w contracts.NodeSourceSnapshot) (collector.SourceSnapshot, bool) {
	b, ok := DomainSourceBinding(w.Binding)
	r, valid := DomainSnapshotRequest(w.Request)
	d, dok := digestHex(w.ExpectationDigest)
	s := collector.SourceSnapshot{AttemptID: w.AttemptID, WriterPodUID: w.WriterPodUID, WriterEpoch: w.WriterEpoch, Binding: b, CaptureID: w.CaptureID, ExpectationDigest: d, Request: r}
	return s, ok && valid && dok && s.Valid() && [32]byte(r.SourceBindingDigest) == deliveryapp.SourceBindingDigest(b)
}
func WireSnapshotOutcome(o artifact.SourceSnapshotOutcome) contracts.NodeSnapshotOutcome {
	return contracts.NodeSnapshotOutcome{Request: WireSnapshotRequest(o.Request), AcceptedExpectationDigest: hex.EncodeToString(o.AcceptedExpectationDigest[:]), NativeSHA256: hex.EncodeToString(o.NativeSHA256[:]), NativeBytes: o.NativeBytes, Retained: o.Retained, OutputFull: o.OutputFull, AvailableFrom: o.AvailableFrom.UTC(), ObservedUntil: o.ObservedUntil.UTC(), SourceStoppedAt: o.SourceStoppedAt.UTC(), SourceClosedAt: o.SourceClosedAt.UTC(), CompletedAt: o.CompletedAt.UTC(), HistoryComplete: o.HistoryComplete, WindowComplete: o.WindowComplete, HistoryEvicted: o.HistoryEvicted, InputUnknown: o.InputUnknown}
}
func DomainSnapshotOutcome(w contracts.NodeSnapshotOutcome) (artifact.SourceSnapshotOutcome, bool) {
	r, ok := DomainSnapshotRequest(w.Request)
	d, dok := digestHex(w.AcceptedExpectationDigest)
	h, hok := digestHex(w.NativeSHA256)
	o := artifact.SourceSnapshotOutcome{NativeSHA256: artifact.Digest(h), SourceSnapshotCoverage: artifact.SourceSnapshotCoverage{Request: r, AcceptedExpectationDigest: artifact.Digest(d), NativeBytes: w.NativeBytes, Retained: w.Retained, OutputFull: w.OutputFull, AvailableFrom: w.AvailableFrom.UTC(), ObservedUntil: w.ObservedUntil.UTC(), SourceStoppedAt: w.SourceStoppedAt.UTC(), SourceClosedAt: w.SourceClosedAt.UTC(), CompletedAt: w.CompletedAt.UTC(), HistoryComplete: w.HistoryComplete, WindowComplete: w.WindowComplete, HistoryEvicted: w.HistoryEvicted, InputUnknown: w.InputUnknown}}
	return o, ok && dok && hok
}
