package node

import (
	"encoding/hex"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/collector"
)

func wireObservation(p collector.ObservationPermit) *contracts.NodeObservationPermit {
	b := p.Binding
	return &contracts.NodeObservationPermit{Binding: contracts.NodeObservationBinding{
		Scope: hex.EncodeToString(b.Scope[:]), ProgramDigest: hex.EncodeToString(b.ProgramDigest[:]), ExpectationDigest: hex.EncodeToString(b.ExpectationDigest[:]), AccountingRule: hex.EncodeToString(b.AccountingRule[:]),
		SessionID: b.SessionID, Fence: b.Fence, CaptureID: b.CaptureID, ActionID: b.ActionID, PodUID: b.PodUID, NodeUID: b.NodeUID, BootID: b.BootID, CollectorPodUID: b.CollectorPodUID, CollectorEpoch: b.CollectorEpoch,
	}, StartedAt: p.StartedAt.UTC(), SessionUntil: p.SessionUntil.UTC(), LeaseUntil: p.LeaseUntil.UTC(), StartBy: p.StartBy.UTC(), DurationMillis: p.Duration.Milliseconds(), Sequence: p.Sequence, Credit: p.Credit, BytesPerSecond: p.BytesPerSecond}
}

func domainObservation(w *contracts.NodeObservationPermit) (*collector.ObservationPermit, bool) {
	if w == nil || w.DurationMillis < 1000 || w.DurationMillis > 15000 {
		return nil, false
	}
	b := w.Binding
	for _, s := range []string{b.SessionID, b.Fence, b.CaptureID, b.ActionID, b.PodUID, b.NodeUID, b.BootID, b.CollectorPodUID, b.CollectorEpoch} {
		if s == "" || !text(s, 128) {
			return nil, false
		}
	}
	p := &collector.ObservationPermit{Binding: collector.ObservationBinding{SessionID: b.SessionID, Fence: b.Fence, CaptureID: b.CaptureID, ActionID: b.ActionID, PodUID: b.PodUID, NodeUID: b.NodeUID, BootID: b.BootID, CollectorPodUID: b.CollectorPodUID, CollectorEpoch: b.CollectorEpoch}, StartedAt: w.StartedAt.UTC(), SessionUntil: w.SessionUntil.UTC(), LeaseUntil: w.LeaseUntil.UTC(), StartBy: w.StartBy.UTC(), Duration: time.Duration(w.DurationMillis) * time.Millisecond, Sequence: w.Sequence, Credit: w.Credit, BytesPerSecond: w.BytesPerSecond}
	for _, item := range []struct {
		wire string
		dst  *[32]byte
	}{{b.Scope, &p.Binding.Scope}, {b.ProgramDigest, &p.Binding.ProgramDigest}, {b.ExpectationDigest, &p.Binding.ExpectationDigest}, {b.AccountingRule, &p.Binding.AccountingRule}} {
		d, ok := digestHex(item.wire)
		if !ok || d == ([32]byte{}) {
			return nil, false
		}
		*item.dst = d
	}
	return p, p.ValidFinite(p.StartedAt)
}
