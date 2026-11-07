package node

import (
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/collector"
	"encoding/hex"
)

func WireManualLive(m collector.ManualLiveSource) contracts.NodeManualLiveSource {
	return contracts.NodeManualLiveSource{ExecutorPodUID: m.ExecutorPodUID, ExecutorEpoch: m.ExecutorEpoch, RootID: m.RootID, CaptureID: m.CaptureID, AttemptID: m.AttemptID, ActionID: m.ActionID, WorkID: m.WorkID, PodUID: m.PodUID, NodeUID: m.NodeUID, BootID: m.BootID, CollectorPodUID: m.CollectorPodUID, CollectorEpoch: m.CollectorEpoch, Scope: hex.EncodeToString(m.Scope[:]), ExpectationDigest: hex.EncodeToString(m.ExpectationDigest[:]), StartedAt: m.StartedAt, HardUntil: m.HardUntil, ObservationKind: m.ObservationKind, ObservationSessionID: m.ObservationSessionID, ObservationFence: m.ObservationFence}
}
func DomainManualLive(w contracts.NodeManualLiveSource) (collector.ManualLiveSource, bool) {
	m := collector.ManualLiveSource{ExecutorPodUID: w.ExecutorPodUID, ExecutorEpoch: w.ExecutorEpoch, RootID: w.RootID, CaptureID: w.CaptureID, AttemptID: w.AttemptID, ActionID: w.ActionID, WorkID: w.WorkID, PodUID: w.PodUID, NodeUID: w.NodeUID, BootID: w.BootID, CollectorPodUID: w.CollectorPodUID, CollectorEpoch: w.CollectorEpoch, StartedAt: w.StartedAt, HardUntil: w.HardUntil, ObservationKind: w.ObservationKind, ObservationSessionID: w.ObservationSessionID, ObservationFence: w.ObservationFence}
	a, e := hex.DecodeString(w.Scope)
	b, f := hex.DecodeString(w.ExpectationDigest)
	if e != nil || f != nil || len(a) != 32 || len(b) != 32 || hex.EncodeToString(a) != w.Scope || hex.EncodeToString(b) != w.ExpectationDigest {
		return collector.ManualLiveSource{}, false
	}
	copy(m.Scope[:], a)
	copy(m.ExpectationDigest[:], b)
	return m, m.BindingValid()
}

func WireManualObservation(m collector.ManualLiveObservation) contracts.NodeManualLiveObservation {
	return contracts.NodeManualLiveObservation{CaptureID: m.CaptureID, WorkID: m.WorkID, PodUID: m.PodUID, NodeUID: m.NodeUID, BootID: m.BootID, CollectorPodUID: m.CollectorPodUID, CollectorEpoch: m.CollectorEpoch, StartedAt: m.StartedAt, HardUntil: m.HardUntil, ObservationKind: m.ObservationKind, ObservationSessionID: m.ObservationSessionID, ObservationFence: m.ObservationFence}
}
func DomainManualObservation(w contracts.NodeManualLiveObservation) (collector.ManualLiveObservation, bool) {
	m := collector.ManualLiveObservation{CaptureID: w.CaptureID, WorkID: w.WorkID, PodUID: w.PodUID, NodeUID: w.NodeUID, BootID: w.BootID, CollectorPodUID: w.CollectorPodUID, CollectorEpoch: w.CollectorEpoch, StartedAt: w.StartedAt, HardUntil: w.HardUntil, ObservationKind: w.ObservationKind, ObservationSessionID: w.ObservationSessionID, ObservationFence: w.ObservationFence}
	return m, m.Valid()
}
