package node

import (
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/collector"
)

// Live source references reuse the existing canonical compact hex-digest node
// binding. No new digest representation or looser authority shape is invented.
func WireLiveRead(r collector.LiveRead) contracts.NodeLiveRead {
	out := contracts.NodeLiveRead{Binding: WireSourceBinding(r.Binding), ClusterID: r.ClusterID, NamespaceUID: r.NamespaceUID, WorkloadUID: r.WorkloadUID, Projection: r.Projection, PrivacyUntil: r.PrivacyUntil, Generation: r.Generation, AfterSequence: r.AfterSequence, AfterLost: r.AfterLost, AfterClockLost: r.AfterClockLost, AfterUnsupported: r.AfterUnsupported, AfterSensorLost: r.AfterSensorLost, Head: r.Head, Limit: r.Limit, WaitMS: r.WaitMS, ReplyBytes: r.ReplyBytes}
	if r.Manual != nil {
		if r.Binding == (collector.SourceBinding{}) {
			out.Binding = contracts.NodeSourceBinding{}
		}
		m := WireManualLive(*r.Manual)
		out.Manual = &m
	}
	out.Inspect = r.Inspect
	return out
}
func DomainLiveRead(r contracts.NodeLiveRead) (collector.LiveRead, bool) {
	b, ok := DomainSourceBinding(r.Binding)
	if r.Manual != nil && r.Binding == (contracts.NodeSourceBinding{}) {
		ok = true
	}
	value := collector.LiveRead{Binding: b, ClusterID: r.ClusterID, NamespaceUID: r.NamespaceUID, WorkloadUID: r.WorkloadUID, Projection: r.Projection, PrivacyUntil: r.PrivacyUntil, Generation: r.Generation, AfterSequence: r.AfterSequence, AfterLost: r.AfterLost, AfterClockLost: r.AfterClockLost, AfterUnsupported: r.AfterUnsupported, AfterSensorLost: r.AfterSensorLost, Head: r.Head, Limit: r.Limit, WaitMS: r.WaitMS, ReplyBytes: r.ReplyBytes}
	if r.Manual != nil {
		m, valid := DomainManualLive(*r.Manual)
		if !valid {
			return collector.LiveRead{}, false
		}
		value.Manual = &m
	}
	value.Inspect = r.Inspect
	return value, ok && value.Valid()
}
