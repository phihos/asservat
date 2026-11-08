package node

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/collector"
	v "asservat.local/asservat/internal/domain/live"
)

func TestManualLivePrivateWirePreservesOriginalTupleAndZeroPolicyBytes(t *testing.T) {
	now := time.Now().UTC()
	id := "11111111-1111-4111-8111-111111111111"
	m := collector.ManualLiveSource{RootID: id, ExecutorPodUID: id, ExecutorEpoch: id, CaptureID: id, AttemptID: id, ActionID: "packet", WorkID: id, PodUID: id, NodeUID: id, BootID: id, CollectorPodUID: id, CollectorEpoch: id, Scope: [32]byte{0xab}, ExpectationDigest: [32]byte{2}}
	r := collector.LiveRead{Manual: &m, Inspect: true, Head: true, ClusterID: id, NamespaceUID: "ns", WorkloadUID: "work", Projection: v.Packet, PrivacyUntil: now.Add(time.Second), Limit: 20}
	w := collector.Work{ID: id, Sequence: 1, Kind: collector.WorkLiveRead, NotAfter: now.Add(time.Second), Live: &r}
	raw, e := json.Marshal(contracts.NodePollResponse{Format: contracts.NodePollFormat, Work: []contracts.NodeWork{WireWork(w)}})
	if e != nil {
		t.Fatal(e)
	}
	decoded, e := contracts.DecodeNodePollResponse(bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	got, ok := DomainWork(decoded.Work[0])
	if !ok || got.Live == nil || got.Live.Manual == nil || *got.Live.Manual != m || !got.Live.Inspect || !got.NotAfter.Equal(w.NotAfter) || got.Packet != nil || got.Source != nil {
		t.Fatal("manual read became acquisition or lost exact tuple", got)
	}
	wire := WireLiveRead(r)
	wire.Manual.Scope = strings.ToUpper(wire.Manual.Scope)
	if _, ok := DomainLiveRead(wire); ok {
		t.Fatal("noncanonical digest accepted")
	}
	wire = WireLiveRead(r)
	wire.Binding = WireSourceBinding(sourceWireFixture(now).Permit.Binding)
	if _, ok := DomainLiveRead(wire); ok {
		t.Fatal("manual/policy union accepted")
	}
	requested := m
	r.Manual = &requested
	m.StartedAt = now
	m.HardUntil = now.Add(time.Second)
	reply := v.NodeReply{Manual: &m, WorkID: id, SourceID: m.CaptureID, Fence: m.WorkID, BootID: m.BootID, Clock: "monotonic", Sample: 1, Rows: []v.StampedRow{}}
	wr, e := WireLiveReply(id, reply)
	if e != nil {
		t.Fatal(e)
	}
	back, e := DomainLiveReply(wr)
	if e != nil || back.Manual != nil || back.ObservedManual == nil {
		t.Fatal("node observation lost or invented acceptance", back, e)
	}
	back, e = v.BindManualLiveReply(r, back)
	if e != nil || back.Manual == nil || *back.Manual != m || back.ObservedManual != nil {
		t.Fatal("actual original holder times lost", back, e)
	}
	body, _ := json.Marshal(wr)
	if bytes.Contains(body, []byte(`"rootID"`)) || bytes.Contains(body, []byte(`"scope"`)) || bytes.Contains(body, []byte(`"executorEpoch"`)) {
		t.Fatal("node echoed unobserved accepted provenance")
	}
	unknown := append([]byte{}, body...)
	unknown = bytes.Replace(unknown, []byte(`"captureID":`), []byte(`"rootID":"`+id+`","captureID":`), 1)
	if _, err := contracts.DecodeNodeLiveResult(bytes.NewReader(unknown)); err == nil {
		t.Fatal("unobserved node acceptance fields accepted")
	}
	old := collector.LiveRead{Binding: sourceWireFixture(now).Permit.Binding, ClusterID: id, NamespaceUID: "ns", WorkloadUID: "work", Projection: v.Packet, PrivacyUntil: now.Add(time.Second), Limit: 20}
	oldRaw, _ := json.Marshal(WireLiveRead(old))
	if bytes.Contains(oldRaw, []byte(`"manual"`)) || bytes.Contains(oldRaw, []byte(`"inspect"`)) {
		t.Fatal("zero manual branch changed policy wire")
	}
	oldReply, _ := WireLiveReply(id, v.NodeReply{WorkID: id, Rows: []v.StampedRow{}})
	oldRaw, _ = json.Marshal(oldReply)
	if bytes.Contains(oldRaw, []byte(`"manual"`)) {
		t.Fatal("zero manual reply changed policy wire")
	}
}
