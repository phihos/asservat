package bootstrap

import (
	"bytes"
	"encoding/json"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

func TestNodeLiveDeploymentTypedCeilings(t *testing.T) {
	_, _, roots := serverCertificate(t)
	base := contracts.NodeDeployment{Format: contracts.NodeDeploymentFormat, ClusterID: "50000000-0000-4000-8000-000000000001", Connector: contracts.NodeConnectorEndpoint{Endpoint: "https://asservat-connector-nodes.asservat-connector.svc:8444", ServerName: "asservat-connector-nodes", RootsPEM: roots}, Ceilings: contracts.NodeCeilings{RingBytes: 256 << 20, FrozenBytes: 256 << 20, UploadBytesPerSecond: 32 << 20, UploadBurstBytes: 64 << 20}}
	decode := func(d contracts.NodeDeployment) (contracts.NodeDeployment, error) {
		t.Helper()
		b, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		return contracts.DecodeNodeDeployment(bytes.NewReader(b))
	}
	old, err := decode(base)
	if err != nil || old.Live != nil {
		t.Fatal("old deployment changed", err)
	}
	if _, err = validNodeDeployment(old); err != nil {
		t.Fatal(err)
	}
	for _, live := range []contracts.NodeLiveProcessing{{Subscriptions: 1, MemoryBytes: 1 << 20, EventsPerSecond: 1, BytesPerSecond: 1, ProcessingNanosPerSecond: 1}, {Subscriptions: 16, MemoryBytes: 16 << 20, EventsPerSecond: 100000, BytesPerSecond: 256 << 20, ProcessingNanosPerSecond: 100000000}} {
		d := base
		d.Live = &live
		got, err := decode(d)
		if err != nil || got.Live == nil || *got.Live != live {
			t.Fatal("typed ceilings changed", got.Live, err)
		}
		if _, err = validNodeDeployment(got); err != nil {
			t.Fatal("boundary refused", err)
		}
	}
	high := contracts.NodeLiveProcessing{Subscriptions: 16, MemoryBytes: 16 << 20, EventsPerSecond: 100000, BytesPerSecond: 256 << 20, ProcessingNanosPerSecond: 100000000}
	for name, edit := range map[string]func(*contracts.NodeLiveProcessing){
		"subscriptions zero": func(p *contracts.NodeLiveProcessing) { p.Subscriptions = 0 }, "subscriptions high": func(p *contracts.NodeLiveProcessing) { p.Subscriptions = 17 },
		"memory low": func(p *contracts.NodeLiveProcessing) { p.MemoryBytes = (1 << 20) - 1 }, "memory high": func(p *contracts.NodeLiveProcessing) { p.MemoryBytes = (16 << 20) + 1 },
		"events zero": func(p *contracts.NodeLiveProcessing) { p.EventsPerSecond = 0 }, "events high": func(p *contracts.NodeLiveProcessing) { p.EventsPerSecond = 100001 },
		"bytes zero": func(p *contracts.NodeLiveProcessing) { p.BytesPerSecond = 0 }, "bytes high": func(p *contracts.NodeLiveProcessing) { p.BytesPerSecond = (256 << 20) + 1 },
		"processing zero": func(p *contracts.NodeLiveProcessing) { p.ProcessingNanosPerSecond = 0 }, "processing high": func(p *contracts.NodeLiveProcessing) { p.ProcessingNanosPerSecond = 100000001 },
	} {
		t.Run(name, func(t *testing.T) {
			live := high
			edit(&live)
			d := base
			d.Live = &live
			got, err := decode(d)
			if err == nil {
				_, err = validNodeDeployment(got)
			}
			if err == nil {
				t.Fatal("invalid ceiling accepted")
			}
		})
	}
	raw, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if json.Unmarshal(raw, &fields) != nil {
		t.Fatal("fixture decode")
	}
	fields["live"] = map[string]any{"subscriptions": 1, "memoryBytes": 1048576, "eventsPerSecond": 1, "bytesPerSecond": 1, "processingNanosPerSecond": 1, "enabled": true}
	unknown, _ := json.Marshal(fields)
	if _, err := contracts.DecodeNodeDeployment(bytes.NewReader(unknown)); err == nil {
		t.Fatal("unknown live option accepted")
	}
}
