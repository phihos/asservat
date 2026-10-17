package audit

import (
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"bytes"
	"testing"
)

func TestConnectorAuditAccountKeepsPeerSpendAcrossRotation(t *testing.T) {
	account := bytes.Repeat([]byte{1}, 32)
	a, e := NewOperationMAC("input-one", bytes.Repeat([]byte{2}, 32), "account-one", account)
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	b, e := NewOperationMAC("input-two", bytes.Repeat([]byte{3}, 32), "account-one", account)
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	p := fleet.PeerBinding{InstallationID: "00000000-0000-4000-8000-000000000001", ClusterID: "00000000-0000-4000-8000-000000000002", IssuerEpoch: "00000000-0000-4000-8000-000000000003", PeerID: "00000000-0000-4000-8000-000000000004", Role: fleet.ConnectorPeer}
	first, e := a.ConnectorAccount(p)
	if e != nil {
		t.Fatal(e)
	}
	p.IssuerEpoch = "00000000-0000-4000-8000-000000000005"
	next, e := b.ConnectorAccount(p)
	if e != nil || next != first {
		t.Fatal("issuer/input key rotation refilled account")
	}
	human, e := a.Principal(identity.Principal{Issuer: p.InstallationID, Subject: p.PeerID, ClientID: p.ClusterID, Kind: identity.Workload})
	if e != nil || human == first {
		t.Fatal("private and human namespaces collided")
	}
	changed := p
	changed.PeerID = "00000000-0000-4000-8000-000000000006"
	other, e := a.ConnectorAccount(changed)
	if e != nil || other == first {
		t.Fatal("different peers share account")
	}
	changed = p
	changed.ClusterID = "00000000-0000-4000-8000-000000000007"
	other, e = a.ConnectorAccount(changed)
	if e != nil || other == first {
		t.Fatal("different clusters share account")
	}
	changed = p
	changed.Role = fleet.NodePeer
	changed.NodeUID = p.PeerID
	changed.NodeBootID = p.PeerID
	changed.CollectorEpoch = p.PeerID
	if _, e = a.ConnectorAccount(changed); e == nil {
		t.Fatal("node admitted to connector lane")
	}
	a.Close()
	if _, e = a.ConnectorAccount(p); e == nil {
		t.Fatal("closed account key used")
	}
}
