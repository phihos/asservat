package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/domain/authorization"
	"testing"
)

func TestPacketQueryGrantUseCannotReplayDownloadReservation(t *testing.T) {
	parent, child := "10000000-0000-4000-8000-000000000001", "10000000-0000-4000-8000-000000000002"
	prior := custodydb.AccessGrantUse{ParentID: id(parent), ChildID: id(child), Operation: authorization.GrantDownloadOperation, Bytes: 24576, Operations: 1}
	request := authapp.GrantUseRequest{ParentID: parent, ChildID: child, Use: authorization.GrantUse{Operation: "pcap_query", Bytes: 24576, Operations: 1}}
	if grantUseMatches(prior, request) {
		t.Fatal("a paid download reservation was reused as a raw packet page")
	}
	prior.Operation = "pcap_query"
	if !grantUseMatches(prior, request) {
		t.Fatal("exact raw page reservation did not replay")
	}
	for _, mutate := range []func(*authapp.GrantUseRequest){func(v *authapp.GrantUseRequest) { v.ParentID = child }, func(v *authapp.GrantUseRequest) { v.ChildID = parent }, func(v *authapp.GrantUseRequest) { v.Use.Bytes-- }, func(v *authapp.GrantUseRequest) { v.Use.Operations++ }} {
		changed := request
		mutate(&changed)
		if grantUseMatches(prior, changed) {
			t.Fatal("changed original raw page reservation replayed", changed)
		}
	}
}

func TestPacketQueryKeyRoleGetsOnlyBoundedGrantPredicate(t *testing.T) {
	grants, ok := publicRuntimeRoleGrants("key-acquisition")
	if !ok {
		t.Fatal("key role missing")
	}
	found := false
	for _, g := range grants {
		if g.kind == "table" && (g.object == "access_grant" || g.object == "access_grant_child" || g.object == "access_grant_use") {
			t.Fatal("key role can read or write grant review/state", g)
		}
		if g.kind == "function" && g.object == "context_packet_query_grant_current(uuid,uuid,uuid)" && g.privilege == "EXECUTE" {
			found = true
		}
	}
	if !found {
		t.Fatal("key role lacks exact existing-query/batch predicate")
	}
}
