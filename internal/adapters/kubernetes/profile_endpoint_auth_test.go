package kubernetes

import (
	"testing"

	"asservat.local/asservat/internal/contracts"
)

func TestProfileEndpointAuthorizationPublicDefinition(t *testing.T) {
	entries := []contracts.RegionalProfileEndpoint{{Name: "pprof", Kind: "profile", AddressMode: "targetLoopback", Port: 6060, LoopbackFamily: "ipv4", Credential: &contracts.RegionalProfileEndpointCredential{Audiences: []contracts.RegionalProfileEndpointAudience{{ClusterID: ownerID(1), NamespaceUID: ownerID(2), WorkloadKind: "Deployment", WorkloadUID: ownerID(3)}}}}}
	// Credential policy can never make clear transport acceptable.
	if ProfileEndpointsValid(entries) {
		t.Fatal("cleartext credential accepted")
	}
}

func TestProfileEndpointAuthorizationTLSAndExactAudiences(t *testing.T) {
	cluster := ownerID(1)
	e := contracts.RegionalProfileEndpoint{Name: "pprof", Kind: "profile", AddressMode: "targetLoopback", Port: 6060, LoopbackFamily: "ipv4", TLS: &contracts.RegionalProfileEndpointTLS{ServerName: "localhost", RootsPEM: profileEndpointTLSRoots(t)}, Credential: &contracts.RegionalProfileEndpointCredential{Audiences: []contracts.RegionalProfileEndpointAudience{{ClusterID: cluster, NamespaceUID: ownerID(2), WorkloadKind: "Deployment", WorkloadUID: ownerID(3)}}}}
	entries, err := ProfileEndpointEntries(cluster, []contracts.RegionalProfileEndpoint{e})
	if err != nil || entries[0].Definition.Credential == nil || entries[0].Definition.Credential.Policy != entries[0].Definition.Source {
		t.Fatal("public credential policy was lost", err)
	}
	e.Credential.Audiences[0].WorkloadUID = ownerID(4)
	if entries[0].Definition.Credential.Audiences[0].WorkloadUID != ownerID(3) {
		t.Fatal("policy aliases config")
	}
	changed, err := ProfileEndpointEntries(cluster, []contracts.RegionalProfileEndpoint{e})
	if err != nil || changed[0].Definition.Source.Digest == entries[0].Definition.Source.Digest {
		t.Fatal("audience change did not change public approval identity", err)
	}
	e.Credential.Audiences = append(e.Credential.Audiences, e.Credential.Audiences[0])
	if ProfileEndpointsValid([]contracts.RegionalProfileEndpoint{e}) {
		t.Fatal("duplicate audience accepted")
	}
}
