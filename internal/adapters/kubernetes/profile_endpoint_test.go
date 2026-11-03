package kubernetes

import (
	"asservat.local/asservat/internal/contracts"
	"testing"
)

func TestProfileEndpointConfigurationIsBoundedAndDeterministic(t *testing.T) {
	template := contracts.RegionalProfileEndpoint{Name: "go-pprof-loopback", Kind: "template", AddressModes: []string{"targetLoopback"}, LoopbackFamily: "ipv4", MinPort: 6060, MaxPort: 6060}
	cluster := "00000000-0000-4000-8000-000000000001"
	first, err := ProfileEndpointEntries(cluster, []contracts.RegionalProfileEndpoint{template})
	if err != nil || len(first) != 1 {
		t.Fatal(first, err)
	}
	again, err := ProfileEndpointEntries(cluster, []contracts.RegionalProfileEndpoint{template})
	if err != nil || first[0].Definition.Source != again[0].Definition.Source {
		t.Fatal("unstable config identity", err)
	}
	template.MaxPort = 6061
	changed, err := ProfileEndpointEntries(cluster, []contracts.RegionalProfileEndpoint{template})
	if err != nil || first[0].Definition.Source.Digest == changed[0].Definition.Source.Digest || first[0].Definition.Source.ResourceUID != changed[0].Definition.Source.ResourceUID {
		t.Fatal("config revision identity", err)
	}
	for _, change := range []func(*contracts.RegionalProfileEndpoint){
		func(e *contracts.RegionalProfileEndpoint) { e.Port = 6060 },
		func(e *contracts.RegionalProfileEndpoint) { e.Namespaces = []string{"payments", "payments"} },
		func(e *contracts.RegionalProfileEndpoint) { e.MinPort = 6062 },
		func(e *contracts.RegionalProfileEndpoint) { e.AddressModes = []string{"url"} },
	} {
		e := template
		change(&e)
		if ProfileEndpointsValid([]contracts.RegionalProfileEndpoint{e}) {
			t.Fatal("invalid definition accepted", e)
		}
	}
	if ProfileEndpointsValid([]contracts.RegionalProfileEndpoint{template, template}) {
		t.Fatal("duplicate name accepted")
	}
	if !ProfileEndpointsValid(nil) {
		t.Fatal("empty configuration must disable resolution")
	}
	profile := contracts.RegionalProfileEndpoint{Name: "fixed", Kind: "profile", AddressMode: "podIP", Port: 6060, Namespaces: []string{"payments"}}
	if !ProfileEndpointsValid([]contracts.RegionalProfileEndpoint{profile}) {
		t.Fatal("fixed profile rejected")
	}
}
