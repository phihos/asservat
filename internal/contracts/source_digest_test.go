package contracts

import "testing"

func TestSourceDigestsSeparateFieldsAndKinds(t *testing.T) {
	a := WorkloadSourceDigest("c", "ns", "hub-api")
	if a == WorkloadSourceDigest("c", "nsh", "ub-api") || a == WorkloadSourceDigest("c", "ns", "hub-api2") || a != WorkloadSourceDigest("c", "ns", "hub-api") {
		t.Fatal("digest is not a deterministic field-separated value")
	}
	if a == ConfigMapSourceDigest("c", "ns", "hub-api") || NamespaceSourceDigest("c", "ns") == ConfigMapSourceDigest("c", "ns", "ns") {
		t.Fatal("kinds share a digest")
	}
}
