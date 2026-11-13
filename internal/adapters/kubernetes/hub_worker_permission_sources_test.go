package kubernetes

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/configuration"
	"k8s.io/client-go/rest"
)

func TestPlainPermissionSourcesUseDeterministicDigests(t *testing.T) {
	const cluster = "22222222-2222-4222-8222-222222222222"
	ns := value.NamespaceRef{Name: "asservat-workers", UID: "33333333-3333-4333-8333-333333333333"}
	c, err := NewPermissionClient(&rest.Config{Host: "https://127.0.0.1:1"}, cluster, ns, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	retention, err := NewPlainRetentionSource(c)
	if err != nil || retention.Digest() != artifact.Digest(contracts.RetentionSourceDigest(cluster, ns.Name)) {
		t.Fatal("retention source digest is not the shared deterministic digest", err)
	}
	worker, err := NewPlainWorkerConfigurationProtection(c, "asservat-worker-profile")
	if err != nil || worker.digest != artifact.Digest(contracts.ConfigMapSourceDigest(cluster, ns.Name, "asservat-worker-profile")) {
		t.Fatal("worker configuration digest is not the shared deterministic digest", err)
	}
	if _, err = NewWorkerConfigurationSource(c, worker, "asservat-worker-profile", "44444444-4444-4444-8444-444444444444", cluster); err != nil {
		t.Fatal("plain protection refused by the source reader", err)
	}
	if _, err = NewPlainWorkerConfigurationProtection(c, "Bad_Name"); err == nil {
		t.Fatal("invalid source name accepted")
	}
	if _, err = NewPlainPermissionTrust(c, artifact.Digest{}); err == nil {
		t.Fatal("zero trust digest accepted")
	}
}
