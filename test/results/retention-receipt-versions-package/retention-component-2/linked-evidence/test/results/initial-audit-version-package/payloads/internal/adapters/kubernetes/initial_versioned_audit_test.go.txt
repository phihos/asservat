package kubernetes

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
	"k8s.io/client-go/rest"
)

func TestInitialVersionedServicesProducePinnedInstallerFormat(t *testing.T) {
	f, old := finalInputFixture(t, "healthy")
	old.Close()
	f.config.Services.Format = contracts.InitialPreparationVersionedAuditServicesFormat
	p := f.preparer(t)
	defer p.Close()
	root, err := p.PrepareFinalInputs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := p.creator.raw(context.Background(), "/api/v1/namespaces/"+f.plan.Workload.Namespace+"/configmaps/"+f.plan.Workload.Configuration, nil)
	if err != nil {
		t.Fatal(err)
	}
	var cm core.ConfigMap
	if err = json.Unmarshal(raw, &cm); err != nil {
		t.Fatal(err)
	}
	c, err := contracts.DecodeInitialInstaller(strings.NewReader(cm.Data["deployment.json"]))
	if err != nil || c.Format != contracts.InitialInstallerVersionedAuditFormat || c.Pod.UID != root.Activation.Pod.Receipt.UID {
		t.Fatal("original versioned services downgraded during final input production", err)
	}
	// The credential binder must accept only the format derived from these
	// original services. It must reject a downgrade before any provider effect.
	ns := cfg.NamespaceRef{Name: c.Namespace.Name, UID: c.Namespace.UID}
	admin, err := NewPermissionClient(f.client, c.ClusterID, ns, f.clock)
	if err != nil {
		t.Fatal(err)
	}
	probeConfig := rest.CopyConfig(f.client)
	probeConfig.BearerToken = "target-probe"
	probe, err := NewPermissionClient(probeConfig, c.ClusterID, ns, f.clock)
	if err != nil {
		t.Fatal(err)
	}
	material := contracts.WorkerObjectReference{Name: "synthetic-sql-material", UID: ownerID(999)}
	if _, err = NewInitialPreparationCredentialBinder(p, admin, probe, c, string(cm.UID), material); err != nil {
		t.Fatal("original versioned credential binding rejected", err)
	}
	weaker := c
	weaker.Format = contracts.InitialInstallerFormat
	if _, err = NewInitialPreparationCredentialBinder(p, admin, probe, weaker, string(cm.UID), material); err == nil {
		t.Fatal("credential binding downgraded original versioned services")
	}
	unknown := *f.config.Services
	unknown.Format = "asservat-initial-preparation-services/v999"
	if _, err = p.checkedServices(unknown); err == nil {
		t.Fatal("unknown service format accepted")
	}
	before := map[string]int{}
	f.mu.Lock()
	for k, v := range f.posts {
		before[k] = v
	}
	f.mu.Unlock()
	replay := f.preparer(t)
	again, err := replay.PrepareFinalInputs(context.Background())
	replay.Close()
	if err != nil || !equalJSON(root, again) {
		t.Fatal("original versioned input replay changed", err)
	}
	f.config.Services.Format = contracts.InitialPreparationServicesFormat
	downgraded := f.preparer(t)
	_, err = downgraded.PrepareFinalInputs(context.Background())
	downgraded.Close()
	if err == nil {
		t.Fatal("accepted weaker service format after original versioned intent")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !equalJSON(before, f.posts) {
		t.Fatal("replay or downgrade repeated a public input CREATE")
	}
}

func TestInitialVersionedAuditRoutingPreservesOriginalProfiles(t *testing.T) {
	for _, format := range []string{contracts.InitialBootstrapPassiveFormat, contracts.InitialBootstrapCopyClosureFormat, contracts.InitialBootstrapVersionedAuditFormat} {
		t.Run(format, func(t *testing.T) {
			f := newBootstrapObserverFixtureVersion(t, context.Background(), format)
			requested := f.desired
			requested.Format = contracts.InitialBootstrapVersionedAuditFormat
			got, ok := bootstrapKnownDesired(requested, bootstrapDigest(f.desired))
			if !ok || !equalJSON(got, f.desired) {
				t.Fatal("existing original format silently upgraded or changed")
			}
			requested.AuditStore.Bucket = "replacement"
			if _, ok := bootstrapKnownDesired(requested, bootstrapDigest(f.desired)); ok {
				t.Fatal("changed original audit backend accepted")
			}
		})
	}
}

// Projection construction is passive provenance; these synthetic receipts do
// not replace the producer's independently enforced admission and current reads.
func TestInitialVersionedBootstrapProjectsRequiredServices(t *testing.T) {
	for _, tc := range []struct{ bootstrap, services string }{
		{contracts.InitialBootstrapPassiveFormat, contracts.InitialPreparationServicesFormat},
		{contracts.InitialBootstrapCopyClosureFormat, contracts.InitialPreparationServicesFormat},
		{contracts.InitialBootstrapVersionedAuditFormat, contracts.InitialPreparationVersionedAuditServicesFormat},
	} {
		t.Run(tc.bootstrap, func(t *testing.T) {
			d, state := bootstrapStateFixture(t)
			d.Format = tc.bootstrap
			state.DesiredDigest = bootstrapDigest(d)
			projection, err := bootstrapProjectionValue(d, state)
			if err != nil || projection.Services == nil || projection.Services.Format != tc.services {
				t.Fatal("original bootstrap did not bind its required audit service format", err)
			}
			if projection.Plan.InstallationID != state.InstallationID || projection.Plan.RequestID != state.RequestID {
				t.Fatal("version selection replaced original installation identity")
			}
		})
	}
}
