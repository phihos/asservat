package kubernetes

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
)

func initialRegistryFixture(t *testing.T) []byte {
	t.Helper()
	b, e := providerconfig.NormalizeInitialRegistry(initialWorkloadPlan().Image, []byte(`{"auths":{"registry.invalid":{"username":"fixture","password":"synthetic-only"}}}`))
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func initialProjectionFiles() map[string][]byte {
	files := map[string][]byte{}
	for _, key := range []string{"sql-prepare.json", "sql-audit.json", "sql-activate.json", "audit-storage.json", "audit-wrap.token", "audit-unwrap.token", "kube-probe.token"} {
		files[key] = []byte("synthetic-only")
	}
	return files
}

func TestInitialRegistryProjectionKeepsOriginalSevenMountedFiles(t *testing.T) {
	plan := initialWorkloadPlan()
	legacy, e := BuildInitialInstallerWorkload(plan)
	if e != nil {
		t.Fatal(e)
	}
	plan.RegistryAuthentication = contracts.InitialRegistryAuthentication
	w, e := BuildInitialInstallerWorkload(plan)
	if e != nil {
		t.Fatal(e)
	}
	if len(w.Pod.Spec.ImagePullSecrets) != 1 || w.Pod.Spec.ImagePullSecrets[0].Name != plan.Credentials {
		t.Fatal("wrong registry source")
	}
	items := w.Pod.Spec.Volumes[0].Projected.Sources[1].Secret.Items
	if len(items) != 7 {
		t.Fatal("activation gained another mounted credential")
	}
	for _, item := range items {
		if item.Key == core.DockerConfigJsonKey {
			t.Fatal("registry input mounted into activation")
		}
	}
	digest := InstallationPodSpecDigest(w.Pod.Spec)
	changed := w.Pod.Spec.DeepCopy()
	changed.ImagePullSecrets[0].Name = "other"
	if InstallationPodSpecDigest(*changed) == digest {
		t.Fatal("registry replacement outside exact spec")
	}
	changed = w.Pod.Spec.DeepCopy()
	changed.ImagePullSecrets = nil
	if InstallationPodSpecDigest(*changed) != InstallationPodSpecDigest(legacy.Pod.Spec) {
		t.Fatal("capability changed unrelated Pod behavior")
	}
	for _, role := range w.Roles {
		for _, rule := range role.Rules {
			for _, resource := range rule.Resources {
				if resource == "secrets" || resource == "*" {
					t.Fatal("registry capability granted Secret API access")
				}
			}
		}
	}
	s := &InitialPreparer{plan: contracts.InitialPreparationPlan{Workload: contracts.InitialPreparationWorkload{Image: plan.Image, RegistryAuthentication: plan.RegistryAuthentication}}}
	files := initialProjectionFiles()
	registry := initialRegistryFixture(t)
	typ, e := s.providerProjectionData(files, registry)
	if e != nil || typ != core.SecretTypeDockerConfigJson || len(files) != 8 || !bytes.Equal(files[core.DockerConfigJsonKey], registry) {
		t.Fatal("exact combined projection rejected")
	}
	registry[0] = '!'
	if files[core.DockerConfigJsonKey][0] == '!' {
		t.Fatal("projection aliases mutable caller credential")
	}
	s.plan.Workload.RegistryAuthentication = ""
	files = initialProjectionFiles()
	before, _ := json.Marshal(files)
	typ, e = s.providerProjectionData(files, nil)
	after, _ := json.Marshal(files)
	if e != nil || typ != core.SecretTypeOpaque || !bytes.Equal(before, after) {
		t.Fatal("legacy absent capability changed bytes")
	}
	if _, e = s.providerProjectionData(initialProjectionFiles(), initialRegistryFixture(t)); e == nil {
		t.Fatal("material accepted without capability")
	}
	s.plan.Workload.RegistryAuthentication = contracts.InitialRegistryAuthentication
	if _, e = s.providerProjectionData(initialProjectionFiles(), nil); e == nil {
		t.Fatal("configured registry fell back to missing material")
	}
	files = initialProjectionFiles()
	files["audit-wrap.token"] = bytes.Repeat([]byte{'x'}, core.MaxSecretSize)
	if _, e = s.providerProjectionData(files, initialRegistryFixture(t)); e == nil {
		t.Fatal("aggregate Kubernetes Secret ceiling ignored")
	}
}

func TestInitialRegistryMaterialSharesOriginalEnvelopeBudget(t *testing.T) {
	d, s := bootstrapStateFixture(t)
	d.Image = initialWorkloadPlan().Image
	d.RegistryAuthentication = contracts.InitialRegistryAuthentication
	m := *s.Material
	m.RegistryConfig = initialRegistryFixture(t)
	if !bootstrapRegistryMaterialValid(d, m) {
		t.Fatal("bounded material denied")
	}
	// Maxima must not add independent unaccounted envelopes. The wire's base64
	// expansion is included before any seed or downstream provider effect.
	m.IssuerToken = strings.Repeat("t", 1024)
	m.Storage.AccessKeyID = strings.Repeat("a", 256)
	m.Storage.SecretAccessKey = strings.Repeat("s", 1024)
	m.Storage.SessionToken = strings.Repeat("x", 4096)
	config := []byte(`{"auths":{"registry.invalid":{"username":"user","password":"` + strings.Repeat("p", 2048) + `"}}}`)
	var e error
	m.RegistryConfig, e = providerconfig.NormalizeInitialRegistry(d.Image, config)
	if e != nil {
		t.Fatal(e)
	}
	if bootstrapRegistryMaterialValid(d, m) {
		t.Fatal("combined serialized input exceeded original 8 KiB backing")
	}
	// The exact final envelope boundary includes the two original UUIDs.
	m = *s.Material
	m.IssuerToken = strings.Repeat("t", 1024)
	m.Storage.AccessKeyID = strings.Repeat("a", 256)
	m.Storage.SecretAccessKey = strings.Repeat("s", 1024)
	m.RegistryConfig, e = providerconfig.NormalizeInitialRegistry(d.Image, config)
	if e != nil {
		t.Fatal(e)
	}
	last := -1
	for n := 0; n <= 4096; n++ {
		m.Storage.SessionToken = strings.Repeat("x", n)
		if bootstrapRegistryMaterialValid(d, m) {
			last = n
		} else {
			break
		}
	}
	if last < 0 || last == 4096 {
		t.Fatal("no bounded fixture accepted")
	}
	if last < 4096 {
		m.Storage.SessionToken = strings.Repeat("x", last+1)
		if bootstrapRegistryMaterialValid(d, m) {
			t.Fatal("serialized overflow accepted")
		}
	}
}
