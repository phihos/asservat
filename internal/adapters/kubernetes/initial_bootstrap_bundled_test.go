package kubernetes

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
)

func TestInitialBootstrapBundledIdentityRetainsOriginalPrivateProvenance(t *testing.T) {
	d, s := bootstrapStateFixture(t)
	at := time.Now().UTC()
	b := contracts.BundledInitialProviderIdentity{Format: contracts.BundledInitialProviderIdentityFormat, BackendName: d.Name, Namespace: s.Prelude.Namespace, SetupAccount: contracts.WorkerObjectReference{Name: d.Name + "-bootstrap-runner", UID: ownerID(91)}, EntityID: ownerID(92), SetupParent: contracts.InitialProviderParent{Accessor: "synthetic-original-parent", IssuedAt: at, ExpiresAt: at.Add(300 * time.Second)}}
	d.KeyService.Endpoint = b.Endpoint()
	s.DesiredDigest = bootstrapDigest(d)
	s.Material.BundledIdentity = &b
	if !bootstrapStateValid(d, s) {
		t.Fatal("exact original bundled identity refused")
	}
	obj, err := bootstrapPrivateObject(d, s, 2)
	if err != nil {
		t.Fatal(err)
	}
	raw := obj.(*core.Secret).Data["material.json"]
	got, err := contracts.DecodeInitialProviderMaterial(bytes.NewReader(raw))
	if err != nil || got.BundledIdentity == nil || !equalJSON(*got.BundledIdentity, b) {
		t.Fatal("private projection lost original identity", err)
	}
	public, err := bootstrapProjectionValue(d, s)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(public)
	if bytes.Contains(encoded, []byte(b.EntityID)) || bytes.Contains(encoded, []byte(b.SetupParent.Accessor)) {
		t.Fatal("private setup provenance entered public projection")
	}
	for name, edit := range map[string]func(*contracts.InitialBootstrapState){
		"namespace-uid":  func(v *contracts.InitialBootstrapState) { v.Material.BundledIdentity.Namespace.UID = ownerID(93) },
		"namespace-name": func(v *contracts.InitialBootstrapState) { v.Material.BundledIdentity.Namespace.Name = "other" },
		"backend": func(v *contracts.InitialBootstrapState) {
			v.Material.BundledIdentity.BackendName = "other"
			v.Material.BundledIdentity.SetupAccount.Name = "other-bootstrap-runner"
		},
		"account":        func(v *contracts.InitialBootstrapState) { v.Material.BundledIdentity.SetupAccount.Name = "other" },
		"invalid-entity": func(v *contracts.InitialBootstrapState) { v.Material.BundledIdentity.EntityID = "invalid" },
	} {
		t.Run(name, func(t *testing.T) {
			v := cloneBootstrapState(t, s)
			edit(&v)
			if bootstrapStateValid(d, v) {
				t.Fatal("foreign or malformed bundled identity adopted")
			}
		})
	}
	other := d
	other.KeyService.Endpoint = "https://other.invalid"
	changed := cloneBootstrapState(t, s)
	changed.DesiredDigest = bootstrapDigest(other)
	if bootstrapStateValid(other, changed) {
		t.Fatal("bundled identity adopted by another endpoint")
	}
	// Individual credentials may fit while the original aggregate does not.
	large := *s.Material
	large.RegistryConfig = []byte(strings.Repeat("x", contracts.InitialProviderMaterialMaxBytes))
	if bootstrapRegistryMaterialValid(d, large) {
		t.Fatal("selected provenance bypassed aggregate private cap")
	}
}
