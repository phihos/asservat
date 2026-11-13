package contracts

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestBundledInitialIdentityPrivateMaterialRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	selected := BundledInitialProviderIdentity{Format: BundledInitialProviderIdentityFormat, BackendName: "trial", Namespace: WorkerObjectReference{Name: "bootstrap", UID: "20000000-0000-4000-8000-000000000010"}, SetupAccount: WorkerObjectReference{Name: "trial-setup", UID: "20000000-0000-4000-8000-000000000011"}, EntityID: "20000000-0000-4000-8000-000000000012", SetupParent: InitialProviderParent{Accessor: "original-setup-accessor", IssuedAt: now, ExpiresAt: now.Add(300 * time.Second)}}
	equivalent := selected
	equivalent.SetupParent.IssuedAt = selected.SetupParent.IssuedAt.In(time.FixedZone("same-instant", 3600))
	equivalent.SetupParent.ExpiresAt = selected.SetupParent.ExpiresAt.In(time.FixedZone("same-instant", -7200))
	if !equivalent.Valid() || !equivalent.SetupParent.IssuedAt.Equal(selected.SetupParent.IssuedAt) || !equivalent.SetupParent.ExpiresAt.Equal(selected.SetupParent.ExpiresAt) {
		t.Fatal("equivalent instant was refused by timezone representation")
	}
	if !selected.Valid() || selected.Endpoint() != "https://trial-openbao.bootstrap.svc:8200" {
		t.Fatal("original private identity invalid")
	}
	material := InitialProviderMaterial{Format: InitialProviderMaterialFormat, IssuerToken: "original", BundledIdentity: &selected}
	raw, _ := json.Marshal(material)
	got, err := DecodeInitialProviderMaterial(bytes.NewReader(raw))
	if err != nil || got.BundledIdentity == nil || *got.BundledIdentity != selected {
		t.Fatal("private original identity was dropped", err)
	}
	// Unknown nested identity fields cannot become a permissive service mode.
	changed := bytes.Replace(raw, []byte(`"backendName":"trial"`), []byte(`"backendName":"trial","unexpected":true`), 1)
	if _, err = DecodeInitialProviderMaterial(bytes.NewReader(changed)); err == nil {
		t.Fatal("unrecognized identity field accepted")
	}
	material.BundledIdentity = nil
	raw, _ = json.Marshal(material)
	if strings.Contains(string(raw), "bundledIdentity") {
		t.Fatal("external material wire changed")
	}
}
