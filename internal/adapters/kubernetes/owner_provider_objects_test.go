package kubernetes

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	apps "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
)

// Actual loopback TLS, with explicitly synthetic original resource/role
// provenance. This qualifies reconstruction of the selected native objects,
// not the independent guard, accepted SQL, provider setup or installed launch.
func providerOwnerObjectFixture(t *testing.T) *ownerIdentityObjectFixture {
	t.Helper()
	x := newOwnerIdentityObjectFixture(t)
	s, _ := providerResourceFixture(t)
	_, in, _ := ownerProjectionOriginalInputFixture(t)
	a := x.reader.activation
	a.Input.OwnerLayout = contracts.OwnerProviderInstalledLayout
	in.Observation.Activation = &a
	ownerBootstrapRuntimeFixture(t, &in, &x.state, a.Input.ServiceAccount)
	recipe, err := providerconfig.OwnerProviderRecipeFor(in, s.ownerProvider.AuthMount, s.ownerProvider.AuthMountAccessor, a.Input.ServiceAccount, s.ownerProvider.AuditCredentials, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	in.ProviderAuthentication = &recipe.Profile
	x.state.WorkerLayout, x.state.OwnerLayout = s.workerLayout, s.ownerLayout
	x.state.WorkerProvider, x.state.OwnerProvider = s.workerProvider, s.ownerProvider
	for i := range x.state.Objects {
		o, e := s.object(x.state, i)
		if e != nil {
			t.Fatal(e)
		}
		x.state.Objects[i].TemplateDigest = preparationDigest(o.object)
	}
	o, err := s.object(x.state, 10)
	if err != nil {
		t.Fatal(err)
	}
	x.deployment = o.object.(*apps.Deployment)
	x.state.OwnerLaunch.InertDigest, err = ownerIdentitySpecDigest(*x.deployment)
	if err != nil {
		t.Fatal(err)
	}
	x.deployment.Spec.Replicas = ptr.To(int32(1))
	x.deployment.UID, x.deployment.ResourceVersion, x.deployment.Generation = types.UID(a.Input.Deployment.UID), "2", 2
	x.deployment.Annotations = map[string]string{initialRuntimeResourceMarker: x.state.Objects[10].OperationID, ownerIdentityLaunchMarker: x.state.OwnerLaunch.OperationID, "deployment.kubernetes.io/revision": "1"}
	x.state.OwnerLaunch.RunningDigest, err = ownerIdentitySpecDigest(*x.deployment)
	if err != nil {
		t.Fatal(err)
	}
	x.manifest.Input = a.Input
	x.mounted = map[string][]byte{}
	for _, name := range ownerIdentityProjectionKeys(in) {
		x.mounted[name] = []byte("synthetic-" + name)
	}
	x.mounted[contracts.OwnerIdentityRoleManifestFile], err = json.Marshal(x.manifest)
	if err != nil {
		t.Fatal(err)
	}
	x.providers.Data = map[string][]byte{}
	for name, value := range x.mounted {
		x.providers.Data[name] = append([]byte(nil), value...)
	}
	x.reader.input, x.reader.activation = in, a
	encoded, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	x.config.Data["deployment.json"] = string(encoded)
	x.state.OwnerIdentity.PublicDigest, err = ownerIdentityPublicDigest(in, x.manifest)
	if err != nil {
		t.Fatal(err)
	}
	x.writeJournal(t)
	return x
}

func TestProviderOwnerNativeObjectReadersPreserveOriginalSelectedLayout(t *testing.T) {
	for _, mode := range []string{"valid", "legacy-worker", "legacy-owner", "missing-selection", "changed-provider-uid", "provider-original-alias", "provider-owner-root-alias", "provider-child-alias", "extra-legacy-secret-key", "missing-sql-key", "changed-jwt-audience", "changed-jwt-lifetime", "changed-audit-secret"} {
		t.Run(mode, func(t *testing.T) {
			x := providerOwnerObjectFixture(t)
			switch mode {
			case "legacy-worker":
				x.state.WorkerLayout = contracts.HubWorkerInstalledLayout
			case "legacy-owner":
				x.state.OwnerLayout = contracts.OwnerInstalledLayout
			case "missing-selection":
				x.state.OwnerProvider = nil
			case "changed-provider-uid":
				x.state.OwnerProvider.AuditCredentials.UID = ownerID(14998)
			case "provider-original-alias":
				x.state.WorkerProvider.AuditCredentials.UID = x.state.Objects[0].Receipt.UID
			case "provider-owner-root-alias":
				x.state.WorkerProvider.AuditCredentials.UID = x.state.OwnerIdentity.RoleRoot.UID
			case "provider-child-alias":
				x.state.WorkerProvider.AuditCredentials.UID = x.state.OwnerIdentity.Credentials.Receipt.Object.UID
			case "extra-legacy-secret-key":
				x.providers.Data["audit-wrap.token"] = []byte("synthetic-legacy-token")
			case "missing-sql-key":
				delete(x.providers.Data, "sql-activation.json")
			case "changed-jwt-audience", "changed-jwt-lifetime":
				found := false
				for _, source := range x.deployment.Spec.Template.Spec.Volumes[0].Projected.Sources {
					if token := source.ServiceAccountToken; token != nil && token.Path == contracts.OwnerProviderTokenFile {
						found = true
						if mode == "changed-jwt-audience" {
							token.Audience += "-other"
						} else {
							*token.ExpirationSeconds++
						}
					}
				}
				if !found {
					t.Fatal("fixture omitted selected native token")
				}
			case "changed-audit-secret":
				found := false
				for _, source := range x.deployment.Spec.Template.Spec.Volumes[0].Projected.Sources {
					if p := source.Secret; p != nil && p.Name == x.reader.input.ProviderAuthentication.AuditCredentials.Name {
						found = true
						p.Name += "-other"
					}
				}
				if !found {
					t.Fatal("fixture omitted selected native audit projection")
				}
			}
			x.writeJournal(t)
			ctx, end := context.WithTimeout(context.Background(), 5*time.Second)
			defer end()
			state, err := x.reader.journal(ctx)
			if err == nil {
				err = x.reader.projections(ctx, state, x.manifest, x.mounted)
			}
			if err == nil {
				err = x.reader.deployment(ctx, state)
			}
			if mode == "valid" && err != nil {
				t.Fatal("original v2 objects unavailable", err)
			}
			if mode != "valid" && err == nil {
				t.Fatal("changed or mixed native projection accepted")
			}
		})
	}
}
