package kubernetes

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

// Pure synthetic original journals and API objects qualify this new additional
// worker boundary only. They supply no current owner/source/SQL authority.
func publicWorkerProofFixture(t *testing.T, base ...contracts.PublicRuntimeRoles) (contracts.PublicRuntimeRoles, map[string]any) {
	t.Helper()
	s, resources := installedWorkerResourceFixture(t)
	if len(base) > 1 {
		t.Fatal("one original worker fixture scope required")
	}
	if len(base) == 1 {
		in := base[0]
		s.initial.InstallationID = in.InstallationID
		s.initial.ClusterID = in.ClusterID
		s.initial.Namespace = in.Namespace
		s.preparer.plan.InstallationID = in.InstallationID
		s.preparer.plan.ClusterID = in.ClusterID
		s.preparer.plan.Workload.Namespace = in.Namespace.Name
		// These are distinct synthetic namespaces. The generic preparation
		// fixture uses ownerID(4), also used by the public-role runtime fixture.
		// Rebase its bootstrap identity with the rest of this synthetic scope.
		s.preparer.plan.BootstrapNamespace.UID = ownerID(1540)
		s.names = runtimeResourceNames(in.InstallationID)
		resources.Objects[14].Receipt.UID = in.OwnerConfigurationUID
		for i := range resources.Objects {
			object, err := s.object(resources, i)
			if err != nil {
				t.Fatal(err)
			}
			resources.Objects[i].TemplateDigest = preparationDigest(object.object)
		}
	}
	in, err := s.inventory(resources)
	if err != nil {
		t.Fatal(err)
	}
	n := s.names
	now := time.Now().UTC().Truncate(time.Microsecond)
	start := now.Add(-30 * time.Second)
	initialClaim := ownerID(1500)
	if len(base) == 1 {
		initialClaim = base[0].InitialClaimID
	}
	configuration := contracts.ConfigurationRuntimeRoles{Format: contracts.ConfigurationRuntimeRolesFormat, InstallationID: s.initial.InstallationID, InitialClaimID: initialClaim, ClusterID: s.initial.ClusterID, Namespace: in.Namespace, Deployment: in.WorkerDeployment, ServiceAccount: in.WorkerAccount, FleetSource: in.FleetSource, OwnerSource: in.OwnerSource, LayoutDigest: strings.Repeat("1", 64)}
	deploymentObject, err := s.object(resources, 11)
	if err != nil {
		t.Fatal(err)
	}
	d := deploymentObject.object.(*apps.Deployment)
	sources := contracts.ConfigurationRoleObservation{InstallationID: configuration.InstallationID, ClusterID: configuration.ClusterID, IssuerEpoch: s.initial.IssuerEpoch, NamespaceUID: in.Namespace.UID, DeploymentUID: in.WorkerDeployment.UID, AccountUID: in.WorkerAccount.UID, WorkloadDigest: preparationDigest(d.Spec), GuardDigest: strings.Repeat("2", 64), ObservedAt: start, FreshUntil: start.Add(5 * time.Second), Fleet: contracts.ConfigurationRoleSourceRevision{UID: in.FleetSource.UID, Generation: 1, Digest: strings.Repeat("3", 64), ObservedAt: start, FreshUntil: start.Add(5 * time.Second)}, Owner: contracts.ConfigurationRoleSourceRevision{UID: in.OwnerSource.UID, Generation: 1, Digest: strings.Repeat("4", 64), ObservedAt: start, FreshUntil: start.Add(5 * time.Second)}}
	state := contracts.ConfigurationRuntimeRoleState{Format: contracts.ConfigurationRuntimeRoleStateFormat, Input: configuration, OperationID: ownerID(1501), CreatedAt: start, Until: start.Add(30 * time.Minute), Projection: &contracts.PublicRuntimeProjectionClaim{OperationID: ownerID(1502), ClaimedAt: start, Until: start.Add(5 * time.Second), SecretUID: ownerID(1503)}}
	for i, purpose := range contracts.ConfigurationRuntimeRolePurposes() {
		key := make([]byte, 32)
		key[0] = byte(i + 1)
		state.Roles = append(state.Roles, contracts.ConfigurationRuntimeRoleMaterial{Purpose: purpose, Password: base64.RawURLEncoding.EncodeToString(key), Claim: &contracts.ConfigurationRuntimeRoleClaim{OperationID: ownerID(1510 + i), ClaimedAt: start, Until: start.Add(5 * time.Second), DatabaseOID: 42, PostmasterAt: start.Add(-time.Hour), Sources: sources}, Receipt: &contracts.PublicRuntimeRoleReceipt{RoleName: "as_" + strings.ReplaceAll(configuration.InstallationID, "-", "") + fmt.Sprintf("_cfg_%02d", i), RoleOID: uint32(300 + i), LayoutDigest: configuration.LayoutDigest}})
	}
	*d.Spec.Replicas = 1
	state.Launch = &contracts.ConfigurationRuntimeLaunch{OperationID: ownerID(1520), ClaimedAt: start.Add(time.Second), Until: start.Add(5 * time.Second), Sources: sources, InertResourceVersion: "1", RunningDigest: preparationDigest(d.Spec), ProjectionUID: state.Projection.SecretUID, Configuration: contracts.WorkerObjectReference{Name: n.WorkerInputs, UID: ownerID(1521)}, Providers: contracts.WorkerObjectReference{Name: n.WorkerProviders, UID: ownerID(1522)}, Receipt: &contracts.ConfigurationRuntimeLaunchReceipt{ResourceVersion: "2", ObservedAt: start.Add(2 * time.Second)}}
	if !configurationRoleStateValid(configuration, state, now) {
		t.Fatal("invalid synthetic completed configuration state")
	}
	resourceSnapshot := contracts.InitialRuntimeResourceSnapshot{State: resources, UID: ownerID(1530)}
	configurationSnapshot := contracts.ConfigurationRuntimeRoleSnapshot{State: state, UID: ownerID(1531)}
	w, err := BuildPublicRuntimeWorkerBinding(resourceSnapshot, in, configurationSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	input := contracts.PublicRuntimeRoles{Format: contracts.PublicRuntimeRolesFormat, InstallationID: configuration.InstallationID, InitialClaimID: configuration.InitialClaimID, ClusterID: configuration.ClusterID, OwnerConfigurationUID: configuration.OwnerSource.UID, Namespace: configuration.Namespace, LayoutDigest: strings.Repeat("5", 64), Worker: w}
	objects := map[string]any{}
	for _, entry := range []struct {
		ref   contracts.WorkerObjectReference
		state any
	}{{w.Resources, resources}, {w.ConfigurationRoot, state}} {
		raw, e := json.Marshal(entry.state)
		if e != nil {
			t.Fatal(e)
		}
		objects["/api/v1/namespaces/"+in.Namespace.Name+"/secrets/"+entry.ref.Name] = &core.Secret{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: metav1.ObjectMeta{Name: entry.ref.Name, Namespace: in.Namespace.Name, UID: types.UID(entry.ref.UID), ResourceVersion: "1"}, Type: core.SecretTypeOpaque, Data: map[string][]byte{"state.json": raw}}
	}
	for _, index := range []int{1, 11, 13} {
		object, e := s.object(resources, index)
		if e != nil {
			t.Fatal(e)
		}
		m, _ := meta.Accessor(object.object)
		c := resources.Objects[index]
		m.SetUID(types.UID(c.Receipt.UID))
		m.SetResourceVersion("1")
		m.SetGeneration(c.Receipt.Generation)
		m.SetAnnotations(map[string]string{initialRuntimeResourceMarker: c.OperationID})
		if index == 11 {
			object.object.(*apps.Deployment).Spec = d.Spec
			m.SetResourceVersion("2")
			m.SetGeneration(c.Receipt.Generation + 1)
			m.SetAnnotations(map[string]string{initialRuntimeResourceMarker: c.OperationID, configurationLaunchAnnotation: state.Launch.OperationID})
		}
		objects[object.collection+"/"+m.GetName()] = object.object
	}
	return input, objects
}

func TestPublicRuntimeWorkerOriginalJournalsAndCurrentObjects(t *testing.T) {
	for _, mode := range []string{"exact-running", "original-inert", "wrong-resource-uid", "wrong-resource-setup", "missing-object-receipt", "wrong-original-template", "unknown-launch", "wrong-launch-root", "running-without-launch", "rollback-inert-after-launch", "different-image", "extra-process", "changed-account", "changed-lease", "controller-first-revision", "later-controller-revision", "unknown-annotation", "expired-read"} {
		t.Run(mode, func(t *testing.T) {
			input, objects := publicWorkerProofFixture(t)
			base := "/api/v1/namespaces/" + input.Namespace.Name
			root := objects[base+"/secrets/"+input.Worker.Resources.Name].(*core.Secret)
			launchRoot := objects[base+"/secrets/"+input.Worker.ConfigurationRoot.Name].(*core.Secret)
			deployment := objects["/apis/apps/v1/namespaces/"+input.Namespace.Name+"/deployments/"+input.Worker.Deployment.Reference.Name].(*apps.Deployment)
			var resources contracts.InitialRuntimeResourceState
			_ = json.Unmarshal(root.Data["state.json"], &resources)
			var configuration contracts.ConfigurationRuntimeRoleState
			_ = json.Unmarshal(launchRoot.Data["state.json"], &configuration)
			switch mode {
			case "wrong-resource-uid":
				root.UID = types.UID(ownerID(1600))
			case "wrong-resource-setup":
				resources.SetupID = ownerID(1600)
			case "missing-object-receipt":
				resources.Objects[1].Receipt = nil
			case "wrong-original-template":
				resources.Objects[11].TemplateDigest = strings.Repeat("8", 64)
			case "unknown-launch":
				configuration.Launch.Receipt = nil
			case "wrong-launch-root":
				launchRoot.UID = types.UID(ownerID(1600))
			case "running-without-launch":
				configuration.Launch = nil
			case "original-inert", "rollback-inert-after-launch":
				*deployment.Spec.Replicas = 0
				deployment.ResourceVersion = "1"
				deployment.Generation--
				delete(deployment.Annotations, configurationLaunchAnnotation)
				if mode == "original-inert" {
					configuration.Launch = nil
				}
			case "different-image":
				deployment.Spec.Template.Spec.Containers[0].Image = "registry.invalid/other@sha256:" + strings.Repeat("9", 64)
			case "extra-process":
				*deployment.Spec.Replicas = 2
			case "changed-account":
				objects[base+"/serviceaccounts/"+input.Worker.Account.Reference.Name].(*core.ServiceAccount).UID = types.UID(ownerID(1600))
			case "controller-first-revision":
				deployment.Annotations["deployment.kubernetes.io/revision"] = "1"
			case "later-controller-revision":
				deployment.Annotations["deployment.kubernetes.io/revision"] = "2"
			case "unknown-annotation":
				deployment.Annotations["unknown"] = "value"
			case "changed-lease":
				input.Worker.Lease.Reference.UID = ownerID(1600)
			}
			root.Data["state.json"], _ = json.Marshal(resources)
			launchRoot.Data["state.json"], _ = json.Marshal(configuration)
			release := make(chan struct{})
			server := httptest.NewTLSServer(http.HandlerFunc(func(out http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Error("worker proof attempted effect")
					http.Error(out, "method", 405)
					return
				}
				if mode == "expired-read" {
					<-release
				}
				if value, ok := objects[r.URL.Path]; ok {
					permissionReply(out, value)
				} else {
					t.Error("unexpected path", r.URL.Path)
					http.NotFound(out, r)
				}
			}))
			defer server.Close()
			defer close(release)
			client, e := NewPermissionClient(&rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}, input.ClusterID, cfg.NamespaceRef{Name: input.Namespace.Name, UID: input.Namespace.UID}, time.Now)
			if e != nil {
				t.Fatal(e)
			}
			rootReader := &PublicRuntimeRoleRoot{client: client, input: input}
			bound := 5 * time.Second
			if mode == "expired-read" {
				bound = 50 * time.Millisecond
			}
			ctx, end := context.WithTimeout(context.Background(), bound)
			defer end()
			err := rootReader.currentWorker(ctx)
			positive := mode == "exact-running" || mode == "original-inert" || mode == "controller-first-revision"
			if positive && err != nil {
				t.Fatal("exact original worker rejected", err)
			}
			if !positive && err == nil {
				t.Fatal("contrary/expired worker proof accepted")
			}
		})
	}
}

func TestPublicRuntimeWorkerOmissionCannotClaimSeparateCompartment(t *testing.T) {
	f := newPublicRoleRootFixture(t, false, false)
	original, err := f.root.OpenPublicRuntimeRoles(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	writes := f.writes.Load()
	for _, purpose := range []string{"capture-cleanup", "capture-verifier", "capture-finalizer", "capacity", "capacity-capture"} {
		_, fresh, err := f.root.ClaimPublicRuntimeRole(t.Context(), purpose, 123, time.Now().Add(-time.Hour))
		if err == nil || fresh || f.writes.Load() != writes {
			t.Fatal("omitted worker authorized credential claim", purpose, err)
		}
	}
	current, err := f.root.ReadPublicRuntimeRoles(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !equalJSON(current.State, original.State) {
		t.Fatal("denied compartment claim changed state")
	}
}
