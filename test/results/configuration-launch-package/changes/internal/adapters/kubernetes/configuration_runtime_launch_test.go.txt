package kubernetes

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
)

type configurationLaunchFixture struct {
	path                     *configurationSourcePathFixture
	root                     *ConfigurationRuntimeRoleRoot
	mu                       sync.Mutex
	deployment               *apps.Deployment
	configuration, providers contracts.WorkerObjectReference
	writes                   atomic.Int32
	loseWrite                atomic.Bool
	claimFault               atomic.Int32 // 1: lost committed reply; 2: changed enforcement after claim
	providerFault            atomic.Int32 // 1: changed enforcement; 2: block until cancellation
	blockReceipt             atomic.Bool
	blockedIO                atomic.Int32
	releaseBlockedIO         chan struct{}
}

// Explicitly synthetic precompleted SQL receipts avoid repeating all three
// provisioning paths in every launch test. Native SQL inventory qualification
// is separate. Original-rate concrete source/guard/Secret/CAS operations remain.
func newConfigurationLaunchFixture(t *testing.T) *configurationLaunchFixture {
	t.Helper()
	f := newConfigurationSourcePathFixture(t)
	f.replicas.Store(0)
	in := f.source.input
	x := &configurationLaunchFixture{path: f, configuration: contracts.WorkerObjectReference{Name: "worker-inputs", UID: ownerID(90)}, providers: contracts.WorkerObjectReference{Name: "worker-providers", UID: ownerID(91)}, releaseBlockedIO: make(chan struct{})}
	// Registered after the HTTP server cleanup, so LIFO cleanup releases any
	// deliberately blocked fake handler before joining the server. HTTP/1 does
	// not necessarily detect a closed client while its PUT body remains unread.
	// This runs only after the original client deadline/state assertions.
	t.Cleanup(func() { close(x.releaseBlockedIO) })
	w, e := BuildProvisionedHubWorkerWorkload(HubWorkerWorkloadPlan{Namespace: in.Namespace.Name, Name: in.Deployment.Name, ServiceAccount: in.ServiceAccount.Name, Configuration: x.configuration.Name, Credentials: x.providers.Name, Image: "registry.invalid/asservat@sha256:" + strings.Repeat("a", 64), FleetSource: in.FleetSource.Name, OwnerSource: in.OwnerSource.Name, FleetGuard: "cfg-fleet", OwnerGuard: "cfg-owner", LeaderLease: "leader"}, in.InstallationID)
	if e != nil {
		t.Fatal(e)
	}
	x.deployment = w.Deployment
	x.deployment.UID = types.UID(in.Deployment.UID)
	x.deployment.ResourceVersion = "1"
	config := contracts.HubWorkerDeployment{Format: contracts.HubWorkerDeploymentFormat, InstallationID: in.InstallationID, ClusterID: in.ClusterID, Namespace: in.Namespace, FleetSource: in.FleetSource, OwnerSource: in.OwnerSource, FleetGuard: contracts.OwnerDeploymentGuard{Name: "cfg-fleet"}, OwnerGuard: contracts.OwnerDeploymentGuard{Name: "cfg-owner"}, LeaderLease: contracts.WorkerObjectReference{Name: "leader", UID: ownerID(92)}}
	configJSON, e := json.Marshal(config)
	if e != nil {
		t.Fatal(e)
	}
	f.extraHandler = func(out http.ResponseWriter, r *http.Request) bool {
		prefix := "/api/v1/namespaces/" + in.Namespace.Name
		if x.root != nil && x.blockReceipt.Load() && r.Method == http.MethodPut && r.URL.Path == x.root.path()+"/"+x.root.name() {
			x.blockedIO.Store(2)
			select {
			case <-r.Context().Done():
			case <-x.releaseBlockedIO:
			}
			return true
		}
		if x.root != nil && r.Method == http.MethodPut && r.URL.Path == x.root.path()+"/"+x.root.name() && x.claimFault.Load() != 0 {
			var next core.Secret
			if json.NewDecoder(r.Body).Decode(&next) != nil {
				http.Error(out, "invalid synthetic claim", http.StatusBadRequest)
				return true
			}
			f.mu.Lock()
			if f.secret == nil || next.UID != f.secret.UID || next.ResourceVersion != f.secret.ResourceVersion {
				f.mu.Unlock()
				http.Error(out, "conflict", http.StatusConflict)
				return true
			}
			version, _ := strconv.Atoi(next.ResourceVersion)
			next.ResourceVersion = strconv.Itoa(version + 1)
			// The real core API sets the response GVK. Match the existing
			// synthetic Secret endpoint; do not relax the production decoder.
			next.TypeMeta = meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}
			f.secret = next.DeepCopy()
			f.secretWrites.Add(1)
			f.mu.Unlock()
			if x.claimFault.Load() == 1 {
				http.Error(out, "synthetic unknown claim", http.StatusServiceUnavailable)
				return true
			}
			// Object identities remain unchanged; the fresh effect-boundary
			// negative enforcement proof must still catch this change.
			f.fault.Store(2)
			permissionReply(out, next)
			return true
		}
		switch r.URL.Path {
		case prefix + "/configmaps/" + x.configuration.Name:
			permissionReply(out, core.ConfigMap{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}, ObjectMeta: meta.ObjectMeta{Name: x.configuration.Name, Namespace: in.Namespace.Name, UID: types.UID(x.configuration.UID), ResourceVersion: "1"}, Immutable: ptr.To(true), Data: map[string]string{"deployment.json": string(configJSON)}})
			return true
		case prefix + "/secrets/" + x.providers.Name:
			switch x.providerFault.Load() {
			case 1:
				f.fault.Store(2)
			case 2:
				x.blockedIO.Store(1)
				select {
				case <-r.Context().Done():
				case <-x.releaseBlockedIO:
				}
				return true
			}
			permissionReply(out, core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: x.providers.Name, Namespace: in.Namespace.Name, UID: types.UID(x.providers.UID), ResourceVersion: "1"}, Immutable: ptr.To(true), Type: core.SecretTypeOpaque, Data: map[string][]byte{"audit-storage.json": []byte("synthetic"), "audit-wrap.token": []byte("synthetic"), "audit-unwrap.token": []byte("synthetic")}})
			return true
		case "/apis/apps/v1/namespaces/" + in.Namespace.Name + "/deployments/" + in.Deployment.Name:
			x.mu.Lock()
			defer x.mu.Unlock()
			if r.Method == http.MethodGet {
				permissionReply(out, x.deployment)
				return true
			}
			var next apps.Deployment
			if r.Method != http.MethodPut || r.URL.Query().Get("dryRun") != "" || r.URL.Query().Get("fieldValidation") != "Strict" || json.NewDecoder(r.Body).Decode(&next) != nil || next.UID != x.deployment.UID || next.ResourceVersion != x.deployment.ResourceVersion {
				http.Error(out, "conflict", http.StatusConflict)
				return true
			}
			x.writes.Add(1)
			next.ResourceVersion = "2"
			x.deployment = next.DeepCopy()
			if x.loseWrite.Load() {
				http.Error(out, "synthetic lost reply", http.StatusServiceUnavailable)
				return true
			}
			permissionReply(out, x.deployment)
			return true
		}
		return false
	}
	x.root = configurationPathRoot(t, f)
	proof, e := f.source.ReadConfigurationRoleSource(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	n := time.Now().UTC().Truncate(time.Microsecond)
	state := contracts.ConfigurationRuntimeRoleState{Format: contracts.ConfigurationRuntimeRoleStateFormat, Input: in, OperationID: ownerID(93), CreatedAt: n, Until: n.Add(30 * time.Minute), Projection: &contracts.PublicRuntimeProjectionClaim{OperationID: ownerID(94), ClaimedAt: n, Until: proof.FreshUntil.Truncate(time.Microsecond), SecretUID: ownerID(51)}}
	for i, purpose := range contracts.ConfigurationRuntimeRolePurposes() {
		key := make([]byte, 32)
		key[0] = byte(i + 1)
		state.Roles = append(state.Roles, contracts.ConfigurationRuntimeRoleMaterial{Purpose: purpose, Password: base64.RawURLEncoding.EncodeToString(key), Claim: &contracts.ConfigurationRuntimeRoleClaim{OperationID: ownerID(95 + i), ClaimedAt: n, Until: state.Projection.Until, DatabaseOID: 42, PostmasterAt: n.Add(-time.Hour), Sources: proof}, Receipt: &contracts.PublicRuntimeRoleReceipt{RoleName: "as_" + strings.ReplaceAll(in.InstallationID, "-", "") + fmt.Sprintf("_cfg_%02d", i), RoleOID: uint32(100 + i), LayoutDigest: in.LayoutDigest}})
	}
	if !configurationRoleStateValid(in, state, n) {
		t.Fatal("synthetic completed state")
	}
	b, e := json.Marshal(state)
	if e != nil {
		t.Fatal(e)
	}
	snapshot := contracts.ConfigurationRuntimeRoleSnapshot{State: state, UID: ownerID(50)}
	data, e := configurationProjectionData(state)
	if e != nil {
		t.Fatal(e)
	}
	data[contracts.ConfigurationRuntimeRoleManifestFile], e = configurationProjectionManifest(snapshot)
	if e != nil {
		t.Fatal(e)
	}
	f.mu.Lock()
	f.secret = &core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: x.root.name(), Namespace: in.Namespace.Name, UID: types.UID(snapshot.UID), ResourceVersion: "1"}, Type: core.SecretTypeOpaque, Data: map[string][]byte{"state.json": b}}
	f.projection = &core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: x.root.projectionName(), Namespace: in.Namespace.Name, UID: types.UID(state.Projection.SecretUID), ResourceVersion: "1", Annotations: map[string]string{"asservat.io/role-root-uid": snapshot.UID, "asservat.io/role-setup-id": state.OperationID, "asservat.io/projection-id": state.Projection.OperationID}}, Immutable: ptr.To(true), Type: core.SecretTypeOpaque, Data: data}
	f.mu.Unlock()
	return x
}

func (f *configurationLaunchFixture) launch() error {
	return f.root.WithConfigurationRoleOperation(context.Background(), func(ctx context.Context) error {
		verified, e := f.root.ReadConfigurationRuntimeRoles(ctx)
		if e != nil {
			return e
		}
		return f.root.LaunchConfigurationRuntime(ctx, verified, f.configuration, f.providers)
	})
}

func TestConfigurationLaunchOneCASAndReadOnlyCompletedReplay(t *testing.T) {
	f := newConfigurationLaunchFixture(t)
	before, e := f.root.ReadConfigurationRuntimeRoles(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	start := time.Now()
	if e = f.launch(); e != nil {
		t.Fatal("original launch", e)
	}
	t.Logf("original launch operation wall=%s", time.Since(start))
	if f.writes.Load() != 1 {
		t.Fatal("launch count")
	}
	e = f.root.WithConfigurationRoleOperation(context.Background(), func(ctx context.Context) error {
		verified, e := f.root.ReadLaunchedConfigurationRuntimeRoles(ctx)
		if e != nil {
			return e
		}
		return f.root.RecordConfigurationRuntimeLaunch(ctx, verified)
	})
	if e != nil {
		t.Fatal("record independent original result", e)
	}
	completed, e := f.root.ReadLaunchedConfigurationRuntimeRoles(context.Background())
	if e != nil || completed.State.Launch.Receipt == nil || !reflect.DeepEqual(completed.State.Roles, before.State.Roles) {
		t.Fatal("original credential provenance changed", e)
	}
	if e = f.launch(); e == nil || f.writes.Load() != 1 {
		t.Fatal("completed replay launched again")
	}
}

func TestConfigurationLaunchUnknownWriteOnlyObservesOriginal(t *testing.T) {
	f := newConfigurationLaunchFixture(t)
	f.loseWrite.Store(true)
	if e := f.launch(); e == nil || f.writes.Load() != 1 {
		t.Fatal("unknown launch was successful", e)
	}
	if _, e := f.root.ReadLaunchedConfigurationRuntimeRoles(context.Background()); e != nil {
		t.Fatal("exact original readback", e)
	}
	if e := f.launch(); e == nil || f.writes.Load() != 1 {
		t.Fatal("unknown write repeated")
	}
}

func TestConfigurationLaunchUnknownClaimNeverWritesWorkload(t *testing.T) {
	f := newConfigurationLaunchFixture(t)
	f.claimFault.Store(1)
	if err := f.launch(); err == nil || f.writes.Load() != 0 {
		t.Fatal("unknown claim conferred launch", err)
	}
	f.claimFault.Store(0)
	retained, err := f.root.ReadConfigurationRuntimeRoles(context.Background())
	if err != nil || retained.State.Launch == nil || retained.State.Launch.Receipt != nil {
		t.Fatal("original spent launch claim missing", err)
	}
	if _, err = f.root.ReadLaunchedConfigurationRuntimeRoles(context.Background()); err == nil {
		t.Fatal("inert deployment reported as launched")
	}
	if err = f.launch(); err == nil || f.writes.Load() != 0 {
		t.Fatal("unknown claim replay authorized another attempt", err)
	}
}

func TestConfigurationLaunchRechecksEnforcementAfterClaim(t *testing.T) {
	f := newConfigurationLaunchFixture(t)
	f.claimFault.Store(2)
	if err := f.launch(); err == nil || f.writes.Load() != 0 {
		t.Fatal("changed enforcement authorized launch", err)
	}
	f.claimFault.Store(0)
	f.path.fault.Store(0)
	if err := f.launch(); err == nil || f.writes.Load() != 0 {
		t.Fatal("restored enforcement revived spent launch", err)
	}
}

func TestConfigurationLaunchExactRunningTransition(t *testing.T) {
	in, proof := configurationRoleProofExample(time.Now())
	d := apps.Deployment{ObjectMeta: meta.ObjectMeta{Name: in.Deployment.Name, Namespace: in.Namespace.Name, UID: types.UID(in.Deployment.UID), ResourceVersion: "2", Annotations: map[string]string{configurationLaunchAnnotation: ownerID(110)}}, Spec: apps.DeploymentSpec{Replicas: ptr.To(int32(0)), Template: core.PodTemplateSpec{Spec: core.PodSpec{ServiceAccountName: in.ServiceAccount.Name}}, Strategy: apps.DeploymentStrategy{Type: apps.RecreateDeploymentStrategyType}}}
	b, _ := json.Marshal(d.Spec)
	h := sha256.Sum256(b)
	proof.WorkloadDigest = hex.EncodeToString(h[:])
	*d.Spec.Replicas = 1
	b, _ = json.Marshal(d.Spec)
	h = sha256.Sum256(b)
	launch := &contracts.ConfigurationRuntimeLaunch{OperationID: ownerID(110), Sources: proof, InertResourceVersion: "1", RunningDigest: hex.EncodeToString(h[:])}
	if !configurationLaunchSpec(d, in, launch) {
		t.Fatal("exact fixed transition rejected")
	}
	for name, mutate := range map[string]func(*apps.Deployment){
		"other UID":         func(x *apps.Deployment) { x.UID = types.UID(ownerID(111)) },
		"original version":  func(x *apps.Deployment) { x.ResourceVersion = "1" },
		"missing launch":    func(x *apps.Deployment) { delete(x.Annotations, configurationLaunchAnnotation) },
		"different launch":  func(x *apps.Deployment) { x.Annotations[configurationLaunchAnnotation] = ownerID(112) },
		"still inert":       func(x *apps.Deployment) { *x.Spec.Replicas = 0 },
		"excess replicas":   func(x *apps.Deployment) { *x.Spec.Replicas = 2 },
		"different account": func(x *apps.Deployment) { x.Spec.Template.Spec.ServiceAccountName = "replacement" },
		"new spec field":    func(x *apps.Deployment) { x.Spec.Template.Spec.HostNetwork = true },
	} {
		t.Run(name, func(t *testing.T) {
			next := d.DeepCopy()
			mutate(next)
			if configurationLaunchSpec(*next, in, launch) {
				t.Fatal("changed result accepted")
			}
		})
	}
}

func TestConfigurationLaunchReceiptRechecksEnforcementAfterObjectReads(t *testing.T) {
	f := newConfigurationLaunchFixture(t)
	if err := f.launch(); err != nil {
		t.Fatal("original launch", err)
	}
	before := f.path.secretWrites.Load()
	err := f.root.WithConfigurationRoleOperation(context.Background(), func(ctx context.Context) error {
		verified, err := f.root.ReadLaunchedConfigurationRuntimeRoles(ctx)
		if err != nil {
			return err
		}
		// The initial proof and all object identities are unchanged. A known
		// enforcement change during Record's object read must deny its CAS.
		f.providerFault.Store(1)
		return f.root.RecordConfigurationRuntimeLaunch(ctx, verified)
	})
	if err == nil || f.path.secretWrites.Load() != before || f.writes.Load() != 1 {
		t.Fatal("receipt mutation used stale enforcement", err)
	}
}

func TestConfigurationLaunchReceiptKeepsOriginalEndDuringBlockedIO(t *testing.T) {
	for _, at := range []string{"input-read", "receipt-cas"} {
		t.Run(at, func(t *testing.T) {
			f := newConfigurationLaunchFixture(t)
			if err := f.launch(); err != nil {
				t.Fatal("original launch", err)
			}
			before := f.path.secretWrites.Load()
			var original time.Time
			var reached bool
			err := f.root.WithConfigurationRoleOperation(context.Background(), func(ctx context.Context) error {
				original, _ = ctx.Deadline()
				verified, err := f.root.ReadLaunchedConfigurationRuntimeRoles(ctx)
				if err != nil {
					return err
				}
				if verified.ValidUntil.After(original) {
					t.Fatal("passive result extended original operation")
				}
				reached = true
				if at == "input-read" {
					f.providerFault.Store(2)
				} else {
					f.blockReceipt.Store(true)
				}
				return f.root.RecordConfigurationRuntimeLaunch(ctx, verified)
			})
			expectedBlock := int32(1)
			if at == "receipt-cas" {
				expectedBlock = 2
			}
			if !reached || f.blockedIO.Load() != expectedBlock || err == nil || time.Now().Before(original) || f.path.secretWrites.Load() != before || f.writes.Load() != 1 {
				t.Fatal("blocking read/CAS escaped its original interval or changed state", reached, err)
			}
		})
	}
}
