package kubernetes

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

// This fixture exercises the concrete TLS effect and exact readback, with an
// actual eight-GET SetupReader over synthetic provider responses. The original
// journals, role verification and initial/post-lock/final native facts remain
// explicitly synthetic. It cannot qualify complete AdvanceLaunch or SQL.
type configurationWorkerLaunchCASFixture struct {
	t                 *testing.T
	mu                sync.Mutex
	owner             *ConfigurationWorkerInputs
	call              context.Context
	resources         contracts.InitialRuntimeResourceSnapshot
	roles             contracts.ConfigurationRuntimeRoleSnapshot
	input             contracts.HubWorkerDeployment
	digest            string
	raw               []byte
	setup             providerconfig.ConfigurationSetupCheck
	plan              configurationWorkerLaunchPlan
	deployment        *apps.Deployment
	journal           *core.Secret
	deploymentWrites  atomic.Int32
	receiptWrites     atomic.Int32
	creates           atomic.Int32
	lostDeployment    bool
	commitDeployment  bool
	lostReceipt       bool
	commitReceipt     bool
	deploymentReadErr string
	inputStarted      chan struct{}
	inputRelease      chan struct{}
}

func newConfigurationWorkerLaunchCASFixture(t *testing.T, running bool) *configurationWorkerLaunchCASFixture {
	t.Helper()
	resources, snapshot, roles, now := configurationWorkerMaterialFixture(t)
	object, err := resources.object(snapshot.State, 11)
	if err != nil {
		t.Fatal(err)
	}
	inert := object.object.(*apps.Deployment).DeepCopy()
	inert.UID, inert.ResourceVersion, inert.Generation = types.UID(roles.State.Input.Deployment.UID), "17", 1
	roles.Sources.WorkloadDigest = configurationWorkerDeploymentDigest(*inert)
	for index := range roles.State.Roles {
		roles.State.Roles[index].Claim.Sources = roles.Sources
	}
	input, digest, raw, setup := configurationWorkerCASSetup(t, resources, snapshot, roles)
	in := input.ProviderInputs
	snapshot.State.WorkerInputs = &contracts.ConfigurationWorkerInputClaim{OperationID: in.OperationID, PublicDigest: digest,
		ConfigurationRoot: in.ConfigurationRoot, ConfigurationSetupID: in.ConfigurationSetupID, SQLProjection: in.SQLProjection,
		AuditCredentials: input.ProviderAuthentication.AuditCredentials, ClaimedAt: now, Until: now.Add(5 * time.Second),
		Receipt: &contracts.ConfigurationWorkerInputReceipt{Configuration: contracts.WorkerObjectReference{Name: resources.names.WorkerInputs, UID: ownerID(17501)}, ResourceVersion: "18", ObservedAt: now}}
	if !resources.valid(snapshot.State) {
		t.Fatal("synthetic positive input receipt invalid")
	}
	plan, err := configurationWorkerLaunchPlanFor(input, snapshot, roles, *inert, ownerID(17502), now, roles.ValidUntil)
	if err != nil {
		t.Fatal("synthetic launch intent", err)
	}
	roles.State.Launch = &plan.claim
	roles.ResourceVersion = "43"
	f := &configurationWorkerLaunchCASFixture{t: t, resources: snapshot, roles: roles, input: input, digest: digest, raw: raw, setup: setup, plan: plan, deployment: inert}
	if running {
		f.deployment = plan.running.DeepCopy()
		f.deployment.ResourceVersion = "19"
	}
	server := httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	client, err := NewPermissionClient(&rest.Config{Host: server.URL, BearerToken: "synthetic-administrator", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}, input.ClusterID, cfg.NamespaceRef{Name: input.Namespace.Name, UID: input.Namespace.UID}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	life, cancel := context.WithCancel(context.Background())
	f.owner = &ConfigurationWorkerInputs{ctx: life, cancel: cancel, resources: resources, roles: &ConfigurationRuntimeRoleRoot{client: client, input: roles.State.Input}, original: snapshot}
	encoded, err := json.Marshal(roles.State)
	if err != nil {
		t.Fatal(err)
	}
	f.journal = &core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: f.owner.roles.name(), Namespace: input.Namespace.Name, UID: types.UID(roles.UID), ResourceVersion: roles.ResourceVersion}, Type: core.SecretTypeOpaque, Data: map[string][]byte{"state.json": encoded}}
	call, finish, err := f.owner.enter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	f.call = call
	t.Cleanup(func() { finish(); f.owner.Close() })
	return f
}

func (f *configurationWorkerLaunchCASFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	root := f.owner.roles
	deploymentPath := "/apis/apps/v1/namespaces/" + root.input.Namespace.Name + "/deployments/" + root.input.Deployment.Name
	journalPath := root.path() + "/" + root.name()
	inputPath := "/api/v1/namespaces/" + root.input.Namespace.Name + "/configmaps/" + f.resources.State.WorkerInputs.Receipt.Configuration.Name
	switch {
	case r.Method == http.MethodPost:
		f.creates.Add(1)
		w.WriteHeader(http.StatusForbidden)
	case r.Method == http.MethodGet && r.URL.Path == inputPath:
		if f.inputStarted != nil {
			close(f.inputStarted)
			// A server can still own a request after the client's original end.
			// The test explicitly joins it; cancellation must prevent the PUT.
			<-f.inputRelease
		}
		object := f.owner.inputObject(f.resources, f.raw)
		object.UID = types.UID(f.resources.State.WorkerInputs.Receipt.Configuration.UID)
		object.ResourceVersion = f.resources.State.WorkerInputs.Receipt.ResourceVersion
		permissionReply(w, object)
	case r.Method == http.MethodGet && r.URL.Path == journalPath:
		permissionReply(w, f.journal)
	case r.Method == http.MethodGet && r.URL.Path == deploymentPath:
		if f.deploymentReadErr != "" {
			status := http.StatusNotFound
			if f.deploymentReadErr == "unavailable" {
				status = http.StatusServiceUnavailable
			}
			w.WriteHeader(status)
			return
		}
		permissionReply(w, f.deployment)
	case r.Method == http.MethodPut && r.URL.Path == deploymentPath:
		f.deploymentWrites.Add(1)
		var next apps.Deployment
		if json.NewDecoder(r.Body).Decode(&next) != nil || !equalJSON(next, f.plan.running) ||
			next.UID != f.deployment.UID || next.ResourceVersion != f.deployment.ResourceVersion || r.URL.Query().Get("fieldValidation") != "Strict" {
			f.t.Error("launch PUT changed original CAS or sole edit")
			w.WriteHeader(http.StatusConflict)
			return
		}
		if !f.lostDeployment || f.commitDeployment {
			next.ResourceVersion, next.Generation = "19", 2
			f.deployment = next.DeepCopy()
		}
		if f.lostDeployment {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		permissionReply(w, f.deployment)
	case r.Method == http.MethodPut && r.URL.Path == journalPath:
		f.receiptWrites.Add(1)
		var next core.Secret
		var oldState, nextState contracts.ConfigurationRuntimeRoleState
		if json.NewDecoder(r.Body).Decode(&next) != nil || next.UID != f.journal.UID || next.ResourceVersion != f.journal.ResourceVersion ||
			r.URL.Query().Get("fieldValidation") != "Strict" || json.Unmarshal(f.journal.Data["state.json"], &oldState) != nil ||
			json.Unmarshal(next.Data["state.json"], &nextState) != nil || !configurationWorkerLaunchTransition(oldState, nextState) {
			f.t.Error("receipt CAS changed original role/launch state")
			w.WriteHeader(http.StatusConflict)
			return
		}
		if !f.lostReceipt || f.commitReceipt {
			version, _ := strconv.Atoi(next.ResourceVersion)
			next.ResourceVersion = strconv.Itoa(version + 1)
			next.TypeMeta = meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}
			f.journal = next.DeepCopy()
		}
		if f.lostReceipt {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		permissionReply(w, f.journal)
	default:
		f.t.Error("unexpected launch component request", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusForbidden)
	}
}

// Only effect ownership is minted here; prior native/SQL phases are synthetic.
// New phases still fetch actual journal and target bytes over the fixture TLS.
func (f *configurationWorkerLaunchCASFixture) phase(readback bool) (*ConfigurationWorkerLaunchOperation, error) {
	f.t.Helper()
	p, err := newConfigurationWorkerLaunchOperation(f.owner, f.call)
	if err != nil {
		return nil, err
	}
	w := p.worker
	w.retained = initialRuntimeRetainedResources{resources: f.resources}
	w.input, w.digest, w.raw, w.setup = f.input, f.digest, append([]byte(nil), f.raw...), f.setup
	w.roles = f.roles
	w.native.deployment = *f.plan.running.DeepCopy()
	w.native.deployment.ResourceVersion = "19"
	w.native.proof.observation = f.roles.Sources
	if readback {
		if err = f.owner.roles.readLaunchObject(w.ctx, "/apis/apps/v1/namespaces/"+f.input.Namespace.Name+"/deployments/"+f.roles.State.Input.Deployment.Name, &w.native.deployment); err != nil {
			p.close()
			return nil, err
		}
		w.native.proof.observation.WorkloadDigest = configurationWorkerDeploymentDigest(w.native.deployment)
		w.roles, p.roleObject, err = f.owner.roles.readObserved(w.ctx, w.native.proof.observation, f.roles.ObservedAt)
		if err != nil {
			p.close()
			return nil, err
		}
	} else {
		f.mu.Lock()
		w.native.deployment = *f.deployment.DeepCopy()
		p.roleObject = f.journal.DeepCopy()
		f.mu.Unlock()
	}
	w.observedInput = *f.resources.State.WorkerInputs.Receipt
	w.phase = configurationWorkerPhaseInitial // Explicit synthetic prior native phase.
	return p, nil
}

func TestConfigurationWorkerUnknownLaunchPUTUsesOriginalReadbackOnly(t *testing.T) {
	for _, test := range []struct {
		name      string
		committed bool
		readError string
		mutate    bool
	}{
		{name: "uncommitted"}, {name: "committed", committed: true},
		{name: "absent", readError: "absent"}, {name: "unavailable", readError: "unavailable"},
		{name: "changed running body", committed: true, mutate: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newConfigurationWorkerLaunchCASFixture(t, false)
			f.lostDeployment, f.commitDeployment = true, test.committed
			first, err := f.phase(false)
			if err != nil {
				t.Fatal(err)
			}
			first.plan, first.mode = f.plan, configurationWorkerLaunchUpdate
			first.worker.phase = configurationWorkerPhasePostLock // Synthetic exact SQL verification.
			err = first.ApplyConfigurationWorkerLaunchEffect(first.worker.ctx, f.owner.roles, first.worker.roles)
			if err == nil || !first.effectAttempted || f.deploymentWrites.Load() != 1 || f.receiptWrites.Load() != 0 {
				first.close()
				t.Fatal("unknown launch became success or repeated the PUT", err)
			}
			first.close()
			f.mu.Lock()
			f.deploymentReadErr = test.readError
			if test.mutate {
				f.deployment.Spec.Template.Spec.Containers[0].Image = "example.test/foreign:immutable"
			}
			f.mu.Unlock()
			second, err := f.phase(true)
			if err == nil {
				defer second.close()
				err = second.prepareIntent(second.worker.ctx, false, true)
			}
			if !test.committed || test.readError != "" || test.mutate {
				if err == nil || f.deploymentWrites.Load() != 1 || f.receiptWrites.Load() != 0 || f.creates.Load() != 0 {
					t.Fatal("failed original readback acquired another write", err)
				}
				return
			}
			if err != nil || second.mode != configurationWorkerLaunchReceipt {
				t.Fatal("exact original running body not retained", err)
			}
			second.worker.phase = configurationWorkerPhasePostLock // Synthetic exact SQL verification.
			if err = second.ApplyConfigurationWorkerLaunchEffect(second.worker.ctx, f.owner.roles, second.worker.roles); err != nil {
				t.Fatal(err)
			}
			second.worker.phase = configurationWorkerPhaseFinal // Genuine final native bracket is outside this effect component test.
			if err = second.CompleteConfigurationWorkerLaunch(second.worker.ctx, f.owner.roles); err != nil {
				t.Fatal(err)
			}
			if second.result.Progress != ConfigurationWorkerLaunchAcknowledged || f.deploymentWrites.Load() != 1 || f.receiptWrites.Load() != 1 || f.creates.Load() != 0 ||
				!second.result.Snapshot.State.Launch.Until.Equal(f.plan.claim.Until) {
				t.Fatal("historical acknowledgement changed original launch or repeated effect")
			}
		})
	}
}

func TestConfigurationWorkerLostLaunchReceiptCASDoesNotRetryWithinRun(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "pending", true: "committed"}[committed], func(t *testing.T) {
			f := newConfigurationWorkerLaunchCASFixture(t, true)
			f.lostReceipt, f.commitReceipt = true, committed
			first, err := f.phase(true)
			if err != nil {
				t.Fatal(err)
			}
			if err = first.prepareIntent(first.worker.ctx, false, true); err != nil {
				first.close()
				t.Fatal(err)
			}
			first.worker.phase = configurationWorkerPhasePostLock // Synthetic exact SQL verification.
			err = first.ApplyConfigurationWorkerLaunchEffect(first.worker.ctx, f.owner.roles, first.worker.roles)
			if err == nil || !first.receiptAttempted || f.receiptWrites.Load() != 1 {
				first.close()
				t.Fatal("receipt reply did not remain unknown", err)
			}
			run := configurationWorkerLaunchRun{calls: 1}
			if !run.continueAfter(ConfigurationWorkerLaunchAdvance{Progress: ConfigurationWorkerLaunchSpent, receiptUncertain: true}, err, true) || !run.receiptUncertain {
				first.close()
				t.Fatal("missing one exact receipt inspection")
			}
			first.close()
			second, err := f.phase(true)
			if err != nil {
				t.Fatal(err)
			}
			defer second.close()
			if err = second.prepareIntent(second.worker.ctx, false, !run.receiptUncertain); err != nil {
				t.Fatal(err)
			}
			want := configurationWorkerLaunchObservePending
			if committed {
				want = configurationWorkerLaunchInspect
			}
			if second.mode != want {
				t.Fatal("unknown receipt selected another CAS")
			}
			second.worker.phase = configurationWorkerPhasePostLock // Synthetic exact SQL verification.
			if err = second.ApplyConfigurationWorkerLaunchEffect(second.worker.ctx, f.owner.roles, second.worker.roles); err != nil {
				t.Fatal(err)
			}
			second.worker.phase = configurationWorkerPhaseFinal // Synthetic final native bracket for this effect component test.
			if err = second.CompleteConfigurationWorkerLaunch(second.worker.ctx, f.owner.roles); err != nil {
				t.Fatal(err)
			}
			if run.continueAfter(second.result, nil, true) || f.receiptWrites.Load() != 1 || f.deploymentWrites.Load() != 0 || f.creates.Load() != 0 ||
				(second.result.Progress == ConfigurationWorkerLaunchAcknowledged) != committed || !second.result.Snapshot.State.Launch.Until.Equal(f.plan.claim.Until) {
				t.Fatal("unknown receipt reattempted a write or promoted pending history")
			}
		})
	}
}

func TestConfigurationWorkerLaunchOriginalDeadlineAfterBlockedInputRead(t *testing.T) {
	f := newConfigurationWorkerLaunchCASFixture(t, false)
	f.inputStarted, f.inputRelease = make(chan struct{}), make(chan struct{})
	var release sync.Once
	defer release.Do(func() { close(f.inputRelease) })
	phase, err := f.phase(false)
	if err != nil {
		t.Fatal(err)
	}
	defer phase.close()
	phase.plan, phase.mode = f.plan, configurationWorkerLaunchUpdate
	phase.worker.phase = configurationWorkerPhasePostLock // Synthetic exact SQL verification.
	call, cancel := context.WithTimeout(phase.worker.ctx, 40*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- phase.ApplyConfigurationWorkerLaunchEffect(call, f.owner.roles, phase.worker.roles) }()
	select {
	case <-f.inputStarted:
	case err = <-result:
		t.Fatal("effect stopped before the intended blocked input read", err)
	case <-time.After(time.Second):
		t.Fatal("input read did not start")
	}
	select {
	case err = <-result:
		if err == nil || phase.effectAttempted || f.deploymentWrites.Load() != 0 || f.receiptWrites.Load() != 0 || f.creates.Load() != 0 {
			t.Fatal("expired original input read admitted a launch effect", err)
		}
	case <-time.After(time.Second):
		t.Fatal("client retained a blocked read after its original caller deadline")
	}
	release.Do(func() { close(f.inputRelease) })
}
