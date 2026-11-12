package kubernetes

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
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
	"k8s.io/utils/ptr"
)

// SQL locks and the three precompleted SQL roles are explicitly synthetic, as
// in the existing owner operation fixture. The concrete worker Advance driver,
// eight-GET SetupReader, native/bridge/current/final reads and receipt CAS run.
type workerInputFinalStatusVerifier struct {
	t         *testing.T
	change    func()
	calls     int
	operation *ConfigurationWorkerOperation
	requests  *atomic.Int64
}

func (s *workerInputFinalStatusVerifier) VerifyConfigurationRuntimeRoles(context.Context) (contracts.ConfigurationRuntimeRoleSnapshot, error) {
	return contracts.ConfigurationRuntimeRoleSnapshot{}, cfg.ErrUnavailable
}
func (s *workerInputFinalStatusVerifier) VerifyLaunchedConfigurationRuntimeRoles(context.Context) (contracts.ConfigurationRuntimeRoleSnapshot, error) {
	return contracts.ConfigurationRuntimeRoleSnapshot{}, cfg.ErrUnavailable
}
func (s *workerInputFinalStatusVerifier) WithConfigurationWorkerOperation(ctx context.Context, op *ConfigurationWorkerOperation) error {
	s.calls++
	s.operation = op
	original := op.native.proof.observation
	until := op.until
	deadline, _ := ctx.Deadline()
	current, err := op.ReadConfigurationWorkerPostLock(ctx, op.owner.roles)
	if err != nil {
		return fmt.Errorf("post-lock: %w", err)
	}
	if err = op.ApplyConfigurationWorkerEffect(ctx, op.owner.roles, current); err != nil {
		return fmt.Errorf("effect: %w", err)
	}
	s.change()
	last, err := op.ReadConfigurationWorkerFinal(ctx, op.owner.roles)
	if err != nil {
		return fmt.Errorf("final: %w", err)
	}
	if !op.native.proof.observation.ObservedAt.Equal(original.ObservedAt) || op.native.proof.observation != original || op.until.After(until) || last.ValidUntil.After(deadline) || last.ValidUntil.After(until) {
		s.t.Error("final worker input renewed original observation or bound")
	}
	if err = op.CompleteConfigurationWorkerOperation(ctx, op.owner.roles); err != nil {
		return err
	}
	return nil
}

func TestConfigurationWorkerInputFinalAllowsOnlyDeploymentStatusProgress(t *testing.T) {
	for _, mode := range []string{"status", "generation", "spec", "metadata"} {
		t.Run(mode, func(t *testing.T) {
			owner, verify, writes := newWorkerInputFinalStatusFixture(t, mode)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			out, err := owner.Advance(ctx)
			if mode == "status" {
				if err != nil || out.Progress != ConfigurationWorkerInputAcknowledged {
					t.Fatal("status-only final bracket lost original receipt", out.Progress, err)
				}
			} else if !errors.Is(err, cfg.ErrChanged) || out.Progress != ConfigurationWorkerInputSpent {
				t.Fatal("final bracket accepted changed original Deployment", out.Progress, err)
			}
			requests := verify.requests.Load()
			if _, replayErr := verify.operation.ReadConfigurationWorkerFinal(ctx, owner.roles); replayErr == nil || verify.requests.Load() != requests {
				t.Fatal("closed worker input repeated its final verification")
			}
			if verify.calls != 1 || writes.Load() != 1 {
				t.Fatal("worker input did not retain exactly one original receipt effect", verify.calls, writes.Load())
			}
		})
	}
}

func newWorkerInputFinalStatusFixture(t *testing.T, mode string) (*ConfigurationWorkerInputs, *workerInputFinalStatusVerifier, *atomic.Int32) {
	t.Helper()
	provider := newOwnerOperationProviderFixture(t)
	f := newOwnerIdentityOperationProviderFixture(t, &provider.endpoint)
	root, err := NewConfigurationRuntimeRoleRoot(t.Context(), f.source, f.source.input)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(root.Close)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	snapshot, _, err := f.resources.read(ctx)
	if err != nil {
		t.Fatal("original resources", err)
	}
	source, err := f.source.ReadConfigurationRoleSource(ctx)
	if err != nil {
		t.Fatal("original source", err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	state := contracts.ConfigurationRuntimeRoleState{Format: contracts.ConfigurationRuntimeRoleStateFormat, Input: root.input, OperationID: ownerID(19600), CreatedAt: now, Until: now.Add(30 * time.Minute), Projection: &contracts.PublicRuntimeProjectionClaim{OperationID: ownerID(19601), ClaimedAt: now, Until: source.FreshUntil.Truncate(time.Microsecond), SecretUID: ownerID(19602)}}
	for i, purpose := range contracts.ConfigurationRuntimeRolePurposes() {
		password := make([]byte, 32)
		password[0] = byte(i + 1)
		state.Roles = append(state.Roles, contracts.ConfigurationRuntimeRoleMaterial{Purpose: purpose, Password: base64.RawURLEncoding.EncodeToString(password), Claim: &contracts.ConfigurationRuntimeRoleClaim{OperationID: ownerID(19610 + i), ClaimedAt: now, Until: state.Projection.Until, DatabaseOID: 42, PostmasterAt: now.Add(-time.Hour), Sources: source}, Receipt: &contracts.PublicRuntimeRoleReceipt{RoleName: fmt.Sprintf("as_%s_cfg_%02d", strings.ReplaceAll(root.input.InstallationID, "-", ""), i), RoleOID: uint32(19610 + i), LayoutDigest: root.input.LayoutDigest}})
	}
	if !configurationRoleStateValid(root.input, state, now) {
		t.Fatal("invalid synthetic original SQL roles")
	}
	roles := contracts.ConfigurationRuntimeRoleSnapshot{State: state, UID: ownerID(19603), ResourceVersion: "1", Sources: source, ObservedAt: now, ValidUntil: source.FreshUntil}
	input, digest, raw, err := f.resources.configurationWorkerInputMaterial(snapshot, roles, ownerID(19604), now)
	if err != nil {
		t.Fatal("original input", err)
	}
	profile := *input.ProviderAuthentication
	recipe, err := providerconfig.ConfigurationProviderRecipeFor(input, *snapshot.State.WorkerProvider, profile.ServiceAccount, now)
	if err != nil {
		t.Fatal(err)
	}
	var ca strings.Builder
	for _, der := range input.Kubernetes.Roots {
		ca.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	provider.responses["sys/mounts/auth/"+profile.AuthMount] = map[string]any{"type": "kubernetes", "accessor": profile.AuthMountAccessor, "config": map[string]any{"default_lease_ttl": 0, "max_lease_ttl": 2764800, "token_type": "default-service"}}
	provider.responses["auth/"+profile.AuthMount+"/config"] = map[string]any{"kubernetes_host": input.Kubernetes.Endpoint, "kubernetes_ca_cert": ca.String(), "disable_local_ca_jwt": true, "token_reviewer_jwt_set": true, "pem_keys": []string{}}
	provider.responses["sys/mounts/"+input.KeyService.AuditMount] = map[string]any{"type": "transit"}
	provider.responses[input.KeyService.AuditMount+"/keys/"+input.KeyService.AuditKey] = map[string]any{"name": input.KeyService.AuditKey, "type": "aes256-gcm96", "derived": false, "exportable": false, "allow_plaintext_backup": false, "deletion_allowed": false, "supports_encryption": true, "supports_decryption": true, "latest_version": 1, "min_decryption_version": 1, "min_encryption_version": 0}
	for _, r := range recipe.Roles {
		provider.responses["sys/policies/acl/"+r.Name] = map[string]any{"name": r.Name, "policy": string(r.Policy)}
		provider.responses["auth/"+profile.AuthMount+"/role/"+r.Name] = json.RawMessage(r.Role)
	}
	// An original pending claim and its already-created public ConfigMap select
	// one receipt CAS. The regression does not create a fresh input opportunity.
	snapshot.State.WorkerInputs = &contracts.ConfigurationWorkerInputClaim{OperationID: input.ProviderInputs.OperationID, PublicDigest: digest, ConfigurationRoot: input.ProviderInputs.ConfigurationRoot, ConfigurationSetupID: input.ProviderInputs.ConfigurationSetupID, SQLProjection: input.ProviderInputs.SQLProjection, AuditCredentials: profile.AuditCredentials, ClaimedAt: now, Until: now.Add(5 * time.Second)}
	verify := &workerInputFinalStatusVerifier{t: t, requests: &f.api.requests}
	owner, err := NewConfigurationWorkerInputs(t.Context(), f.bridge, f.resources, root, verify, provider.reader, snapshot)
	if err != nil {
		t.Fatal("worker constructor", err)
	}
	t.Cleanup(owner.Close)
	put := func(path string, value any) {
		body, e := json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}
		var object map[string]any
		if json.Unmarshal(body, &object) != nil {
			t.Fatal("fixture object")
		}
		f.api.objects[path] = object
	}
	f.api.mu.Lock()
	resource := &core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: f.resources.name(), Namespace: input.Namespace.Name, UID: types.UID(snapshot.UID), ResourceVersion: snapshot.ResourceVersion}, Type: core.SecretTypeOpaque}
	stateJSON, _ := json.Marshal(snapshot.State)
	resource.Data = map[string][]byte{"state.json": stateJSON}
	put(f.resources.path(), resource)
	roleJSON, _ := json.Marshal(state)
	put(root.path()+"/"+root.name(), &core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: root.name(), Namespace: input.Namespace.Name, UID: types.UID(roles.UID), ResourceVersion: roles.ResourceVersion}, Type: core.SecretTypeOpaque, Data: map[string][]byte{"state.json": roleJSON}})
	data, err := configurationProjectionData(state)
	if err != nil {
		t.Fatal(err)
	}
	data[contracts.ConfigurationRuntimeRoleManifestFile], err = configurationProjectionManifest(roles)
	if err != nil {
		t.Fatal(err)
	}
	put(root.path()+"/"+root.projectionName(), &core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: root.projectionName(), Namespace: input.Namespace.Name, UID: types.UID(state.Projection.SecretUID), ResourceVersion: "1", Annotations: map[string]string{"asservat.io/role-root-uid": roles.UID, "asservat.io/role-setup-id": state.OperationID, "asservat.io/projection-id": state.Projection.OperationID}}, Type: core.SecretTypeOpaque, Immutable: ptr.To(true), Data: data})
	auditRaw, _ := json.Marshal(contracts.OwnerStorageCredential{AccessKeyID: "synthetic-config-audit", SecretAccessKey: "synthetic-fixed-key"})
	put("/api/v1/namespaces/"+input.Namespace.Name+"/secrets/"+profile.AuditCredentials.Name, &core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: profile.AuditCredentials.Name, Namespace: input.Namespace.Name, UID: types.UID(profile.AuditCredentials.UID), ResourceVersion: "1"}, Type: core.SecretTypeOpaque, Data: map[string][]byte{contracts.ConfigurationProviderAuditCredentialFile: auditRaw}})
	target := owner.inputObject(snapshot, raw)
	target.UID = types.UID(ownerID(19605))
	target.ResourceVersion = "1"
	put("/api/v1/namespaces/"+input.Namespace.Name+"/configmaps/"+target.Name, target)
	writes := &atomic.Int32{}
	previous := f.api.extra
	f.api.extra = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPut && r.URL.Path == f.resources.path() && r.URL.Query().Get("dryRun") == "" {
			var next core.Secret
			if json.NewDecoder(r.Body).Decode(&next) != nil || next.UID != resource.UID || next.ResourceVersion != resource.ResourceVersion || r.URL.Query().Get("fieldValidation") != "Strict" {
				t.Error("receipt CAS changed original identity")
				w.WriteHeader(409)
				return true
			}
			// Existing preparer fixture already holds its API mutex here.
			writes.Add(1)
			v, _ := strconv.Atoi(resource.ResourceVersion)
			next.ResourceVersion = strconv.Itoa(v + 1)
			next.TypeMeta = resource.TypeMeta
			resource = next.DeepCopy()
			put(r.URL.Path, resource)
			permissionReply(w, resource)
			return true
		}
		return previous != nil && previous(w, r)
	}
	f.api.mu.Unlock()
	verify.change = func() {
		f.api.mu.Lock()
		defer f.api.mu.Unlock()
		path := "/apis/apps/v1/namespaces/" + input.Namespace.Name + "/deployments/" + root.input.Deployment.Name
		body, _ := json.Marshal(f.api.objects[path])
		var d apps.Deployment
		if json.Unmarshal(body, &d) != nil {
			t.Fatal("original deployment")
		}
		d.ResourceVersion = "controller-progress"
		d.Status = apps.DeploymentStatus{ObservedGeneration: d.Generation, ReadyReplicas: 1}
		d.ManagedFields = []meta.ManagedFieldsEntry{{Manager: "kube-controller-manager", Operation: meta.ManagedFieldsOperationUpdate, APIVersion: "apps/v1", Subresource: "status"}}
		switch mode {
		case "generation":
			d.Generation++
		case "spec":
			d.Spec.Template.Spec.Containers[0].Args = append(d.Spec.Template.Spec.Containers[0].Args, "changed")
		case "metadata":
			d.Annotations["changed"] = "value"
		}
		put(path, &d)
	}
	return owner, verify, writes
}
