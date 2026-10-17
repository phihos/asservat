package kubernetes

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

// Only the eight actual SetupReader GETs are exercised here. Responses are
// synthetic provider configuration, not qualification of an installed provider.
func configurationWorkerCASSetup(t *testing.T, resources *InitialRuntimeResources, snapshot contracts.InitialRuntimeResourceSnapshot, roles contracts.ConfigurationRuntimeRoleSnapshot) (contracts.HubWorkerDeployment, string, []byte, providerconfig.ConfigurationSetupCheck) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: big.NewInt(17201), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	responses := map[string]any{}
	var reads atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("X-Vault-Token") != "synthetic-fixed-inspector" || r.URL.RawQuery != "" {
			t.Error("setup escaped original read scope")
			w.WriteHeader(403)
			return
		}
		value, ok := responses[strings.TrimPrefix(r.URL.Path, "/v1/")]
		if !ok {
			t.Error("unselected setup path", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		reads.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": value, "auth": nil, "wrap_info": nil, "lease_id": "", "lease_duration": 0, "renewable": false})
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
	resources.initial.KeyService.Endpoint, resources.initial.KeyService.Roots = server.URL, [][]byte{der}
	input, digest, raw, err := resources.configurationWorkerInputMaterial(snapshot, roles, ownerID(17202), time.Now())
	if err != nil {
		t.Fatal("complete synthetic material", err)
	}
	profile := *input.ProviderAuthentication
	recipe, err := providerconfig.ConfigurationProviderRecipeFor(input, *snapshot.State.WorkerProvider, profile.ServiceAccount, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var ca strings.Builder
	for _, b := range input.Kubernetes.Roots {
		ca.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b}))
	}
	responses["sys/mounts/auth/"+profile.AuthMount] = map[string]any{"type": "kubernetes", "accessor": profile.AuthMountAccessor, "config": map[string]any{"default_lease_ttl": 0, "max_lease_ttl": 2764800, "token_type": "default-service"}}
	responses["auth/"+profile.AuthMount+"/config"] = map[string]any{"kubernetes_host": input.Kubernetes.Endpoint, "kubernetes_ca_cert": ca.String(), "disable_local_ca_jwt": true, "token_reviewer_jwt_set": true, "pem_keys": []string{}}
	responses["sys/mounts/"+input.KeyService.AuditMount] = map[string]any{"type": "transit"}
	responses[input.KeyService.AuditMount+"/keys/"+input.KeyService.AuditKey] = map[string]any{"name": input.KeyService.AuditKey, "type": "aes256-gcm96", "derived": false, "exportable": false, "allow_plaintext_backup": false, "deletion_allowed": false, "supports_encryption": true, "supports_decryption": true, "latest_version": 1, "min_decryption_version": 1, "min_encryption_version": 0}
	for _, role := range recipe.Roles {
		responses["sys/policies/acl/"+role.Name] = map[string]any{"name": role.Name, "policy": string(role.Policy)}
		responses["auth/"+profile.AuthMount+"/role/"+role.Name] = json.RawMessage(role.Role)
	}
	reader, err := providerconfig.NewSetupReader(contracts.OwnerProviderEndpoint{Endpoint: server.URL, Roots: [][]byte{der}}, []byte("synthetic-fixed-inspector"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reader.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	check, err := reader.VerifyConfiguration(context.Background(), input, profile)
	if err != nil || reads.Load() != 8 {
		t.Fatal("actual bounded setup reader", err, reads.Load())
	}
	return input, digest, raw, check
}

// The original journals and SQL/native phase observations below are explicitly
// synthetic. The concrete effect, strict CAS/readback, opaque setup check and
// finite driver disposition run. This is not full Advance or SQL qualification.
func TestConfigurationWorkerLostReceiptCASNeverRepeatsWithinAutomaticRun(t *testing.T) {
	for _, test := range []struct {
		name      string
		committed bool
		readback  string
	}{
		{name: "still pending"},
		{name: "committed receipt", committed: true},
		{name: "target absent after unknown receipt", readback: "absent"},
		{name: "target unavailable after unknown receipt", readback: "unavailable"},
		{name: "target replaced after committed receipt", committed: true, readback: "replaced"},
	} {
		t.Run(test.name, func(t *testing.T) {
			resources, snapshot, roles, now := configurationWorkerMaterialFixture(t)
			input, digest, raw, setup := configurationWorkerCASSetup(t, resources, snapshot, roles)
			provenance := input.ProviderInputs
			snapshot.State.WorkerInputs = &contracts.ConfigurationWorkerInputClaim{OperationID: provenance.OperationID, PublicDigest: digest, ConfigurationRoot: provenance.ConfigurationRoot, ConfigurationSetupID: provenance.ConfigurationSetupID, SQLProjection: provenance.SQLProjection, AuditCredentials: input.ProviderAuthentication.AuditCredentials, ClaimedAt: now.Add(-10 * time.Second), Until: now.Add(-5 * time.Second)}
			if !resources.valid(snapshot.State) {
				t.Fatal("synthetic original pending state invalid")
			}
			stateRaw, err := json.Marshal(snapshot.State)
			if err != nil {
				t.Fatal(err)
			}
			object := &core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: resources.name(), Namespace: input.Namespace.Name, UID: types.UID(snapshot.UID), ResourceVersion: snapshot.ResourceVersion}, Type: core.SecretTypeOpaque, Data: map[string][]byte{"state.json": stateRaw}}
			var mu sync.Mutex
			var writes, creates atomic.Int32
			var owner *ConfigurationWorkerInputs
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				switch {
				case r.Method == http.MethodPost:
					creates.Add(1)
					w.WriteHeader(403)
				case r.URL.Path == resources.path() && r.Method == http.MethodGet:
					permissionReply(w, object)
				case r.URL.Path == resources.path() && r.Method == http.MethodPut:
					var next core.Secret
					if json.NewDecoder(r.Body).Decode(&next) != nil || next.UID != object.UID || next.ResourceVersion != object.ResourceVersion || r.URL.Query().Get("fieldValidation") != "Strict" {
						t.Error("CAS lost original identity")
						w.WriteHeader(409)
						return
					}
					writes.Add(1)
					if test.committed {
						version, _ := strconv.Atoi(next.ResourceVersion)
						next.ResourceVersion = strconv.Itoa(version + 1)
						next.TypeMeta = meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}
						object = next.DeepCopy()
					}
					// Both outcomes have the same uncertain response to the caller.
					w.WriteHeader(http.StatusServiceUnavailable)
				case r.Method == http.MethodGet && r.URL.Path == "/api/v1/namespaces/"+input.Namespace.Name+"/configmaps/"+resources.names.WorkerInputs:
					if writes.Load() != 0 && test.readback == "absent" {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					if writes.Load() != 0 && test.readback == "unavailable" {
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					}
					config := owner.inputObject(snapshot, raw)
					config.UID = types.UID(ownerID(17203))
					if writes.Load() != 0 && test.readback == "replaced" {
						config.UID = types.UID(ownerID(17204))
					}
					config.ResourceVersion = "91"
					permissionReply(w, config)
				default:
					t.Error("unexpected effect path", r.Method, r.URL.Path)
					w.WriteHeader(403)
				}
			}))
			t.Cleanup(server.Close)
			client, err := NewPermissionClient(&rest.Config{Host: server.URL, BearerToken: "synthetic-administrator", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}, input.ClusterID, cfg.NamespaceRef{Name: input.Namespace.Name, UID: input.Namespace.UID}, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			resources.preparer.creator = &InitialNamespaceCreator{api: client.api}
			life, cancel := context.WithCancel(context.Background())
			owner = &ConfigurationWorkerInputs{ctx: life, cancel: cancel, resources: resources, roles: &ConfigurationRuntimeRoleRoot{client: client, input: roles.State.Input}, original: snapshot}
			call, finish, err := owner.enter(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer finish()
			defer cancel()
			newPhase := func(current contracts.InitialRuntimeResourceSnapshot, obj *core.Secret) *ConfigurationWorkerOperation {
				p, e := newConfigurationWorkerOperation(owner, call)
				if e != nil {
					t.Fatal(e)
				}
				p.phase = configurationWorkerPhaseInitial // Explicit synthetic prior native phase for this CAS component test.
				p.retained = initialRuntimeRetainedResources{resources: current, object: obj}
				p.input, p.digest, p.raw, p.setup, p.roles = input, digest, append([]byte(nil), raw...), setup, roles
				return p
			}
			first := newPhase(snapshot, object.DeepCopy())
			if err = first.prepareIntent(first.ctx, false, true); err != nil {
				first.close()
				t.Fatal(err)
			}
			first.phase = configurationWorkerPhasePostLock // Synthetic independently verified SQL facts; never used by production.
			if err = first.ApplyConfigurationWorkerEffect(first.ctx, owner.roles, roles); err == nil || !first.receiptAttempted || writes.Load() != 1 {
				first.close()
				t.Fatal("lost receipt reply became success or was retried", err)
			}
			run := configurationWorkerInputRun{calls: 1} // The preceding CREATE was positively read; its original interval is already over.
			if !run.continueAfter(ConfigurationWorkerInputAdvance{Progress: ConfigurationWorkerInputSpent, receiptUncertain: first.receiptAttempted}, err, true) || !run.receiptUncertain {
				first.close()
				t.Fatal("unknown write did not select one inspection")
			}
			first.close()
			current, currentObject, err := resources.read(call)
			if err != nil {
				t.Fatal(err)
			}
			if got := current.State.WorkerInputs.Receipt != nil; got != test.committed {
				t.Fatal("exact readback confused committed and pending")
			}
			second := newPhase(current, currentObject)
			defer second.close()
			err = second.prepareIntent(second.ctx, false, !run.receiptUncertain)
			if test.readback != "" {
				if err == nil || second.phase != configurationWorkerPhaseFailed || second.mode != 0 || writes.Load() != 1 || creates.Load() != 0 {
					t.Fatal("absent/unknown/replaced readback acquired another effect or completion", err)
				}
				if run.continueAfter(ConfigurationWorkerInputAdvance{Progress: ConfigurationWorkerInputSpent}, err, true) {
					t.Fatal("failed inspection admitted another automatic poll")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want := configurationWorkerEffectObservePending
			if test.committed {
				want = configurationWorkerEffectInspect
			}
			if second.mode != want {
				t.Fatal("unknown receipt reply admitted another CAS or CREATE")
			}
			second.phase = configurationWorkerPhasePostLock // Explicit synthetic phase facts again.
			if err = second.ApplyConfigurationWorkerEffect(second.ctx, owner.roles, roles); err != nil {
				t.Fatal(err)
			}
			second.phase = configurationWorkerPhaseFinal // The final native bracket is independently tested, not fabricated as a claim here.
			if err = second.CompleteConfigurationWorkerOperation(second.ctx, owner.roles); err != nil {
				t.Fatal(err)
			}
			if run.continueAfter(second.result, nil, true) || writes.Load() != 1 || creates.Load() != 0 {
				t.Fatal("automatic inspection retried an uncertain effect")
			}
			if got := second.result.Progress == ConfigurationWorkerInputAcknowledged; got != test.committed {
				t.Fatal("pending history reported an acknowledged receipt")
			}
			if !second.result.Snapshot.State.WorkerInputs.Until.Equal(snapshot.State.WorkerInputs.Until) {
				t.Fatal("historical receipt renewed original CREATE")
			}
		})
	}
}
