package kubernetes

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SQL verification and provider credentials are synthetic here. The real root,
// current native proof calls, exact object decoder and one-use producer run.
// The separately qualified native SQL matrix remains the SQL authority test.
type ownerIdentityComposedVerification struct{ root *OwnerIdentityRoleRoot }

func (v ownerIdentityComposedVerification) VerifyOwnerIdentityRoles(ctx context.Context) (contracts.OwnerIdentityRoleSnapshot, error) {
	return v.root.ReadOwnerIdentityRoles(ctx)
}

type ownerIdentityComposedFixture struct {
	*ownerIdentityProducerFixture
	lose                                                  atomic.Int32 // 1 credentials CREATE, 2 configuration CREATE, 3 launch PUT.
	credentialCreates, configurationCreates, launchWrites atomic.Int32
}

func newOwnerIdentityComposedFixture(t *testing.T) (*ownerIdentityComposedFixture, *OwnerIdentityProjection) {
	t.Helper()
	f := &ownerIdentityComposedFixture{ownerIdentityProducerFixture: newOwnerIdentityProducerFixture(t)}
	if _, e := f.root.OpenOwnerIdentityRoles(context.Background()); e != nil {
		t.Fatal("original role root", e)
	}
	started := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	for i, purpose := range contracts.OwnerIdentityRolePurposes() {
		ctx, end := context.WithTimeout(context.Background(), 5*time.Second)
		roles, fresh, e := f.root.ClaimOwnerIdentityRole(ctx, purpose, 42, started)
		if e == nil && fresh {
			e = f.root.CompleteOwnerIdentityRole(ctx, roles, purpose, contracts.PublicRuntimeRoleReceipt{RoleName: "as_" + strings.ReplaceAll(f.root.input.InstallationID, "-", "") + "_own_0" + strconv.Itoa(i), RoleOID: uint32(6500 + i), LayoutDigest: f.root.input.LayoutDigest})
		}
		end()
		if e != nil || !fresh {
			t.Fatal("original synthetic SQL receipt", purpose, fresh, e)
		}
	}
	root, original, guard := f.root, f.resources.initial, f.source.protection
	plan := f.bridge.administration.Owner
	in := contracts.OwnerDeployment{Format: contracts.OwnerDeploymentFormat, InstallationID: original.InstallationID, ClusterID: original.ClusterID, PermissionRootID: ownerID(9700), Namespace: original.Namespace, ConfigurationUID: root.input.OwnerConfigurationUID, Kubernetes: original.Kubernetes, Postgres: original.Postgres, AuditStore: original.AuditStore, Connections: 4, Concurrency: 2}
	in.Postgres.MaxConnections = 1
	in.KeyService = contracts.OwnerKeyService{Endpoint: original.KeyService.Endpoint, Roots: original.KeyService.Roots, AuditMount: original.KeyService.AuditMount, AuditKey: original.KeyService.AuditKey, PKIMount: "owner-pki", ServerRole: "owner-server", ClientRole: "owner-client"}
	in.WorkloadGuard = contracts.OwnerDeploymentGuard{Name: plan.Name, PolicyUID: guard.pin.PolicyUID, PolicyGeneration: guard.pin.PolicyGeneration, BindingUID: guard.pin.BindingUID, BindingResourceVersion: guard.pin.BindingResourceVersion}
	for _, a := range plan.Administrators {
		in.WorkloadGuard.Administrators = append(in.WorkloadGuard.Administrators, contracts.OwnerDeploymentActor{Kind: string(a.Kind), Name: a.Name})
	}
	for _, p := range plan.ConfigurationProbes {
		in.ConfigurationProbes = append(in.ConfigurationProbes, contracts.OwnerConfigurationProbe{ConfigMap: p.ConfigMap, ServiceAccount: p.ServiceAccount})
	}
	for _, p := range plan.SchedulingLeases {
		in.SchedulingLeases = append(in.SchedulingLeases, contracts.OwnerSchedulingLease{Lease: p.Lease, ServiceAccount: p.ServiceAccount})
	}
	h := plan.InitialHistoryProbe
	in.InitialHistoryProbe = &contracts.OwnerInitialHistoryProbe{Namespace: contracts.WorkerObjectReference{Name: h.Namespace.Name, UID: h.Namespace.UID}, ServiceAccount: contracts.WorkerObjectReference{Name: h.ServiceAccount, UID: h.ServiceAccountUID}, Configuration: h.Configuration}
	in.CapacityProbe = &contracts.OwnerDeploymentCapacityProbe{ServiceAccount: contracts.WorkerObjectReference{Name: plan.CapacityProbe.ServiceAccount, UID: plan.CapacityProbe.ServiceAccountUID}}
	path := "/apis/apps/v1/namespaces/" + original.Namespace.Name + "/deployments/" + root.input.Deployment.Name
	f.api.mu.Lock()
	raw, _ := json.Marshal(f.api.objects[path])
	var d apps.Deployment
	if json.Unmarshal(raw, &d) != nil {
		f.api.mu.Unlock()
		t.Fatal("original fixture Deployment")
	}
	// The native API supplies these exact scalar defaults; no other template
	// field is changed or removed, and the original journal is untouched.
	d.Spec.Template.Spec.DNSPolicy = core.DNSClusterFirst
	d.Spec.Template.Spec.SchedulerName = core.DefaultSchedulerName
	d.Spec.Template.Spec.Containers[0].TerminationMessagePath = core.TerminationMessagePathDefault
	d.Spec.Template.Spec.Containers[0].TerminationMessagePolicy = core.TerminationMessageReadFile
	raw, _ = json.Marshal(d)
	var object map[string]any
	_ = json.Unmarshal(raw, &object)
	f.api.objects[path] = object
	f.api.mu.Unlock()
	digest, e := ConnectorAPITemplateDigest(d.Spec.Template)
	if e != nil {
		t.Fatal("original native template", e)
	}
	in.Observation = &contracts.OwnerObservationBootstrap{Format: contracts.OwnerObservationFormat, TemplateDigest: hex.EncodeToString(digest[:]), ImageDigest: strings.Split(d.Spec.Template.Spec.Containers[0].Image, "@sha256:")[1], ProtectionDigest: hex.EncodeToString(guard.digest[:]), Peers: []contracts.OwnerObservationPeer{{InstallationID: original.InstallationID, ClusterID: original.ClusterID, IssuerEpoch: original.IssuerEpoch, PeerID: ownerID(9701), Roots: f.resources.ownerRoots}}}
	provider := OwnerIdentityProviderMaterial{Audit: contracts.OwnerStorageCredential{AccessKeyID: "synthetic-owner-audit", SecretAccessKey: "synthetic-owner-secret"}, WrapToken: "synthetic-wrap", OpenToken: "synthetic-open", ServerToken: "synthetic-server", ClientToken: "synthetic-client"}
	producer, e := NewOwnerIdentityProjection(root, ownerIdentityComposedVerification{root}, in, provider)
	if e != nil {
		t.Fatal("original composed projection", e)
	}
	f.api.mu.Lock()
	previous := f.api.extra
	f.api.extra = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Query().Get("dryRun") != "" {
			return previous(w, r)
		}
		isJournal := r.Method == http.MethodPut && r.URL.Path == f.resources.path()
		isLaunch := r.Method == http.MethodPut && r.URL.Path == path
		collection := "/api/v1/namespaces/" + original.Namespace.Name
		isCreate := r.Method == http.MethodPost && (r.URL.Path == collection+"/secrets" || r.URL.Path == collection+"/configmaps")
		if !isJournal && !isLaunch && !isCreate {
			return previous(w, r)
		}
		raw, e := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if e != nil {
			t.Error(e)
			return true
		}
		r.Body = io.NopCloser(bytes.NewReader(raw))
		var next map[string]any
		if json.Unmarshal(raw, &next) != nil {
			t.Error("fixed effect wire")
			return true
		}
		m, ok := next["metadata"].(map[string]any)
		if !ok {
			t.Error("fixed effect metadata")
			return true
		}
		name, _ := m["name"].(string)
		purpose := int32(0)
		if isCreate {
			if name == f.resources.names.OwnerProviders && strings.HasSuffix(r.URL.Path, "/secrets") {
				purpose = 1
			} else if name == f.resources.names.OwnerInputs && strings.HasSuffix(r.URL.Path, "/configmaps") {
				purpose = 2
			} else {
				return previous(w, r)
			}
		}
		if r.URL.Query().Get("fieldValidation") != "Strict" {
			t.Error("fixed effect missing strict validation")
		}
		full := r.URL.Path
		if isCreate {
			full += "/" + name
		}
		if isLaunch {
			purpose = 3
			next["apiVersion"], next["kind"] = "apps/v1", "Deployment"
		} else {
			next["apiVersion"], next["kind"] = "v1", "Secret"
			if purpose == 2 {
				next["kind"] = "ConfigMap"
			}
		}
		if isCreate {
			if f.api.objects[full] != nil {
				f.api.status(w, 409, meta.StatusReasonAlreadyExists, "objects", "")
				return true
			}
			if purpose == 1 {
				f.credentialCreates.Add(1)
			} else {
				f.configurationCreates.Add(1)
			}
			encoded, _ := json.Marshal(next)
			f.api.store(full, encoded)
		} else {
			old := f.api.objects[full]
			if old == nil {
				t.Error("fixed CAS missing original")
				return true
			}
			om := old["metadata"].(map[string]any)
			if m["uid"] != om["uid"] || m["resourceVersion"] != om["resourceVersion"] {
				f.api.status(w, 409, meta.StatusReasonConflict, "objects", "")
				return true
			}
			f.api.serial++
			m["resourceVersion"] = strconv.Itoa(f.api.serial)
			if isLaunch {
				f.launchWrites.Add(1)
				m["generation"] = float64(2)
			}
			f.api.objects[full] = next
		}
		if purpose != 0 && f.lose.CompareAndSwap(purpose, 0) {
			f.api.status(w, 503, meta.StatusReasonServiceUnavailable, "objects", "synthetic lost committed reply")
			return true
		}
		if isCreate {
			w.WriteHeader(http.StatusCreated)
		}
		permissionReply(w, f.api.objects[full])
		return true
	}
	f.api.mu.Unlock()
	return f, producer
}

func (f *ownerIdentityComposedFixture) resourceState(t *testing.T) contracts.InitialRuntimeResourceState {
	t.Helper()
	f.api.mu.Lock()
	raw, _ := json.Marshal(f.api.objects[f.resources.path()])
	f.api.mu.Unlock()
	var object core.Secret
	if json.Unmarshal(raw, &object) != nil {
		t.Fatal("resource wire")
	}
	defer clearRuntimeProjection(object.Data)
	state, e := contracts.DecodeInitialRuntimeResourceState(bytes.NewReader(object.Data["state.json"]))
	if e != nil {
		t.Fatal("resource state", e)
	}
	return state
}
