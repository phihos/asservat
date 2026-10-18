package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	fleet "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	admission "k8s.io/api/admissionregistration/v1"
	apps "k8s.io/api/apps/v1"
	auth "k8s.io/api/authentication/v1"
	authz "k8s.io/api/authorization/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

type publicRoleRootFixture struct {
	input                 contracts.PublicRuntimeRoles
	root                  *PublicRuntimeRoleRoot
	mu                    sync.Mutex
	object                *core.Secret
	projection            *core.Secret
	federation            *core.Secret
	publisher             *core.Secret
	projectionWrites      atomic.Int32
	lostProjection        atomic.Bool
	lostProjectionClaim   atomic.Bool
	writes                atomic.Int32
	lostCreate, lostClaim bool
	badAdmin              atomic.Bool
	badSecretVersion      atomic.Bool
	configuration         fleet.OwnerConfiguration
	replicas              atomic.Int32
	requests              atomic.Int64
	workerObjects         map[string]any
}

func (f *publicRoleRootFixture) ReadOwnerConfiguration(ctx context.Context) (fleet.OwnerConfigurationObservation, error) {
	if ctx.Err() != nil {
		return fleet.OwnerConfigurationObservation{}, ctx.Err()
	}
	n := time.Now().UTC().Truncate(time.Microsecond)
	until := n.Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(until) {
		until = d
	}
	return fleet.OwnerConfigurationObservation{Configuration: f.configuration.Clone(), ObservedAt: n, FreshUntil: until}, nil
}

// The API transport, protected-object parsing and CAS flow are actual code.
// The loopback fixture simulates Kubernetes enforcement and has no SQL side.
func newPublicRoleRootFixture(t *testing.T, lostCreate, lostClaim bool) *publicRoleRootFixture {
	return newPublicRoleRootFixtureWithWorker(t, lostCreate, lostClaim, false)
}

func newPublicRoleRootFixtureWithWorker(t *testing.T, lostCreate, lostClaim, worker bool) *publicRoleRootFixture {
	t.Helper()
	plan := cfg.OwnerWorkloadAdministration{Name: "owner-workload", Deployment: "hub", DeploymentUID: ownerID(5), ControlNamespace: cfg.NamespaceRef{Name: "owners", UID: ownerID(4)}, Administrators: []cfg.KubernetesActor{{Kind: "User", Name: "installer"}}, ConfigurationProbes: []cfg.OwnerConfigurationProbe{}, SchedulingLeases: []cfg.OwnerSchedulingLease{}}
	policy, binding, err := OwnerWorkloadAdmission(plan)
	if err != nil {
		t.Fatal(err)
	}
	pin := GuardPin{PolicyUID: ownerID(1), PolicyGeneration: 1, BindingUID: ownerID(2), BindingResourceVersion: "20"}
	policy.UID = types.UID(pin.PolicyUID)
	policy.Generation = 1
	policy.ResourceVersion = "10"
	policy.Status.ObservedGeneration = 1
	policy.Status.TypeChecking = &admission.TypeChecking{}
	binding.UID = types.UID(pin.BindingUID)
	binding.ResourceVersion = "20"
	f := &publicRoleRootFixture{input: contracts.PublicRuntimeRoles{Format: contracts.PublicRuntimeRolesFormat, InstallationID: ownerID(7), InitialClaimID: ownerID(8), ClusterID: ownerID(9), OwnerConfigurationUID: ownerID(10), Namespace: contracts.WorkerObjectReference{Name: "owners", UID: ownerID(4)}, LayoutDigest: strings.Repeat("1", 64)}, lostCreate: lostCreate, lostClaim: lostClaim}
	f.configuration = fleet.OwnerConfiguration{Pool: fleet.OwnerPool{InstallationID: f.input.InstallationID, ClusterID: f.input.ClusterID, IssuerEpoch: ownerID(11), Namespace: "owners", NamespaceUID: ownerID(4), Service: "hub", ServiceUID: ownerID(12), Deployment: "hub", DeploymentUID: ownerID(5), ServiceAccount: "hub", AccountUID: ownerID(13), Port: 8443}, Revision: identity.Revision{UID: f.input.OwnerConfigurationUID, Generation: 1, Digest: artifact.Digest{1}}, ProtectionDigest: artifact.Digest{2}, IssuerRoots: [][]byte{{1}}}
	f.replicas.Store(2)
	if worker {
		input, objects := publicWorkerProofFixture(t, f.input)
		f.input.Worker = input.Worker
		f.workerObjects = objects
	}
	status := func(w http.ResponseWriter, code int, reason meta.StatusReason) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: meta.StatusFailure, Reason: reason, Code: int32(code)})
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		if v, ok := f.workerObjects[r.URL.Path]; ok {
			if r.Method != http.MethodGet {
				t.Error("worker provenance attempted effect")
				http.Error(w, "method", 405)
				return
			}
			permissionReply(w, v)
			return
		}
		switch {
		case r.URL.Path == "/api/v1/namespaces/owners":
			permissionReply(w, permissionNamespace("owners", ownerID(4)))
		case strings.HasSuffix(r.URL.Path, "/validatingadmissionpolicies/owner-workload"):
			permissionReply(w, policy)
		case strings.HasSuffix(r.URL.Path, "/validatingadmissionpolicybindings/owner-workload"):
			permissionReply(w, binding)
		case strings.HasSuffix(r.URL.Path, "/selfsubjectreviews"):
			name := "probe"
			if r.Header.Get("Authorization") == "Bearer administrator" && !f.badAdmin.Load() {
				name = "installer"
			}
			permissionReply(w, auth.SelfSubjectReview{Status: auth.SelfSubjectReviewStatus{UserInfo: auth.UserInfo{Username: name, Groups: []string{"system:authenticated"}}}})
		case strings.HasSuffix(r.URL.Path, "/selfsubjectaccessreviews"):
			permissionReply(w, authz.SelfSubjectAccessReview{Status: authz.SubjectAccessReviewStatus{Allowed: true}})
		case strings.HasSuffix(r.URL.Path, "/deployments/hub"):
			if r.Method == http.MethodGet {
				permissionReply(w, apps.Deployment{TypeMeta: meta.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"}, ObjectMeta: meta.ObjectMeta{Name: "hub", Namespace: "owners", UID: types.UID(ownerID(5)), ResourceVersion: "1"}, Spec: apps.DeploymentSpec{Replicas: ptr.To(f.replicas.Load()), Template: core.PodTemplateSpec{Spec: core.PodSpec{ServiceAccountName: "hub"}}, Strategy: apps.DeploymentStrategy{Type: apps.RollingUpdateDeploymentStrategyType, RollingUpdate: &apps.RollingUpdateDeployment{MaxSurge: ptr.To(intstr.FromInt(1))}}}})
				return
			}
			if r.Method != http.MethodPut || r.URL.Query().Get("dryRun") != "All" {
				t.Error("unbounded proof write")
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			permissionReply(w, meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: meta.StatusFailure, Reason: meta.StatusReasonForbidden, Code: 403, Details: &meta.StatusDetails{Group: "apps", Kind: "deployments", Causes: []meta.StatusCause{{Message: "ValidatingAdmissionPolicy 'owner-workload' with binding 'owner-workload' denied request: " + ownerWorkloadDenial}}}})
		case strings.Contains(r.URL.Path, "/secrets"):
			f.mu.Lock()
			defer f.mu.Unlock()
			if r.Header.Get("Authorization") != "Bearer administrator" {
				status(w, 403, meta.StatusReasonForbidden)
				return
			}
			if r.Method == http.MethodGet {
				target := f.object
				if strings.HasSuffix(r.URL.Path, "/"+f.root.projectionName()) {
					target = f.projection
				}
				if strings.HasSuffix(r.URL.Path, "/"+contracts.FederationRuntimeProjectionName(f.input.InstallationID)) {
					target = f.federation
				}
				if strings.HasSuffix(r.URL.Path, "/"+contracts.PublisherRuntimeProjectionName(f.input.InstallationID)) {
					target = f.publisher
				}
				if target == nil {
					status(w, 404, meta.StatusReasonNotFound)
				} else {
					response := target.DeepCopy()
					if f.badSecretVersion.Load() {
						response.APIVersion = "wrong/v1"
					}
					permissionReply(w, response)
				}
				return
			}
			if r.URL.Query().Get("fieldValidation") != "Strict" {
				t.Error("missing strict server validation")
			}
			var object core.Secret
			if json.NewDecoder(r.Body).Decode(&object) != nil {
				status(w, 400, meta.StatusReasonBadRequest)
				return
			}
			// The real versioned API response supplies TypeMeta even when the
			// unversioned client encoder omitted apiVersion from the request.
			// This fixture must model that response, not echo request bytes.
			object.TypeMeta = meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}
			if side, uid := map[string]**core.Secret{contracts.FederationRuntimeProjectionName(f.input.InstallationID): &f.federation, contracts.PublisherRuntimeProjectionName(f.input.InstallationID): &f.publisher}[object.Name],
				map[string]int{contracts.FederationRuntimeProjectionName(f.input.InstallationID): 12, contracts.PublisherRuntimeProjectionName(f.input.InstallationID): 13}[object.Name]; side != nil {
				if r.Method != http.MethodPost || *side != nil {
					status(w, 409, meta.StatusReasonAlreadyExists)
					return
				}
				object.UID = types.UID(ownerID(uid))
				object.ResourceVersion = "1"
				*side = object.DeepCopy()
				w.WriteHeader(http.StatusCreated)
				permissionReply(w, &object)
				return
			}
			if object.Name == f.root.projectionName() {
				if r.Method != http.MethodPost || f.projection != nil {
					status(w, 409, meta.StatusReasonAlreadyExists)
					return
				}
				object.UID = types.UID(ownerID(11))
				object.ResourceVersion = "1"
				f.projection = object.DeepCopy()
				f.projectionWrites.Add(1)
				if f.lostProjection.Load() {
					status(w, 500, meta.StatusReasonInternalError)
					return
				}
				w.WriteHeader(http.StatusCreated)
				permissionReply(w, &object)
				return
			}
			if r.Method == http.MethodPost {
				if f.object != nil {
					status(w, 409, meta.StatusReasonAlreadyExists)
					return
				}
				object.UID = types.UID(ownerID(10))
				object.ResourceVersion = "1"
			} else if r.Method == http.MethodPut {
				if f.object == nil || object.UID != f.object.UID || object.ResourceVersion != f.object.ResourceVersion {
					status(w, 409, meta.StatusReasonConflict)
					return
				}
				n, _ := strconv.Atoi(object.ResourceVersion)
				object.ResourceVersion = strconv.Itoa(n + 1)
			} else {
				status(w, 400, meta.StatusReasonBadRequest)
				return
			}
			var state contracts.PublicRuntimeRoleState
			_ = json.Unmarshal(object.Data["state.json"], &state)
			lostProjectionClaim := f.lostProjectionClaim.Load() && state.Projection != nil && state.Projection.SecretUID == ""
			f.object = object.DeepCopy()
			f.writes.Add(1)
			if lostProjectionClaim {
				status(w, 500, meta.StatusReasonInternalError)
				return
			}
			if f.lostCreate && r.Method == http.MethodPost || f.lostClaim && r.Method == http.MethodPut && object.ResourceVersion == "2" {
				status(w, 500, meta.StatusReasonInternalError)
				return
			}
			permissionReply(w, &object)
		default:
			t.Error("unexpected API route", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	makeClient := func(token string) *PermissionClient {
		c, e := NewPermissionClient(&rest.Config{Host: server.URL, BearerToken: token, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}, f.input.ClusterID, plan.ControlNamespace, time.Now)
		if e != nil {
			t.Fatal(e)
		}
		return c
	}
	observer, probe := makeClient("administrator"), makeClient("probe")
	protection, err := NewOwnerWorkloadProtection(observer, probe, plan, pin)
	if err != nil {
		t.Fatal(err)
	}
	f.root, err = NewPublicRuntimeRoleRoot(t.Context(), observer, protection, f, f.input)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.root.Close)
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.object == nil {
			t.Logf("role-root diagnostic: writes=%d root=false", f.writes.Load())
			return
		}
		// Fixed metadata and booleans only: never print private state, passwords,
		// key bytes, serialized input, or a decoder/provider error.
		state, decode := contracts.DecodePublicRuntimeRoleState(bytes.NewReader(f.object.Data["state.json"]))
		t.Logf("role-root diagnostic: writes=%d root=true api=%q kind=%q namespace=%t name=%t type=%t fields=%d decode=%t valid=%t", f.writes.Load(), f.object.APIVersion, f.object.Kind, f.object.Namespace == f.input.Namespace.Name, f.object.Name == f.root.name(), f.object.Type == core.SecretTypeOpaque, len(f.object.Data), decode == nil, decode == nil && runtimeRoleStateValid(f.input, state, time.Now()))
	})
	return f
}
func TestPublicRoleRootUnknownClaimCannotRenewFirstCreation(t *testing.T) {
	for _, mode := range []string{"normal", "lost-root-create", "lost-claim"} {
		t.Run(mode, func(t *testing.T) {
			f := newPublicRoleRootFixture(t, mode == "lost-root-create", mode == "lost-claim")
			original, err := f.root.OpenPublicRuntimeRoles(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if original.UID == "" || len(original.State.Roles) != len(contracts.PublicRuntimeRolePurposes()) || f.writes.Load() != 1 {
				t.Fatal("missing exact original private root")
			}
			claimed, fresh, err := f.root.ClaimPublicRuntimeRole(t.Context(), "identity-read", 123, time.Now().Add(-time.Hour))
			if mode == "lost-claim" {
				if err == nil || fresh {
					t.Fatal("unknown CAS was fresh")
				}
			} else if err != nil || !fresh {
				t.Fatal("sole acknowledged first CAS unavailable", err)
			}
			replay, again, err := f.root.ClaimPublicRuntimeRole(t.Context(), "identity-read", 456, time.Now().Add(-time.Minute))
			if err != nil || again || replay.State.Roles[0].Claim.DatabaseOID != 123 || f.writes.Load() != 2 {
				t.Fatal("claim replay replaced original identity or repeated write", err)
			}
			if fresh && (!replay.State.Roles[0].Claim.Until.Equal(claimed.State.Roles[0].Claim.Until) || replay.State.Roles[0].Claim.OperationID != claimed.State.Roles[0].Claim.OperationID) {
				t.Fatal("claim dates changed")
			}
			reopened, err := f.root.OpenPublicRuntimeRoles(t.Context())
			if err != nil || reopened.State.OperationID != original.State.OperationID || reopened.State.Roles[0].Password != original.State.Roles[0].Password || !reflect.DeepEqual(reopened.State.MAC, original.State.MAC) || f.writes.Load() != 2 {
				t.Fatal("root replay replaced credentials", err)
			}
		})
	}
}
func TestPublicRoleRootRevokedAdministratorAndCancelledCallerCannotClaim(t *testing.T) {
	f := newPublicRoleRootFixture(t, false, false)
	if _, err := f.root.OpenPublicRuntimeRoles(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.badAdmin.Store(true)
	if _, fresh, err := f.root.ClaimPublicRuntimeRole(t.Context(), "identity-read", 123, time.Now().Add(-time.Hour)); err == nil || fresh || f.writes.Load() != 1 {
		t.Fatal("revoked administrator created role claim")
	}
	f.badAdmin.Store(false)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, fresh, err := f.root.ClaimPublicRuntimeRole(ctx, "identity-read", 123, time.Now().Add(-time.Hour)); err == nil || fresh || f.writes.Load() != 1 {
		t.Fatal("cancelled caller created role claim")
	}
}

func TestPublicRoleRootRejectsUnsupportedRetainedProcessCount(t *testing.T) {
	f := newPublicRoleRootFixture(t, false, false)
	if _, err := f.root.OpenPublicRuntimeRoles(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.replicas.Store(3)
	if _, fresh, err := f.root.ClaimPublicRuntimeRole(t.Context(), "identity-read", 123, time.Now().Add(-time.Hour)); err == nil || fresh || f.writes.Load() != 1 {
		t.Fatal("unsupported hub replica count created a role claim")
	}
	f.replicas.Store(2)
	if _, fresh, err := f.root.ClaimPublicRuntimeRole(t.Context(), "identity-read", 123, time.Now().Add(-time.Hour)); err != nil || !fresh {
		t.Fatal("valid bounded rollout could not make original first claim", err)
	}
}

func TestPublicRoleProjectionExcludesReconcilerCredentials(t *testing.T) {
	_, original := completedPublicRoleFixture(t)
	// Future installer inventories must not implicitly extend the hub mount.
	extra := original.State.Roles[0]
	extra.Purpose, extra.Password = "capacity-capture", "not-a-hub-credential"
	original.State.Roles = append(original.State.Roles, extra)
	data, err := runtimeProjectionData(original.State)
	if err != nil {
		t.Fatal(err)
	}
	defer clearRuntimeProjection(data)
	if len(data) != len(contracts.PublicRuntimeHubRolePurposes()) || data["sql-public-capacity-capture.json"] != nil {
		t.Fatal("reconciler credential leaked into public runtime projection")
	}
}

// Receipts here are deliberately synthetic: this test isolates Secret lifetime,
// fixed projection contents and unknown-create replay, not SQL authorization.
func completedPublicRoleFixture(t *testing.T) (*publicRoleRootFixture, contracts.PublicRuntimeRoleSnapshot) {
	t.Helper()
	f := newPublicRoleRootFixtureWithWorker(t, false, false, true)
	original, err := f.root.OpenPublicRuntimeRoles(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	// Projection-only tests start from explicitly synthetic completed SQL claims.
	// The dedicated full-loop test below retains actual claim/complete parsing,
	// native proof calls, original request bounds and every purpose's flow.
	for n := range original.State.Roles {
		role := &original.State.Roles[n]
		now := time.Now().UTC().Truncate(time.Microsecond)
		role.Claim = &contracts.PublicRuntimeRoleClaim{OperationID: ownerID(2100 + n), DatabaseOID: 123, PostmasterAt: now.Add(-time.Hour), ClaimedAt: now, Until: now.Add(5 * time.Second)}
		ordinal, _ := contracts.PublicRuntimeRoleOrdinal(role.Purpose)
		name := "as_" + strings.ReplaceAll(f.input.InstallationID, "-", "") + "_pub_" + string([]byte{'0' + byte(ordinal/10), '0' + byte(ordinal%10)})
		role.Receipt = &contracts.PublicRuntimeRoleReceipt{RoleName: name, RoleOID: uint32(100 + n), LayoutDigest: f.input.LayoutDigest}
	}
	if !runtimeRoleStateValid(f.input, original.State, time.Now()) {
		t.Fatal("invalid synthetic completed role fixture")
	}
	f.mu.Lock()
	f.object.Data["state.json"], err = json.Marshal(original.State)
	f.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := f.root.ReadPublicRuntimeRoles(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return f, snapshot
}

func TestPublicRuntimeAllPurposeClaimCompletionKeepsOriginalWorkerProof(t *testing.T) {
	f := newPublicRoleRootFixtureWithWorker(t, false, false, true)
	if _, err := f.root.OpenPublicRuntimeRoles(t.Context()); err != nil {
		t.Fatal(err)
	}
	for n, purpose := range contracts.PublicRuntimeRolePurposes() {
		original, fresh, err := f.root.ClaimPublicRuntimeRole(t.Context(), purpose, 123, time.Now().Add(-time.Hour))
		if err != nil || !fresh {
			t.Fatal("first role claim", purpose, err)
		}
		ordinal, _ := contracts.PublicRuntimeRoleOrdinal(purpose)
		name := "as_" + strings.ReplaceAll(f.input.InstallationID, "-", "") + "_pub_" + string([]byte{'0' + byte(ordinal/10), '0' + byte(ordinal%10)})
		if err = f.root.CompletePublicRuntimeRole(t.Context(), original, purpose, contracts.PublicRuntimeRoleReceipt{RoleName: name, RoleOID: uint32(100 + n), LayoutDigest: f.input.LayoutDigest}); err != nil {
			t.Fatal(purpose, err)
		}
	}
	snapshot, err := f.root.ReadPublicRuntimeRoles(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range snapshot.State.Roles {
		if role.Claim == nil || role.Receipt == nil {
			t.Fatal("missing original completion", role.Purpose)
		}
	}
}

func TestPublicRuntimeProjectionUnknownWriteAndRestartRemainExact(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(strconv.FormatBool(lost), func(t *testing.T) {
			f, snapshot := completedPublicRoleFixture(t)
			f.lostProjection.Store(lost)
			ref, err := f.root.PublishPublicRuntimeProjection(t.Context(), snapshot)
			if err != nil || ref.UID == "" || f.projectionWrites.Load() != 1 {
				t.Fatal("exact projection readback", err)
			}
			current, err := f.root.ReadPublicRuntimeRoles(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			again, err := f.root.PublishPublicRuntimeProjection(t.Context(), current)
			if err != nil || again != ref || f.projectionWrites.Load() != 1 {
				t.Fatal("replay repeated projection create", err)
			}
			f.mu.Lock()
			projection := f.projection.DeepCopy()
			f.mu.Unlock()
			if !*projection.Immutable || len(projection.Data) != len(contracts.PublicRuntimeHubRolePurposes())+2 {
				t.Fatal("incorrect private compartment")
			}
			for _, r := range snapshot.State.Roles {
				if publicRuntimeWorkerPurpose(r.Purpose) {
					if projection.Data["sql-public-"+r.Purpose+".json"] != nil {
						t.Fatal("worker credential leaked")
					}
					continue
				}
				var c contracts.OwnerSQLCredential
				if json.Unmarshal(projection.Data["sql-public-"+r.Purpose+".json"], &c) != nil || c.Username != r.Receipt.RoleName || c.Password != r.Password {
					t.Fatal("projection changed credential")
				}
			}
			manifest, err := contracts.DecodePublicRuntimeCredentialManifest(strings.NewReader(string(projection.Data[contracts.PublicRuntimeCredentialManifestFile])))
			if err != nil || manifest.RootUID != snapshot.UID || manifest.SetupID != snapshot.State.OperationID || len(manifest.Roles) != len(contracts.PublicRuntimeHubRolePurposes()) {
				t.Fatal("projection omitted original role provenance", err)
			}
			f.mu.Lock()
			f.projection = nil
			f.mu.Unlock()
			if _, err = f.root.PublishPublicRuntimeProjection(t.Context(), current); err == nil || f.projectionWrites.Load() != 1 {
				t.Fatal("missing projection was recreated")
			}
		})
	}
}
func TestPublicRuntimeProjectionUnknownClaimCannotCreate(t *testing.T) {
	f, snapshot := completedPublicRoleFixture(t)
	f.lostProjectionClaim.Store(true)
	if _, err := f.root.PublishPublicRuntimeProjection(t.Context(), snapshot); err == nil || f.projectionWrites.Load() != 0 {
		t.Fatal("unknown claim created runtime credentials")
	}
	f.lostProjectionClaim.Store(false)
	current, err := f.root.ReadPublicRuntimeRoles(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.root.PublishPublicRuntimeProjection(t.Context(), current); err == nil || f.projectionWrites.Load() != 0 {
		t.Fatal("unknown claim retried creation")
	}
}
func TestPublicRuntimeProjectionDoesNotUseShortenedOrIncompleteVerification(t *testing.T) {
	f, snapshot := completedPublicRoleFixture(t)
	snapshot.ValidUntil = time.Now().Add(-time.Millisecond)
	if _, err := f.root.PublishPublicRuntimeProjection(t.Context(), snapshot); err == nil || f.projectionWrites.Load() != 0 {
		t.Fatal("expired original verification accepted")
	}
	fresh, err := f.root.ReadPublicRuntimeRoles(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	fresh.State.Roles[0].Receipt = nil
	if _, err = f.root.PublishPublicRuntimeProjection(t.Context(), fresh); err == nil || f.projectionWrites.Load() != 0 {
		t.Fatal("incomplete verification accepted")
	}
}

func TestPublicRoleMACProjectionKeepsAccountCompartmentAndOriginalIdentity(t *testing.T) {
	f := newPublicRoleRootFixture(t, false, false)
	original, e := f.root.OpenPublicRuntimeRoles(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	hub, e := runtimeAuditKeyProjection(original)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(hub)
	capacity, e := runtimeCaptureAccountProjection(original)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(capacity)
	h, e := contracts.DecodePublicAuditKeys(bytes.NewReader(hub))
	if e != nil {
		t.Fatal(e)
	}
	defer clear(h.Material.InputKey)
	defer clear(h.Material.AccountKey)
	c, e := contracts.DecodeCaptureAccountKey(bytes.NewReader(capacity))
	if e != nil {
		t.Fatal(e)
	}
	defer clear(c.Key)
	if c.RootUID != original.UID || c.SetupID != original.State.OperationID || c.Version != h.Material.AccountVersion || !bytes.Equal(c.Key, h.Material.AccountKey) || bytes.Equal(c.Key, h.Material.InputKey) {
		t.Fatal("independent HMAC compartments lost original identity")
	}
	var shape map[string]json.RawMessage
	if json.Unmarshal(capacity, &shape) != nil || len(shape) != 6 || shape["inputKey"] != nil || shape["material"] != nil {
		t.Fatal("capacity received input-key material")
	}
	mutated := original
	mutated.State.MAC.AccountVersion = "replacement"
	if _, e = runtimeCaptureAccountProjection(mutated); e == nil {
		t.Fatal("replacement account version was projected")
	}
}

func TestPublicRoleRootRejectsWrongSecretResponseVersion(t *testing.T) {
	f := newPublicRoleRootFixture(t, false, false)
	if _, e := f.root.OpenPublicRuntimeRoles(t.Context()); e != nil {
		t.Fatal(e)
	}
	before := f.writes.Load()
	f.badSecretVersion.Store(true)
	if _, fresh, e := f.root.ClaimPublicRuntimeRole(t.Context(), "identity-read", 123, time.Now().Add(-time.Hour)); e == nil || fresh || f.writes.Load() != before {
		t.Fatal("invalid returned Secret version allowed a role claim")
	}
}

func TestPublicRoleStateRejectsIncompletePriorInventory(t *testing.T) {
	f, snapshot := completedPublicRoleFixture(t)
	if !runtimeRoleStateValid(f.input, snapshot.State, time.Now()) {
		t.Fatal("positive complete state invalid")
	}
	old := snapshot.State
	old.Roles = slices.DeleteFunc(slices.Clone(old.Roles), func(r contracts.PublicRuntimeRoleMaterial) bool {
		return r.Purpose == "capture-preview" || r.Purpose == "capture-resolution"
	})
	if len(old.Roles) != len(contracts.PublicRuntimeRolePurposes())-2 || runtimeRoleStateValid(f.input, old, time.Now()) {
		t.Fatal("prior inventory silently accepted")
	}
	changed := snapshot.State
	changed.Input.LayoutDigest = strings.Repeat("0", 64)
	if runtimeRoleStateValid(f.input, changed, time.Now()) {
		t.Fatal("foreign layout accepted")
	}
}

// ADR-186: one role operation proves the current state once at its start and
// once before the completing write; inner reads only fetch the journal.
func TestPublicRoleOperationBoundsAPIRequests(t *testing.T) {
	f := newPublicRoleRootFixtureWithWorker(t, false, false, true)
	if _, err := f.root.OpenPublicRuntimeRoles(t.Context()); err != nil {
		t.Fatal(err)
	}
	purpose := contracts.PublicRuntimeRolePurposes()[1]
	ordinal, _ := contracts.PublicRuntimeRoleOrdinal(purpose)
	name := "as_" + strings.ReplaceAll(f.input.InstallationID, "-", "") + "_pub_" + string([]byte{'0' + byte(ordinal/10), '0' + byte(ordinal%10)})
	f.requests.Store(0)
	err := f.root.WithPublicRoleOperation(t.Context(), func(op context.Context) error {
		original, fresh, e := f.root.ClaimPublicRuntimeRole(op, purpose, 123, time.Now().Add(-time.Hour))
		if e != nil || !fresh {
			return errors.Join(e, errors.New("claim"))
		}
		if _, e = f.root.ReadPublicRuntimeRoles(op); e != nil {
			return e
		}
		return f.root.CompletePublicRuntimeRole(op, original, purpose, contracts.PublicRuntimeRoleReceipt{RoleName: name, RoleOID: 101, LayoutDigest: f.input.LayoutDigest})
	})
	// Without the operation the same three steps took 141 requests.
	if err != nil || f.requests.Load() > 60 {
		t.Fatal("role operation exceeded its proof budget", f.requests.Load(), err)
	}
	snapshot, err := f.root.ReadPublicRuntimeRoles(t.Context())
	if err != nil || snapshot.State.Roles[1].Receipt == nil {
		t.Fatal("operation did not complete the role", err)
	}
	// Nested operations are refused; a reused proof is never extended.
	if err = f.root.WithPublicRoleOperation(t.Context(), func(op context.Context) error {
		return f.root.WithPublicRoleOperation(op, func(context.Context) error { return nil })
	}); err == nil {
		t.Fatal("nested role operation accepted")
	}
}

// ADR-186: verification and publication share one role operation; the
// projection starts from the opening proof instead of repeating it.
func TestPublicProjectionInsideRoleOperationBoundsAPIRequests(t *testing.T) {
	f, _ := completedPublicRoleFixture(t)
	f.requests.Store(0)
	var ref contracts.WorkerObjectReference
	err := f.root.WithPublicRoleOperation(t.Context(), func(op context.Context) error {
		verified, e := f.root.ReadPublicRuntimeRoles(op)
		if e == nil {
			ref, e = f.root.PublishPublicRuntimeProjection(op, verified)
		}
		return e
	})
	// Outside an operation the read and publish took 35 + 63 requests; the
	// projection still re-proves at each of its effect boundaries.
	if err != nil || ref.Name != contracts.PublicRuntimeProjectionName(f.input.InstallationID) || f.requests.Load() > 80 {
		t.Fatal("projection inside role operation", f.requests.Load(), err)
	}
}

// ADR-193: the federation projection has its own one-use claim beside the
// hub-api projection and carries exactly the six federation logins plus the
// audit keys bound to the permission root.
func TestFederationRuntimeProjectionIsSeparateAndExact(t *testing.T) {
	f, snapshot := completedPublicRoleFixture(t)
	root := ownerID(4242)
	ref, err := f.root.PublishFederationRuntimeProjection(t.Context(), snapshot, root)
	if err != nil || ref.UID != ownerID(12) || f.projectionWrites.Load() != 0 {
		t.Fatal("federation projection", err)
	}
	current, err := f.root.ReadPublicRuntimeRoles(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	c := current.State.FederationProjection
	if c == nil || c.SecretUID != ref.UID || current.State.Projection != nil {
		t.Fatal("claim not recorded in its own slot", c)
	}
	if again, err := f.root.PublishFederationRuntimeProjection(t.Context(), current, root); err != nil || again != ref {
		t.Fatal("replay was not lookup-only", err)
	}
	f.mu.Lock()
	data := f.federation.DeepCopy().Data
	f.mu.Unlock()
	if len(data) != len(contracts.PublicRuntimeFederationPurposes())+1 {
		t.Fatal("unexpected federation projection files", len(data))
	}
	for _, purpose := range contracts.PublicRuntimeFederationPurposes() {
		if data["sql-federation-"+purpose+".json"] == nil {
			t.Fatal("missing login", purpose)
		}
	}
	keys, err := contracts.DecodeFederationAuditKeys(strings.NewReader(string(data[contracts.FederationAuditKeysFile])))
	if err != nil || keys.RootID != root || keys.AccountVersion != snapshot.State.MAC.AccountVersion || keys.InstallationID != f.input.InstallationID {
		t.Fatal("audit keys not bound to the permission root", err)
	}
	// The hub-api projection still claims and creates independently.
	if current, err = f.root.ReadPublicRuntimeRoles(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err = f.root.PublishPublicRuntimeProjection(t.Context(), current); err != nil || f.projectionWrites.Load() != 1 {
		t.Fatal("hub projection after federation", err)
	}
}

func TestPublisherRuntimeProjectionIsSeparateAndExact(t *testing.T) {
	f, snapshot := completedPublicRoleFixture(t)
	ref, err := f.root.PublishPublisherRuntimeProjection(t.Context(), snapshot)
	if err != nil || ref.UID != ownerID(13) || f.projectionWrites.Load() != 0 {
		t.Fatal("publisher projection", err)
	}
	current, err := f.root.ReadPublicRuntimeRoles(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if c := current.State.PublisherProjection; c == nil || c.SecretUID != ref.UID || current.State.Projection != nil || current.State.FederationProjection != nil {
		t.Fatal("claim not recorded in its own slot", c)
	}
	if again, err := f.root.PublishPublisherRuntimeProjection(t.Context(), current); err != nil || again != ref {
		t.Fatal("replay was not lookup-only", err)
	}
	f.mu.Lock()
	data := f.publisher.DeepCopy().Data
	f.mu.Unlock()
	purposes := contracts.PublicRuntimePublisherPurposes()
	if len(data) != len(purposes)+1 {
		t.Fatal("unexpected publisher projection files", len(data))
	}
	for _, purpose := range purposes {
		if data["sql-public-"+purpose+".json"] == nil {
			t.Fatal("missing login", purpose)
		}
	}
	var m contracts.PublicRuntimeCredentialManifest
	if json.Unmarshal(data[contracts.PublisherCredentialManifestFile], &m) != nil || len(m.Roles) != len(purposes) || m.RootUID != snapshot.UID {
		t.Fatal("manifest", m)
	}
	for i, r := range m.Roles {
		if r.Purpose != purposes[i] {
			t.Fatal("manifest order", i, r.Purpose)
		}
	}
}
