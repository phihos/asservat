package kubernetes

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	admission "k8s.io/api/admissionregistration/v1"
	apps "k8s.io/api/apps/v1"
	auth "k8s.io/api/authentication/v1"
	access "k8s.io/api/authorization/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
)

// Full selected reader over actual loopback TLS. All API enforcement replies,
// original receipts and token identity remain explicitly synthetic; no SQL or
// external storage authority is inferred from this component regression.
func TestProviderOwnerAuditReadRequiresCurrentOriginalMaterial(t *testing.T) {
	for _, mode := range []string{"valid", "rotated-current", "stale-mount", "replaced-secret", "wrong-secret-kind", "wrong-secret-version", "extra-key", "placeholder", "missing-receipt", "guard-lost", "allowing-probe", "wrong-token-pod", "token-revoked", "late-secret", "cancelled", "sdk-budget", "final-pod-changed", "final-pod-read"} {
		t.Run(mode, func(t *testing.T) {
			x := providerOwnerObjectFixture(t)
			in := x.reader.input
			a := x.reader.activation
			// Keep the input's complete guard declaration equal to the actual
			// original generated guard used by the fixture.
			in.APIContextStarts = nil
			if p := x.plan.APIContextStarts; p != nil {
				in.APIContextStarts = &contracts.OwnerDeploymentAPIContextStarts{CapacityAccount: contracts.WorkerObjectReference{Name: p.CapacityAccount, UID: p.CapacityAccountUID}, ExecutionAccount: contracts.WorkerObjectReference{Name: p.ExecutionAccount, UID: p.ExecutionAccountUID}}
			}
			// Model exactly the four scalar defaults established by the native
			// inert-object roundtrip. This is synthetic API data; generated
			// object receipts keep their original pre-API template digest.
			x.deployment.Spec.Template.Spec.DNSPolicy = core.DNSClusterFirst
			x.deployment.Spec.Template.Spec.SchedulerName = core.DefaultSchedulerName
			x.deployment.Spec.Template.Spec.Containers[0].TerminationMessagePath = core.TerminationMessagePathDefault
			x.deployment.Spec.Template.Spec.Containers[0].TerminationMessagePolicy = core.TerminationMessageReadFile
			var e error
			x.state.OwnerLaunch.RunningDigest, e = ownerIdentitySpecDigest(*x.deployment)
			if e != nil {
				t.Fatal(e)
			}
			inert := x.deployment.DeepCopy()
			inert.Spec.Replicas = ptr.To(int32(0))
			x.state.OwnerLaunch.InertDigest, e = ownerIdentitySpecDigest(*inert)
			if e != nil {
				t.Fatal(e)
			}
			credential, e := json.Marshal(contracts.OwnerStorageCredential{AccessKeyID: "synthetic-original", SecretAccessKey: "synthetic-original"})
			if e != nil {
				t.Fatal(e)
			}
			mounted := append([]byte(nil), credential...)
			if mode == "stale-mount" {
				credential, e = json.Marshal(contracts.OwnerStorageCredential{AccessKeyID: "synthetic-rotated", SecretAccessKey: "synthetic-rotated"})
				if e != nil {
					t.Fatal(e)
				}
			}
			selected := in.ProviderAuthentication.AuditCredentials
			secret := core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: selected.Name, Namespace: in.Namespace.Name, UID: types.UID(selected.UID), ResourceVersion: "2"}, Type: core.SecretTypeOpaque, Data: map[string][]byte{contracts.OwnerProviderAuditCredentialFile: credential}}
			switch mode {
			case "replaced-secret":
				secret.UID = types.UID(ownerID(14997))
			case "wrong-secret-kind":
				secret.Kind = "ConfigMap"
			case "wrong-secret-version":
				secret.APIVersion = "future/v1"
			case "extra-key":
				secret.Data["different-purpose"] = []byte("synthetic")
			case "placeholder":
				secret.Data = map[string][]byte{}
			case "missing-receipt":
				x.state.OwnerIdentity.Receipt = nil
			}
			var storageReads atomic.Int32
			var currentSecret atomic.Pointer[core.Secret]
			currentSecret.Store(secret.DeepCopy())
			policy, binding, e := OwnerWorkloadAdmission(x.plan)
			if e != nil {
				t.Fatal(e)
			}
			g := in.WorkloadGuard
			policy.UID = types.UID(g.PolicyUID)
			policy.ResourceVersion = "1"
			policy.Generation = g.PolicyGeneration
			policy.Status.ObservedGeneration = g.PolicyGeneration
			policy.Status.TypeChecking = &admission.TypeChecking{}
			binding.UID = types.UID(g.BindingUID)
			binding.ResourceVersion = g.BindingResourceVersion
			ns := core.Namespace{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: in.Namespace.Name, UID: types.UID(in.Namespace.UID), ResourceVersion: "1"}}
			rs := apps.ReplicaSet{TypeMeta: meta.TypeMeta{APIVersion: "apps/v1", Kind: "ReplicaSet"}, ObjectMeta: meta.ObjectMeta{Name: "owner-replica", Namespace: in.Namespace.Name, UID: types.UID(ownerID(3500)), ResourceVersion: "1", OwnerReferences: []meta.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: a.Input.Deployment.Name, UID: types.UID(a.Input.Deployment.UID), Controller: ptr.To(true)}}}, Spec: apps.ReplicaSetSpec{Replicas: ptr.To(int32(1)), Selector: x.deployment.Spec.Selector.DeepCopy(), Template: *x.deployment.Spec.Template.DeepCopy()}}
			pod := core.Pod{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Pod"}, ObjectMeta: meta.ObjectMeta{Name: "owner-pod", Namespace: in.Namespace.Name, UID: types.UID(x.reader.podUID), ResourceVersion: "1", Labels: rs.Spec.Template.Labels, OwnerReferences: []meta.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: ptr.To(true)}}}, Spec: *rs.Spec.Template.Spec.DeepCopy(), Status: core.PodStatus{Phase: core.PodRunning}}
			pod.Spec.NodeName = "synthetic-node"
			start := time.Now().UTC()
			var offset atomic.Int64
			x.reader.client.now = func() time.Time { return time.Now().UTC().Add(time.Duration(offset.Load())) }
			payload, _ := json.Marshal(map[string]int64{"iat": start.Add(-time.Second).Unix(), "exp": start.Add(5 * time.Minute).Unix()})
			token := []byte("e30." + base64.RawURLEncoding.EncodeToString(payload) + ".synthetic-signature")
			var reviews atomic.Int32
			deploymentPath := "/apis/apps/v1/namespaces/" + in.Namespace.Name + "/deployments/" + a.Input.Deployment.Name
			x.extra = func(w http.ResponseWriter, r *http.Request) bool {
				switch r.URL.Path {
				case "/api/v1/namespaces/" + in.Namespace.Name + "/secrets/" + secret.Name:
					if r.Method != http.MethodGet {
						t.Error("provider material reader attempted mutation")
						http.Error(w, "read only", 403)
						break
					}
					storageReads.Add(1)
					if mode == "late-secret" {
						offset.Store(int64(6 * time.Second))
					}
					permissionReply(w, currentSecret.Load())
				case "/api/v1/namespaces/" + in.Namespace.Name:
					permissionReply(w, ns)
				case "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/" + g.Name:
					if mode == "guard-lost" && storageReads.Load() > 0 {
						http.NotFound(w, r)
					} else {
						permissionReply(w, policy)
					}
				case "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings/" + g.Name:
					permissionReply(w, binding)
				case "/apis/authentication.k8s.io/v1/selfsubjectreviews":
					permissionReply(w, auth.SelfSubjectReview{Status: auth.SelfSubjectReviewStatus{UserInfo: auth.UserInfo{Username: "synthetic-probe", Groups: []string{"system:authenticated"}}}})
				case "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews":
					permissionReply(w, access.SelfSubjectAccessReview{Status: access.SubjectAccessReviewStatus{Allowed: true}})
				case deploymentPath:
					if r.Method != http.MethodPut {
						return false
					}
					if r.URL.Query().Get("dryRun") != "All" {
						t.Error("persistent guard probe attempted")
					}
					if mode == "allowing-probe" && storageReads.Load() > 0 {
						permissionReply(w, x.deployment)
						break
					}
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(403)
					permissionReply(w, meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: meta.StatusFailure, Reason: meta.StatusReasonForbidden, Code: 403, Details: &meta.StatusDetails{Group: "apps", Kind: "deployments", Causes: []meta.StatusCause{{Message: "ValidatingAdmissionPolicy '" + g.Name + "' with binding '" + g.Name + "' denied request: " + ownerWorkloadDenial}}}})
				case "/apis/authentication.k8s.io/v1/tokenreviews":
					n := reviews.Add(1)
					var request auth.TokenReview
					if json.NewDecoder(r.Body).Decode(&request) != nil || request.Spec.Token != string(token) || len(request.Spec.Audiences) != 1 || request.Spec.Audiences[0] != OwnerEnrollmentAudience(in.InstallationID) {
						t.Error("wrong original token or audience")
					}
					reply := auth.TokenReview{TypeMeta: meta.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "TokenReview"}, Status: auth.TokenReviewStatus{Authenticated: true, Audiences: request.Spec.Audiences, User: auth.UserInfo{Username: "system:serviceaccount:" + in.Namespace.Name + ":" + a.Input.ServiceAccount.Name, UID: a.Input.ServiceAccount.UID, Extra: map[string]auth.ExtraValue{"authentication.kubernetes.io/pod-name": {pod.Name}, "authentication.kubernetes.io/pod-uid": {string(pod.UID)}}}}}
					if mode == "wrong-token-pod" {
						reply.Status.User.Extra["authentication.kubernetes.io/pod-uid"] = auth.ExtraValue{ownerID(3501)}
					}
					if mode == "token-revoked" && n == 2 {
						reply.Status.Authenticated = false
					}
					permissionReply(w, reply)
				case "/api/v1/namespaces/" + in.Namespace.Name + "/pods/" + pod.Name:
					if reviews.Load() == 2 {
						if mode == "final-pod-read" {
							http.Error(w, "synthetic unavailable", 503)
							break
						}
						if mode == "final-pod-changed" {
							changed := pod.DeepCopy()
							changed.Spec.Containers[0].Image = "different-synthetic-image"
							permissionReply(w, changed)
							break
						}
					}
					permissionReply(w, pod)
				case "/apis/apps/v1/namespaces/" + in.Namespace.Name + "/replicasets/" + rs.Name:
					permissionReply(w, rs)
				default:
					return false
				}
				return true
			}
			probe, e := NewPermissionClient(x.apiConfig, in.ClusterID, x.reader.client.control, x.reader.client.now)
			if e != nil {
				t.Fatal(e)
			}
			guard, e := NewOwnerWorkloadProtection(x.reader.client, probe, x.plan, GuardPin{PolicyUID: g.PolicyUID, PolicyGeneration: g.PolicyGeneration, BindingUID: g.BindingUID, BindingResourceVersion: g.BindingResourceVersion})
			if e != nil {
				t.Fatal("fixture guard construction", e)
			}
			in.Observation.ProtectionDigest = hex.EncodeToString(guard.digest[:])
			template, e := ConnectorAPITemplateDigest(x.deployment.Spec.Template)
			if e != nil {
				t.Fatal(e)
			}
			in.Observation.TemplateDigest = hex.EncodeToString(template[:])
			in.Observation.ImageDigest = strings.Split(x.deployment.Spec.Template.Spec.Containers[0].Image, "@sha256:")[1]
			x.reader.input = in
			encoded, e := json.Marshal(in)
			if e != nil {
				t.Fatal(e)
			}
			x.config.Data["deployment.json"] = string(encoded)
			x.state.OwnerIdentity.PublicDigest, e = ownerIdentityPublicDigest(in, x.manifest)
			if e != nil {
				t.Fatal(e)
			}
			x.writeJournal(t)
			originalJournal := string(x.journal.Data["state.json"])
			reader, e := NewInstalledOwnerIdentityReader(x.reader.client, guard, in, a, ownerTokenFunc(func(context.Context) ([]byte, error) { return append([]byte(nil), token...), nil }), x.reader.podUID)
			if e != nil {
				t.Fatal(e)
			}
			if mode == "sdk-budget" {
				exerciseProviderCredentialAuditBudget(t, reader, x, mounted)
				return
			}
			verifyStart := time.Now()
			ctx, end := context.WithDeadline(context.Background(), verifyStart.Add(5*time.Second))
			defer end()
			if mode == "cancelled" {
				end()
			}
			out, until, e := reader.ReadProviderAuditCredential(ctx, x.manifest, x.mounted, mounted)
			if mode == "valid" || mode == "rotated-current" {
				if e != nil || !until.After(time.Now()) || until.After(verifyStart.Add(5*time.Second)) {
					t.Fatal("current original material/Pod/guard unavailable", e)
				}
				if out.AccessKeyID == "" || storageReads.Load() != 1 {
					t.Fatal("current material not read exactly once")
				}
			} else if e == nil {
				t.Fatal("unavailable/replaced/revoked proof accepted")
			}
			if mode == "rotated-current" {
				// Rotate only content on the same protected original Secret.
				// An old projection is denied, then the newly mounted bytes
				// succeed on a separately initiated current observation.
				rotatedBytes, err := json.Marshal(contracts.OwnerStorageCredential{AccessKeyID: "synthetic-rotated", SecretAccessKey: "synthetic-rotated"})
				if err != nil {
					t.Fatal(err)
				}
				rotated := secret.DeepCopy()
				rotated.ResourceVersion = "3"
				rotated.Data[contracts.OwnerProviderAuditCredentialFile] = rotatedBytes
				currentSecret.Store(rotated)
				staleCall, stopStale := context.WithTimeout(context.Background(), 5*time.Second)
				stale, staleUntil, err := reader.ReadProviderAuditCredential(staleCall, x.manifest, x.mounted, mounted)
				stopStale()
				if err == nil || stale != (contracts.OwnerStorageCredential{}) || !staleUntil.IsZero() {
					t.Fatal("old mount remained usable after original Secret rotation")
				}
				freshStart := time.Now()
				freshCall, stopFresh := context.WithDeadline(context.Background(), freshStart.Add(5*time.Second))
				fresh, freshUntil, err := reader.ReadProviderAuditCredential(freshCall, x.manifest, x.mounted, rotatedBytes)
				stopFresh()
				if err != nil || fresh.AccessKeyID != "synthetic-rotated" || !freshUntil.After(time.Now()) || freshUntil.After(freshStart.Add(5*time.Second)) || storageReads.Load() != 3 {
					t.Fatal("same original Secret could not rotate current mounted credentials", err)
				}
			}
			if mode == "final-pod-changed" || mode == "final-pod-read" {
				want := "identity/final-pod-changed"
				if mode == "final-pod-read" {
					want = "identity/final-pod/live-pod-read"
				}
				var named interface{ FixedStep() string }
				if !errors.As(e, &named) || named.FixedStep() != want {
					t.Fatal("indistinguishable Pod failure", e)
				}
			}
			if string(x.journal.Data["state.json"]) != originalJournal {
				t.Fatal("credential observation mutated original journal")
			}
			if mode == "missing-receipt" && storageReads.Load() != 0 {
				t.Fatal("provider secret read before positive original receipt")
			}
			if e != nil && (out != (contracts.OwnerStorageCredential{}) || !until.IsZero()) {
				t.Fatal("failed proof disclosed a credential or fresh interval")
			}
			if e != nil && strings.Contains(e.Error(), string(token)) {
				t.Fatal("token leaked")
			}
		})
	}
}
