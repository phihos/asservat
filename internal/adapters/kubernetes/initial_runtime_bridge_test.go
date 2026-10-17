package kubernetes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	admission "k8s.io/api/admissionregistration/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

func bridgeStateFixture(t *testing.T) (*InitialRuntimeBridge, contracts.InitialRuntimeBridgeState) {
	t.Helper()
	plan := initialRuntimeBridgeFixture()
	old, _, err := InitialWorkloadAdmission(plan.Initial)
	if err != nil {
		t.Fatal(err)
	}
	probe, _, err := InitialRuntimeProbeAdmission(plan)
	if err != nil {
		t.Fatal(err)
	}
	retained, _, err := InitialRuntimeRetainedAdmission(plan)
	if err != nil {
		t.Fatal(err)
	}
	s := &InitialRuntimeBridge{binding: strings.Repeat("a", 64), administration: plan, initial: contracts.InitialInstaller{WorkloadGuard: contracts.OwnerDeploymentGuard{Name: plan.Initial.Name}}}
	for i, p := range []*admission.ValidatingAdmissionPolicy{old, probe, retained} {
		normalizePermissionPolicy(&p.Spec)
		s.policies[i] = p
		s.guards[i] = &configMapProtection{pin: GuardPin{PolicyUID: ownerID(301), PolicyGeneration: int64(1 + i)}}
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	v := contracts.InitialRuntimeBridgeState{Format: contracts.InitialRuntimeBridgeStateFormat, BindingDigest: s.binding, SetupID: ownerID(302), CreatedAt: now.Add(-time.Minute), Until: now.Add(29 * time.Minute)}
	v.Probe = &contracts.InitialRuntimeBridgeTransition{OperationID: ownerID(303), FromResourceVersion: "10", FromGeneration: 1, ClaimedAt: now.Add(-30 * time.Second), Until: now.Add(-25 * time.Second), Receipt: &contracts.InitialRuntimeBridgeReceipt{PolicyUID: ownerID(301), ResourceVersion: "11", Generation: 2, SpecDigest: initialRuntimeBridgeSpecDigest(probe)}}
	v.Retained = &contracts.InitialRuntimeBridgeTransition{OperationID: ownerID(304), FromResourceVersion: "12", FromGeneration: 2, ClaimedAt: now.Add(-10 * time.Second), Until: now.Add(-5 * time.Second), Receipt: &contracts.InitialRuntimeBridgeReceipt{PolicyUID: ownerID(301), ResourceVersion: "13", Generation: 3, SpecDigest: initialRuntimeBridgeSpecDigest(retained)}}
	return s, v
}
func TestInitialRuntimeBridgeOriginalClaimsAndFiniteReceipts(t *testing.T) {
	s, v := bridgeStateFixture(t)
	now := time.Now()
	if !s.validState(v, now) {
		t.Fatal("historical exact result rejected solely because original effect interval ended")
	}
	for name, change := range map[string]func(*contracts.InitialRuntimeBridgeState){
		"new binding":                   func(v *contracts.InitialRuntimeBridgeState) { v.BindingDigest = strings.Repeat("b", 64) },
		"renewed setup":                 func(v *contracts.InitialRuntimeBridgeState) { v.Until = v.Until.Add(time.Microsecond) },
		"unacknowledged predecessor":    func(v *contracts.InitialRuntimeBridgeState) { v.Probe.Receipt = nil },
		"missing predecessor":           func(v *contracts.InitialRuntimeBridgeState) { v.Probe = nil },
		"operation reuse":               func(v *contracts.InitialRuntimeBridgeState) { v.Retained.OperationID = v.Probe.OperationID },
		"six-second permit":             func(v *contracts.InitialRuntimeBridgeState) { v.Probe.Until = v.Probe.ClaimedAt.Add(6 * time.Second) },
		"future claim":                  func(v *contracts.InitialRuntimeBridgeState) { v.Retained.ClaimedAt = now.Add(time.Second) },
		"different original generation": func(v *contracts.InitialRuntimeBridgeState) { v.Probe.FromGeneration++ },
		"receipt before update": func(v *contracts.InitialRuntimeBridgeState) {
			v.Probe.Receipt.ResourceVersion = v.Probe.FromResourceVersion
		},
		"different receipt UID": func(v *contracts.InitialRuntimeBridgeState) { v.Retained.Receipt.PolicyUID = ownerID(999) },
		"retained digest substituted": func(v *contracts.InitialRuntimeBridgeState) {
			v.Retained.Receipt.SpecDigest = v.Probe.Receipt.SpecDigest
		},
	} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(v)
			var copy contracts.InitialRuntimeBridgeState
			_ = json.Unmarshal(raw, &copy)
			change(&copy)
			if s.validState(copy, now) {
				t.Fatal("accepted changed original claim/result")
			}
		})
	}
}

// Actual HTTP reads qualify the phase decoder only; this synthetic transport
// does not pretend to establish current SQL or Kubernetes enforcement.
func TestInitialRuntimeBridgeCannotSelectPolicyFromUnacknowledgedState(t *testing.T) {
	for _, mode := range []string{"exact-probe-pending", "exact-retained-pending", "unclaimed-probe", "unclaimed-retained", "old-after-receipt", "wrong-operation", "replaced-policy", "changed-shape", "extra-generation", "expired-read"} {
		t.Run(mode, func(t *testing.T) {
			s, state := bridgeStateFixture(t)
			phase := 1
			state.Retained = nil
			state.Probe.Receipt = nil
			if mode == "exact-retained-pending" || mode == "unclaimed-retained" {
				s, state = bridgeStateFixture(t)
				phase = 2
				state.Retained.Receipt = nil
			}
			policy := s.policies[phase].DeepCopy()
			policy.TypeMeta = meta.TypeMeta{APIVersion: "admissionregistration.k8s.io/v1", Kind: "ValidatingAdmissionPolicy"}
			policy.UID = types.UID(ownerID(301))
			policy.Generation = int64(1 + phase)
			policy.ResourceVersion = "20"
			operation := state.Probe.OperationID
			if phase == 2 {
				operation = state.Retained.OperationID
			}
			policy.Annotations = map[string]string{initialRuntimeBridgeMarker: operation}
			switch mode {
			case "unclaimed-probe":
				state.Probe = nil
			case "unclaimed-retained":
				state.Retained = nil
			case "old-after-receipt":
				_, state = bridgeStateFixture(t)
				phase = 0
				policy.Spec = *s.policies[0].Spec.DeepCopy()
				policy.Generation = 1
				policy.Annotations = nil
			case "wrong-operation":
				policy.Annotations[initialRuntimeBridgeMarker] = ownerID(998)
			case "replaced-policy":
				policy.UID = types.UID(ownerID(999))
			case "changed-shape":
				policy.Spec.Validations[0].Expression = "true"
			case "extra-generation":
				policy.Generation++
			}
			release := make(chan struct{})
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Error("passive phase check wrote an object")
					http.Error(w, "method", 405)
					return
				}
				if mode == "expired-read" {
					<-release
				}
				permissionReply(w, policy)
			}))
			defer server.Close()
			defer close(release)
			conf := &rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
			client, err := NewPermissionClient(conf, permissionCluster, s.administration.Initial.ControlNamespace, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			s.source = &ConfigurationRoleSource{client: client}
			s.preparer = &InitialPreparer{creator: &InitialNamespaceCreator{api: client.api}}
			limit := time.Second
			if mode == "expired-read" {
				limit = 30 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), limit)
			defer cancel()
			_, got, err := s.phasePolicy(ctx, state)
			pass := mode == "exact-probe-pending" || mode == "exact-retained-pending"
			if pass && (err != nil || got != phase) {
				t.Fatal("exact pending result", got, err)
			}
			if !pass && err == nil {
				t.Fatal("accepted absent/contrary claim or expired original read")
			}
		})
	}
}
func TestInitialRuntimeBridgeCanonicalDigestHasNoPolicyStatusAuthority(t *testing.T) {
	s, _ := bridgeStateFixture(t)
	p := s.policies[1].DeepCopy()
	want := initialRuntimeBridgeSpecDigest(p)
	p.ResourceVersion = "new-status"
	p.Status.ObservedGeneration = 999
	if initialRuntimeBridgeSpecDigest(p) != want {
		t.Fatal("status changed canonical policy identity")
	}
	p.Spec.Validations[0].Expression = "true"
	if initialRuntimeBridgeSpecDigest(p) == want {
		t.Fatal("changed enforcement kept canonical policy identity")
	}
	raw, _ := json.Marshal(s.policies[1].Spec)
	d := sha256.Sum256(raw)
	if want != hex.EncodeToString(d[:]) {
		t.Fatal("policy digest not exact canonical spec")
	}
}
