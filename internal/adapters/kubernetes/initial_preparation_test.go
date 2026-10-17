package kubernetes

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	admission "k8s.io/api/admissionregistration/v1"
	auth "k8s.io/api/authentication/v1"
	authz "k8s.io/api/authorization/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

func TestInitialPreparationJournalNeverReissuesAnUncertainCreate(t *testing.T) {
	for _, mode := range []string{"valid", "lost-update-reply", "expired-after-update", "guard-lost-after-update", "wrong-admin", "journal-replaced", "concurrent", "malformed-chain", "resource-valid", "resource-lost-reply", "resource-missing", "resource-mutated", "resource-replaced", "resource-stripped"} {
		t.Run(mode, func(t *testing.T) {
			plan := cfg.InitialNamespaceAdministration{Name: "stage", Namespace: "install", ProbeSource: "preparation", Inputs: "inputs", Administrators: []cfg.KubernetesActor{{Kind: "User", Name: "operator"}}}
			policy, binding, err := InitialNamespaceAdmission(plan)
			if err != nil {
				t.Fatal(err)
			}
			policy.UID, policy.Generation, policy.ResourceVersion = types.UID(ownerID(3)), 1, "1"
			policy.Status.ObservedGeneration, policy.Status.TypeChecking = 1, &admission.TypeChecking{}
			binding.UID, binding.ResourceVersion = types.UID(ownerID(4)), "2"
			refs := InitialNamespaceResources{Namespace: cfg.NamespaceRef{Name: plan.Namespace, UID: ownerID(5)}, Guard: GuardPin{PolicyUID: ownerID(3), PolicyGeneration: 1, BindingUID: ownerID(4), BindingResourceVersion: "2"}}
			var mu sync.Mutex
			var cm core.ConfigMap
			var account core.ServiceAccount
			creates := 0
			updates := 0
			fault := true
			clock := func() time.Time {
				mu.Lock()
				defer mu.Unlock()
				now := time.Now()
				if fault && mode == "expired-after-update" && updates > 0 {
					return now.Add(6 * time.Second)
				}
				return now
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(out http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				status := func(code int, reason meta.StatusReason, cause string) {
					out.Header().Set("Content-Type", "application/json")
					out.WriteHeader(code)
					permissionReply(out, meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: meta.StatusFailure, Reason: reason, Code: int32(code), Details: &meta.StatusDetails{Kind: "configmaps", Causes: []meta.StatusCause{{Message: cause}}}})
				}
				switch r.URL.Path {
				case "/apis/authentication.k8s.io/v1/selfsubjectreviews":
					who := auth.SelfSubjectReview{}
					who.Status.UserInfo = auth.UserInfo{Username: "operator", Groups: []string{"system:authenticated"}}
					if r.Header.Get("Authorization") == "Bearer probe" || fault && mode == "wrong-admin" {
						who.Status.UserInfo.Username = "probe"
					}
					permissionReply(out, who)
				case "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews":
					a := authz.SelfSubjectAccessReview{}
					a.Status.Allowed = true
					permissionReply(out, a)
				case "/api/v1/namespaces/install/serviceaccounts", "/api/v1/namespaces/install/serviceaccounts/writer":
					if r.Method == http.MethodPost {
						creates++
						if json.NewDecoder(r.Body).Decode(&account) != nil {
							t.Error("invalid account create")
						}
						account.UID, account.ResourceVersion = types.UID(ownerID(21)), "100"
						if mode == "resource-mutated" {
							*account.AutomountServiceAccountToken = true
						}
						if mode == "resource-stripped" {
							account.AutomountServiceAccountToken = nil
						}
						if mode == "resource-missing" {
							account = core.ServiceAccount{}
						}
						if mode == "resource-lost-reply" || mode == "resource-missing" {
							status(500, meta.StatusReasonInternalError, "")
							return
						}
					}
					if account.UID == "" {
						status(404, meta.StatusReasonNotFound, "")
						return
					}
					permissionReply(out, account)
				case "/api/v1/namespaces/install":
					permissionReply(out, core.Namespace{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "install", UID: types.UID(refs.Namespace.UID), ResourceVersion: "1"}})
				case "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/stage":
					permissionReply(out, policy)
				case "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings/stage":
					if fault && mode == "guard-lost-after-update" && updates > 0 {
						status(404, meta.StatusReasonNotFound, "")
						return
					}
					permissionReply(out, binding)
				case "/api/v1/namespaces/install/configmaps/preparation":
					if r.Method == http.MethodPut {
						if r.URL.Query().Get("dryRun") == "All" {
							status(403, meta.StatusReasonForbidden, "ValidatingAdmissionPolicy 'stage' with binding 'stage' denied request: "+initialNamespaceDenial)
							return
						}
						var update core.ConfigMap
						if r.Header.Get("Authorization") != "Bearer operator" || r.URL.Query().Get("fieldValidation") != "Strict" || json.NewDecoder(r.Body).Decode(&update) != nil {
							t.Error("unexpected journal write")
						}
						if update.ResourceVersion != cm.ResourceVersion || update.UID != cm.UID {
							status(409, meta.StatusReasonConflict, "")
							return
						}
						updates++
						cm = update
						cm.ResourceVersion = strconv.Itoa(updates + 1)
						if fault && mode == "lost-update-reply" {
							status(500, meta.StatusReasonInternalError, "")
							return
						}
					}
					response := cm.DeepCopy()
					if fault && mode == "journal-replaced" {
						response.UID = types.UID(ownerID(20))
					}
					permissionReply(out, response)
				default:
					t.Error("unexpected request", r.Method, r.URL.Path)
					http.NotFound(out, r)
				}
			}))
			defer server.Close()
			ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			kc := &rest.Config{Host: server.URL, BearerToken: "operator", TLSClientConfig: rest.TLSClientConfig{CAData: ca}}
			creator, err := NewInitialNamespaceCreator(kc, plan, ownerID(1), ownerID(2))
			if err != nil {
				t.Fatal(err)
			}
			client := func(token string) *PermissionClient {
				c := rest.CopyConfig(kc)
				c.BearerToken = token
				v, err := NewPermissionClient(c, ownerID(6), refs.Namespace, clock)
				if err != nil {
					t.Fatal(err)
				}
				return v
			}
			guard, err := NewInitialNamespaceProtection(client("operator"), client("probe"), plan, refs.Namespace.UID, refs.Guard)
			if err != nil {
				t.Fatal(err)
			}
			digest := artifact.Digest{1}
			if strings.HasPrefix(mode, "resource-") {
				digest, err = InitialPreparationWorkloadDigest(initialWorkloadPlan())
				if err != nil {
					t.Fatal(err)
				}
			}
			initial := creator.preparation(refs, digest)
			first := contracts.InitialPreparationCreate{OperationID: ownerID(10), Kind: "ServiceAccount", Name: "writer", SpecDigest: hex.EncodeToString(digest[:])}
			if mode == "malformed-chain" {
				initial.Creates = []contracts.InitialPreparationCreate{first, first}
			}
			b, _ := json.Marshal(initial)
			cm = core.ConfigMap{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}, ObjectMeta: meta.ObjectMeta{Name: plan.ProbeSource, Namespace: plan.Namespace, UID: types.UID(ownerID(7)), ResourceVersion: "1"}, Data: map[string]string{"preparation.json": string(b)}}
			creator.stamp(&cm.ObjectMeta)
			journal, err := NewInitialPreparationJournal(creator, guard, refs, contracts.WorkerObjectReference{Name: cm.Name, UID: string(cm.UID)}, digest)
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			if strings.HasPrefix(mode, "resource-") {
				producer, err := NewInitialPreparationResources(journal, initialWorkloadPlan())
				if err != nil {
					t.Fatal(err)
				}
				ref, err := producer.Ensure(ctx, "ServiceAccount", "writer")
				good := mode == "resource-valid" || mode == "resource-lost-reply" || mode == "resource-replaced"
				if (err == nil) != good || good && ref.UID != ownerID(21) {
					t.Fatal("unexpected exact resource creation", ref, err)
				}
				mu.Lock()
				if mode == "resource-replaced" {
					account.UID = types.UID(ownerID(22))
				}
				mu.Unlock()
				replayed, err := producer.Ensure(ctx, "ServiceAccount", "writer")
				if (err == nil) != (good && mode != "resource-replaced") || err == nil && replayed != ref {
					t.Fatal("resource identity changed on replay", replayed, err)
				}
				if _, err := producer.Ensure(ctx, "Pod", "installer"); err == nil {
					t.Fatal("account/RBAC producer accepted a Pod")
				}
				mu.Lock()
				count := creates
				mu.Unlock()
				if count != 1 {
					t.Fatal("uncertain or existing account was recreated", count)
				}
				return
			}
			if mode == "concurrent" {
				results := make(chan InitialPreparationStart, 2)
				for range 2 {
					go func() { v, _ := journal.Begin(ctx, first); results <- v }()
				}
				fresh := 0
				for range 2 {
					if (<-results).Fresh {
						fresh++
					}
				}
				if fresh != 1 {
					t.Fatal("concurrent begin did not retain one attempt", fresh)
				}
			} else {
				v, err := journal.Begin(ctx, first)
				if (err == nil) != (mode == "valid") || v.Fresh != (mode == "valid") {
					t.Fatal("unexpected fresh admission", v, err)
				}
			}
			mu.Lock()
			count := updates
			fault = false
			mu.Unlock()
			if mode == "wrong-admin" || mode == "journal-replaced" || mode == "malformed-chain" {
				if count != 0 {
					t.Fatal("mutated unavailable journal", count)
				}
				return
			}
			if count != 1 {
				t.Fatal("write retry or duplicate create reservation", count)
			}
			if v, err := journal.Begin(ctx, first); err != nil || v.Fresh {
				t.Fatal("replay must remain lookup-only", err)
			}
			next := first
			next.OperationID, next.Name = ownerID(11), "next"
			if _, err := journal.Begin(ctx, next); err == nil {
				t.Fatal("pending create was skipped")
			}
			receipt := contracts.InitialPreparationReceipt{UID: ownerID(12), ResourceVersion: "10"}
			if err := journal.Observe(ctx, first.OperationID, receipt); err != nil {
				t.Fatal(err)
			}
			if err := journal.Observe(ctx, first.OperationID, receipt); err != nil {
				t.Fatal("same receipt replay", err)
			}
			if err := journal.Observe(ctx, first.OperationID, contracts.InitialPreparationReceipt{UID: ownerID(13), ResourceVersion: "10"}); err == nil {
				t.Fatal("resource receipt was replaced")
			}
			if v, err := journal.Begin(ctx, next); err != nil || !v.Fresh {
				t.Fatal("verified prefix cannot advance", err)
			}
			state, err := journal.Read(ctx)
			if err != nil || len(state.Creates) != 2 || state.Creates[0].Receipt == nil || state.Creates[1].Receipt != nil {
				t.Fatal("durable prefix changed", err)
			}
		})
	}
}

func TestInitialPreparationRejectsOpenOrUnboundedIntents(t *testing.T) {
	v := contracts.InitialPreparationCreate{OperationID: ownerID(1), Kind: "Pod", Name: "installer", SpecDigest: strings.Repeat("01", 32)}
	for _, change := range []func(*contracts.InitialPreparationCreate){
		func(v *contracts.InitialPreparationCreate) { v.OperationID = "invalid" },
		func(v *contracts.InitialPreparationCreate) { v.Name = "../escape" },
		func(v *contracts.InitialPreparationCreate) { v.Kind = "Command" },
		func(v *contracts.InitialPreparationCreate) { v.SpecDigest = strings.Repeat("00", 32) },
		func(v *contracts.InitialPreparationCreate) { v.SpecDigest = strings.Repeat("AB", 32) },
		func(v *contracts.InitialPreparationCreate) {
			v.Receipt = &contracts.InitialPreparationReceipt{UID: ownerID(2)}
		},
	} {
		bad := v
		change(&bad)
		if initialPreparationCreateValid(bad) {
			t.Fatal("invalid creation intent accepted")
		}
	}
	for _, raw := range []string{`{"password":"forbidden"}`, `{"creates":[],"creates":[]}`, `{"format":"v1"} {}`, strings.Repeat(" ", contracts.InitialPreparationMaxBytes+1)} {
		if _, err := contracts.DecodeInitialPreparation(strings.NewReader(raw)); err == nil {
			t.Fatal("open or unbounded journal decoded")
		}
	}
}
