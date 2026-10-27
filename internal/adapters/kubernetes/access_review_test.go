package kubernetes

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/targets"
	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/client-go/rest"
)

func reviewFixtureRequest(check string) value.AccessReviewRequest {
	r := value.AccessReviewRequest{
		Target:    value.Request{ClusterID: permissionCluster, Namespace: cfg.NamespaceRef{Name: "payments", UID: "payments-uid"}, Workload: cfg.WorkloadRef{Kind: "Deployment", Name: "api", UID: "api-uid"}, PodName: "api-1", PodUID: "pod-api-1"},
		Source:    value.AccessReviewSource{UID: "source-uid", Type: cfg.SourceKubernetesExec, Check: cfg.ReviewPodExec, IdentityMapping: "company", NamespaceSelector: map[string]string{"example.invalid/managed": "true"}, ExcludedNamespaces: []string{"kube-system"}},
		Principal: value.AccessReviewPrincipal{Issuer: "https://id.example.invalid", Subject: "alice-sub", Groups: []string{"team-a"}},
	}
	if check != cfg.ReviewPodExec {
		r.Source.Type, r.Source.Check = cfg.SourceKubernetesAccessReview, check
	}
	return r
}

// ADR-245: the connector maps the principal through its own record, checks
// namespace and object identity and submits exactly one SubjectAccessReview
// naming the mapped user, never itself.
func TestReviewAccessSubmitsMappedSubjectAccessReview(t *testing.T) {
	groups := "oidc:"
	mappings := []contracts.RegionalIdentityMapping{{Name: "company", Issuer: "https://id.example.invalid", UsernamePrefix: "oidc:", GroupsPrefix: &groups, UID: true}}
	for _, mode := range []string{"allowed", "denied", "evaluation-error", "explicit-deny", "pod-deleted", "pod-replaced", "namespace-replaced", "namespace-gone", "outside-selector", "excluded", "unknown-mapping", "other-issuer", "sar-forbidden", "workload-patch", "namespace-capture", "bare-pod-workload-check"} {
		t.Run(mode, func(t *testing.T) {
			var reviews []authorizationv1.SubjectAccessReview
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer synthetic-only" {
					t.Error("unexpected credential")
				}
				switch {
				case r.Method == "GET" && r.URL.Path == "/api/v1/namespaces/payments":
					switch mode {
					case "namespace-gone":
						w.WriteHeader(404)
						permissionReply(w, map[string]any{"apiVersion": "v1", "kind": "Status", "reason": "NotFound", "status": "Failure", "code": 404})
						return
					case "namespace-replaced":
						permissionReply(w, permissionNamespace("payments", "other-uid"))
						return
					}
					ns := permissionNamespace("payments", "payments-uid")
					if mode == "outside-selector" {
						ns["metadata"].(map[string]any)["labels"] = map[string]string{"example.invalid/managed": "false"}
					}
					permissionReply(w, ns)
				case r.Method == "GET" && r.URL.Path == "/api/v1/namespaces/payments/pods/api-1":
					if mode == "pod-deleted" {
						w.WriteHeader(404)
						permissionReply(w, map[string]any{"apiVersion": "v1", "kind": "Status", "reason": "NotFound", "status": "Failure", "code": 404})
						return
					}
					uid := "pod-api-1"
					if mode == "pod-replaced" {
						uid = "pod-api-1-new"
					}
					permissionReply(w, targetMetadata("Pod", "api-1", uid))
				case r.Method == "GET" && r.URL.Path == "/apis/apps/v1/namespaces/payments/deployments/api":
					permissionReply(w, targetMetadata("Deployment", "api", "api-uid"))
				case r.Method == "POST" && r.URL.Path == "/apis/authorization.k8s.io/v1/subjectaccessreviews":
					if mode == "sar-forbidden" {
						w.WriteHeader(403)
						permissionReply(w, map[string]any{"apiVersion": "v1", "kind": "Status", "reason": "Forbidden", "status": "Failure", "code": 403})
						return
					}
					var review authorizationv1.SubjectAccessReview
					if json.NewDecoder(r.Body).Decode(&review) != nil {
						t.Error("undecodable review")
					}
					reviews = append(reviews, review)
					review.Status.Allowed = mode != "denied" && mode != "explicit-deny"
					review.Status.Denied = mode == "explicit-deny"
					if mode == "evaluation-error" {
						review.Status.EvaluationError = "webhook unavailable"
					}
					w.WriteHeader(201)
					permissionReply(w, review)
				default:
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
					w.WriteHeader(500)
				}
			}))
			defer s.Close()
			config := &rest.Config{Host: s.URL, BearerToken: "synthetic-only", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw})}}
			client, err := NewPermissionClient(config, permissionCluster, permissionControl, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			targets, err := NewAPIContextTargets(client)
			if err != nil {
				t.Fatal(err)
			}
			if targets, err = targets.WithIdentityMappings(mappings); err != nil {
				t.Fatal(err)
			}
			check := cfg.ReviewPodExec
			switch mode {
			case "workload-patch", "bare-pod-workload-check":
				check = cfg.ReviewWorkloadPatch
			case "namespace-capture":
				check = cfg.ReviewNamespaceCaptureCreate
			}
			req := reviewFixtureRequest(check)
			switch mode {
			case "excluded":
				req.Source.ExcludedNamespaces = []string{"payments"}
			case "unknown-mapping":
				req.Source.IdentityMapping = "other"
			case "other-issuer":
				req.Principal.Issuer = "https://other.example.invalid"
			case "bare-pod-workload-check":
				req.Target.Workload = cfg.WorkloadRef{Kind: "Pod", Name: "api-1", UID: "pod-api-1"}
			}
			got, err := targets.ReviewAccess(context.Background(), req)
			want := map[string]string{"allowed": value.AccessAllowed, "denied": value.AccessDenied, "evaluation-error": value.AccessDenied, "explicit-deny": value.AccessDenied, "pod-deleted": value.AccessAllowed,
				"pod-replaced": value.AccessTargetChanged, "namespace-replaced": value.AccessTargetChanged, "namespace-gone": value.AccessTargetChanged, "outside-selector": value.AccessOutsideSource, "excluded": value.AccessOutsideSource,
				"unknown-mapping": value.AccessMappingUnsupported, "other-issuer": value.AccessMappingUnsupported, "workload-patch": value.AccessAllowed, "namespace-capture": value.AccessAllowed, "bare-pod-workload-check": value.AccessOutsideSource}[mode]
			if mode == "sar-forbidden" {
				if !errors.Is(err, value.ErrUnavailable) {
					t.Fatalf("missing review authority must be unavailable, got %+v %v", got, err)
				}
				return
			}
			if err != nil || got.Outcome != want || got.SourceUID != "source-uid" || !got.Valid(req) {
				t.Fatalf("got %+v %v, want %s", got, err, want)
			}
			if len(reviews) == 0 {
				return
			}
			if len(reviews) != 1 {
				t.Fatalf("expected one review, got %d", len(reviews))
			}
			spec := reviews[0].Spec
			if spec.User != "oidc:alice-sub" || spec.UID != "alice-sub" || !slices.Equal(spec.Groups, []string{"oidc:team-a", "system:authenticated"}) || spec.NonResourceAttributes != nil || spec.ResourceAttributes == nil {
				t.Fatalf("review subject is not the mapped principal: %+v", spec)
			}
			a := *spec.ResourceAttributes
			switch check {
			case cfg.ReviewPodExec:
				if a != (authorizationv1.ResourceAttributes{Namespace: "payments", Version: "v1", Resource: "pods", Subresource: "exec", Verb: "create", Name: "api-1"}) {
					t.Fatalf("exec attributes %+v", a)
				}
			case cfg.ReviewWorkloadPatch:
				if a != (authorizationv1.ResourceAttributes{Namespace: "payments", Group: "apps", Version: "v1", Resource: "deployments", Verb: "patch", Name: "api"}) {
					t.Fatalf("workload attributes %+v", a)
				}
			case cfg.ReviewNamespaceCaptureCreate:
				if a != (authorizationv1.ResourceAttributes{Namespace: "payments", Group: "asservat.io", Version: "v1alpha1", Resource: "debugcaptures", Verb: "create"}) {
					t.Fatalf("capture attributes %+v", a)
				}
			}
		})
	}
}

func TestIdentityMappingsAreBoundedLocalRecords(t *testing.T) {
	g := "oidc:"
	bad := "bad prefix"
	ok := contracts.RegionalIdentityMapping{Name: "company", Issuer: "https://id.example.invalid", UsernamePrefix: "oidc:", GroupsPrefix: &g}
	if !IdentityMappingsValid(nil) || !IdentityMappingsValid([]contracts.RegionalIdentityMapping{ok}) {
		t.Fatal("valid mapping refused")
	}
	for name, m := range map[string]contracts.RegionalIdentityMapping{
		"http issuer":    {Name: "x", Issuer: "http://id.example.invalid"},
		"bad name":       {Name: "X_Y", Issuer: ok.Issuer},
		"control prefix": {Name: "x", Issuer: ok.Issuer, UsernamePrefix: "a\nb"},
		"space groups":   {Name: "x", Issuer: ok.Issuer, GroupsPrefix: &bad},
		"long prefix":    {Name: "x", Issuer: ok.Issuer, UsernamePrefix: strings.Repeat("a", 257)},
	} {
		if IdentityMappingsValid([]contracts.RegionalIdentityMapping{m}) {
			t.Errorf("%s accepted", name)
		}
	}
	if IdentityMappingsValid([]contracts.RegionalIdentityMapping{ok, ok}) {
		t.Error("duplicate name accepted")
	}
}

// Only a cluster with identity mappings grants its connector review create.
func TestRegionalReviewRBACIsSubjectAccessReviewCreateOnly(t *testing.T) {
	r := regionalReviewRBAC()
	if !slices.Equal(r.APIGroups, []string{"authorization.k8s.io"}) || !slices.Equal(r.Resources, []string{"subjectaccessreviews"}) || !slices.Equal(r.Verbs, []string{"create"}) || len(r.ResourceNames) != 0 {
		t.Fatalf("review rule %+v", r)
	}
	cluster, connector, _ := regionalExecutorRBAC("region")
	for _, rule := range append(cluster, connector...) {
		if slices.Contains(rule.Resources, "subjectaccessreviews") {
			t.Fatal("executor RBAC grants review create without identity mappings")
		}
	}
}
