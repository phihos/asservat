package integration

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

func TestHelmBundledRegionUsesOriginalAccountAndPublicBootstrapOnly(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Fatal(err)
	}
	desired := contracts.InitialBootstrap{Name: "install", BootstrapNamespace: "original-bootstrap", Image: "registry.example/asservat@sha256:" + strings.Repeat("a", 64)}
	issued := installedFleetBootstrapReceipt{BootstrapID: "41414141-4141-4141-8141-414141414141"}
	file := filepath.Join(t.TempDir(), "values.json")
	helmBootstrapWriteValues(t, file, helmBundledRegionValues(desired, issued))
	raw, err := exec.CommandContext(t.Context(), "helm", "template", "asservat-region", "../../charts/asservat", "--namespace", desired.BootstrapNamespace, "--kube-version", "1.37.0", "--values", file).CombinedOutput()
	if err != nil {
		t.Fatalf("selected regional chart: %v %s", err, raw)
	}
	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(raw), 4096)
	found := false
	for {
		var object struct {
			Kind     string
			Metadata meta.ObjectMeta
			Spec     struct{ Template struct{ Spec core.PodSpec } }
		}
		if err := decoder.Decode(&object); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if object.Kind != "Job" {
			continue
		}
		spec := object.Spec.Template.Spec
		want := []string{"/asservat", "installer-cluster", "--in-cluster", "--bundled-hub", desired.Name, "--bootstrap-id", issued.BootstrapID, "--join-hub", "--namespace", "asservat-connector"}
		if object.Metadata.Namespace != desired.BootstrapNamespace || spec.ServiceAccountName != desired.Name+"-bootstrap-runner" || len(spec.Containers) != 1 || !reflect.DeepEqual(spec.Containers[0].Command, want) {
			t.Fatal("regional chart replaced source account/scope or used manual inputs")
		}
		found = true
	}
	if !found {
		t.Fatal("actual selected regional hook missing")
	}
}

func TestBundledRegionalBindingNamesActualUserAndPinnedTarget(t *testing.T) {
	t.Setenv("ASSERVAT_JOURNEY_FOCUS", "journey")
	actual := "42424242-4242-4242-8242-424242424242"
	called := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		if r.Method != http.MethodPost || r.URL.Path != "/apis/asservat.io/v1alpha1/namespaces/hub/accessbindings" {
			t.Error("unexpected operator effect")
		}
		var body struct {
			Spec struct {
				Subjects []struct{ Kind, Issuer, ID string }
				Scope    struct {
					ClusterID    string
					NamespaceRef struct{ Name, UID string }
					Workloads    []struct{ Kind, Name, UID string }
				}
			}
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || len(body.Spec.Subjects) != 1 || body.Spec.Subjects[0].Kind != "User" || body.Spec.Subjects[0].ID != actual || body.Spec.Subjects[0].Issuer != "https://identity.example/realms/asservat" || body.Spec.Scope.ClusterID != "43434343-4343-4343-8343-434343434343" || body.Spec.Scope.NamespaceRef.UID != "namespace-actual" || len(body.Spec.Scope.Workloads) != 1 || body.Spec.Scope.Workloads[0].UID != "deployment-actual" {
			t.Error("binding granted ordinary group or replaced the pinned target")
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"apiVersion":"v1","kind":"Status","status":"Success"}`)
	}))
	defer server.Close()
	api, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}})
	if err != nil {
		t.Fatal(err)
	}
	b := &regionalBudget{t: t, ctx: t.Context(), client: api.CoreV1().RESTClient(), base: "/apis/asservat.io/v1alpha1/namespaces/hub/", issuer: "https://identity.example/realms/asservat", cluster: "43434343-4343-4343-8343-434343434343", bindingName: "actual-developer", subjectKind: "User", subjectID: actual}
	b.addBinding(regionalWorkload{ns: &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: "apps", UID: "namespace-actual"}}, app: &apps.Deployment{ObjectMeta: meta.ObjectMeta{Name: "target", UID: "deployment-actual"}}})
	if called != 1 {
		t.Fatal("binding was repeated")
	}
	legacy := &regionalBudget{}
	if legacy.subjectKindValue() != "Group" || legacy.subjectIDValue() != installedIdentityGroup {
		t.Fatal("external fixture changed")
	}
}

func TestBundledObservationReaderUsesRetainedCredentialAndOriginalTransport(t *testing.T) {
	const namespace = "hub"
	ref := contracts.WorkerObjectReference{Name: "original-reader", UID: "44444444-4444-4444-8444-444444444444"}
	credential := contracts.OwnerStorageCredential{AccessKeyID: "original-private-reader", SecretAccessKey: "original-private-secret"}
	raw, _ := json.Marshal(credential)
	source := &core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Namespace: namespace, Name: ref.Name, UID: "44444444-4444-4444-8444-444444444444", ResourceVersion: "1"}, Immutable: ptr.To(false), Type: core.SecretTypeOpaque, Data: map[string][]byte{contracts.ConfigurationProviderAuditCredentialFile: raw}}
	reads := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reads++
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/namespaces/hub/secrets/original-reader" {
			t.Error("observer performed provider administration or ambient lookup")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(source)
	}))
	defer server.Close()
	api, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}})
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Client{}
	original := s3.New(s3.Options{Region: "original", BaseEndpoint: aws.String("https://original.example"), HTTPClient: transport, Credentials: credentials.NewStaticCredentialsProvider("initial-audit", "initial-only", "")})
	observed := bundledRuntimeObservationStore(t, t.Context(), api, namespace, ref, contracts.ConfigurationProviderAuditCredentialFile, original)
	actual, err := observed.Options().Credentials.Retrieve(t.Context())
	if err != nil || actual.AccessKeyID != credential.AccessKeyID || observed.Options().HTTPClient != transport || aws.ToString(observed.Options().BaseEndpoint) != "https://original.example" || observed.Options().Region != "original" || reads != 1 {
		t.Fatal("observer substituted credential, roots/transport or backend")
	}
	unchanged, _ := original.Options().Credentials.Retrieve(t.Context())
	if unchanged.AccessKeyID != "initial-audit" {
		t.Fatal("initial-audit capability was broadened")
	}
}
