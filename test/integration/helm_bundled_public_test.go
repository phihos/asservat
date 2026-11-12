package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/rest"
	"net"
	"net/http"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type helmBundledPublic struct {
	materialName, nodeIP string
	root                 []byte
}

func newHelmBundledPublic(t *testing.T, ctx context.Context, api kubernetes.Interface, d contracts.InitialBootstrap, nodeIP string) *helmBundledPublic {
	t.Helper()
	data := map[string][]byte{}
	root, cert, key := syntheticServingPair(t, nodeIP)
	data[contracts.OwnerPublicTLSCertificate], data[contracts.OwnerPublicTLSKey] = cert, key
	for _, keys := range [][3]string{{contracts.InstallerInboxFederationTLSCertificate, contracts.InstallerInboxFederationTLSKey, contracts.InstallerInboxFederationTLSCA}, {contracts.InstallerInboxKeyServiceTLSCertificate, contracts.InstallerInboxKeyServiceTLSKey, contracts.InstallerInboxKeyServiceTLSCA}} {
		ca, crt, private := syntheticServingPair(t, nodeIP)
		data[keys[0]], data[keys[1]], data[keys[2]] = crt, private, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca})
	}
	name := d.Name + "-operator-serving-material"
	if _, err := api.CoreV1().Secrets(d.BootstrapNamespace).Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: name}, Type: core.SecretTypeOpaque, Data: data}, meta.CreateOptions{}); err != nil {
		t.Fatal("explicit operator serving material", err)
	}
	for _, raw := range data {
		clear(raw)
	}
	return &helmBundledPublic{materialName: name, nodeIP: nodeIP, root: root}
}

func (p *helmBundledPublic) Values(t *testing.T, k *helmBundledIdentity) map[string]any {
	t.Helper()
	profile := helmContextTrialProfile(t).Public
	profile.Origin = k.settings.Origin
	profile.ClientID = k.settings.ConsoleClientID
	profile.Issuer = bundledKeycloakIssuer(k.settings)
	profile.Clients = []contracts.IdentityClient{{ID: k.settings.ConsoleClientID, Kind: "human", ClassQualified: true}, {ID: k.settings.MCPClientID, Kind: "human", ClassQualified: true}}
	profile.EligibleGroups = []string{}
	profile.ProcessingOperators = nil
	f := profile.Federation
	f.ConnectorPKIMount, f.ConnectorIssuerRootsPEM = "", ""
	f.Endpoint = "https://" + net.JoinHostPort(p.nodeIP, "31446")
	f.ServerName = p.nodeIP
	f.OwnerAddress = net.JoinHostPort(p.nodeIP, "31447")
	f.OwnerOperationAddress = net.JoinHostPort(p.nodeIP, "31449")
	f.KeyServiceEndpoint = "https://" + net.JoinHostPort(p.nodeIP, "31448")
	f.EvidenceStore = &contracts.InstallerEvidenceStore{}
	profile.Promotion.BrowserAudience = k.settings.BrowserAudience
	profile.Promotion.ProviderRootsPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: k.root}))
	raw, _ := json.Marshal(profile)
	var public map[string]any
	if json.Unmarshal(raw, &public) != nil {
		t.Fatal("canonical finite public profile")
	}
	delete(public, "processingOperators") // original explicit opt-in derives it
	// Operator values omit this internal qualification bit; the actual chart
	// adds it while compiling its closed continuation DTO.
	for _, raw := range public["clients"].([]any) {
		delete(raw.(map[string]any), "classQualified")
	}
	return map[string]any{"enabled": true, "materialSecretName": p.materialName, "public": public}
}

func (p *helmBundledPublic) Login(t *testing.T, ctx context.Context, identity *installedIdentity) *installedBrowser {
	t.Helper()
	cert, err := x509.ParseCertificate(p.root)
	if err != nil {
		t.Fatal(err)
	}
	address := net.JoinHostPort(p.nodeIP, "31450")
	// Helm joins only after automatic continuation. This is the actual public
	// cookie login through the chart-imported Keycloak, not fixture bearer auth.
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	if err := waitHelmBundledPublicListener(ctx, client, "https://"+address); err != nil {
		t.Fatal("bundled public/listener-readiness", err)
	}
	browser := identity.consoleSession(t, ctx, cert, address, "https://"+address)
	t.Log("actual bundled five-command Helm completed; imported Keycloak browser login reached the real public session")
	return browser
}

// The actual chart must preserve source selection and the COMPLETE finite
// reference profile; pure helper construction alone cannot prove this boundary.
func TestHelmBundledPublicUsesActualClosedSourceInputs(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Fatal("Helm is required")
	}
	ca, _, _ := syntheticServingPair(t, "api.example")
	endpoint := &rest.Config{Host: "https://api.example:6443", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca})}}
	desired := initialBootstrapGuardDesired(t, endpoint, "trusted-bootstrap", "actual-unit-operator")
	desired.Image = "registry.example/asservat@sha256:" + strings.Repeat("a", 64)
	input := helmBootstrapPublicInput(desired)
	input.Administrators = desired.Administrators
	values := helmBootstrapValues(input)
	pg := helmBundledPostgres{image: "registry.example/postgres@sha256:" + strings.Repeat("b", 64)}
	store := helmBundledObjectStore{plan: contracts.SmallSeaweedPlan{Image: "registry.example/seaweed@sha256:" + strings.Repeat("c", 64)}}
	key := helmBundledKeyService{plan: contracts.SmallOpenBaoPlan{Image: contracts.SmallOpenBaoImage}}
	pg.Values(values)
	store.Values(values)
	key.Values(values)
	public := &helmBundledPublic{materialName: "operator-serving-material", nodeIP: "127.0.0.1", root: ca}
	identity := &helmBundledIdentity{root: ca, settings: contracts.SmallKeycloakSettings{Namespace: desired.BootstrapNamespace, SecretName: desired.Name + "-keycloak-state", Hostname: "https://127.0.0.1:31451", Realm: "asservat", Origin: "https://127.0.0.1:31450", ConsoleClientID: "asservat-console", BrowserAudience: "asservat-api", MCPClientID: "asservat-mcp", MCPRedirectURIs: []string{"http://127.0.0.1:42000/callback"}, ProcessingOperators: true, Database: contracts.SmallKeycloakDatabase{Host: desired.Name + "-postgres." + desired.BootstrapNamespace + ".svc", Port: 5432, Database: "keycloak", Username: "keycloak"}}}
	identity.Values(t, values, &input, public)
	values["bootstrap"].(map[string]any)["secrets"].(map[string]any)["producer"] = ""
	path := filepath.Join(t.TempDir(), "values.json")
	helmBootstrapWriteValues(t, path, values)
	ctx, stop := context.WithTimeout(t.Context(), 30*time.Second)
	defer stop()
	raw, err := exec.CommandContext(ctx, "helm", "template", "asservat", "../../charts/asservat", "--namespace", desired.BootstrapNamespace, "--kube-version", "1.37.0", "--values", path).CombinedOutput()
	if err != nil {
		t.Fatalf("all-four public chart: %v %s", err, raw)
	}
	decoded := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(raw), 4096)
	var preparation, continuation, bootstrapInput, runner bool
	for {
		var object struct {
			Kind     string
			Metadata struct{ Name string }
			Data     map[string]string
			Spec     struct{ InitContainers, Containers []core.Container }
		}
		if err := decoded.Decode(&object); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if object.Kind == "Pod" && object.Metadata.Name == desired.Name+"-bootstrap" {
			runner = len(object.Spec.InitContainers) == 4 && len(object.Spec.Containers) == 1 && reflect.DeepEqual(object.Spec.Containers[0].Command, []string{"/asservat", "installer-continue"})
		}
		if object.Kind != "ConfigMap" {
			continue
		}
		if content := object.Data["preparation.json"]; content != "" {
			actual, err := contracts.DecodeSmallServicesPreparation(strings.NewReader(content))
			if err != nil || !actual.Postgres || actual.Keycloak == nil || !reflect.DeepEqual(*actual.Keycloak, identity.settings) || actual.ObjectStore == nil || actual.OpenBao == nil {
				t.Fatal("actual selected preparation lost original Keycloak or storage inputs", err)
			}
			preparation = true
		}
		if content := object.Data["bootstrap.json"]; content != "" {
			actual, err := contracts.DecodeInitialBootstrapInput(strings.NewReader(content))
			if err != nil || actual.IdentitySource != "bundledKeycloak" || actual.Fleet.Issuer != bundledKeycloakIssuer(identity.settings) || len(actual.Fleet.Groups) != 0 || !reflect.DeepEqual(actual.Administrators, desired.Administrators) {
				t.Fatal("chart injected identity or lost actual explicit operator", err)
			}
			bootstrapInput = true
		}
		if content := object.Data[contracts.InstallerContinuationFile]; content != "" {
			actual, err := contracts.DecodeInstallerContinuation(strings.NewReader(content))
			want := helmContextTrialProfile(t).Public
			if err != nil || actual.Public == nil || actual.IdentitySource != "bundledKeycloak" || actual.KeyServiceSource != "bundledOpenBao" || actual.ObjectStoreSource != "bundledSeaweed" || actual.MaterialSecretName != public.materialName || len(actual.Public.ProcessingOperators) != 0 || !reflect.DeepEqual(actual.Public.Capacity, want.Capacity) || !reflect.DeepEqual(actual.Public.Federation.Connector, want.Federation.Connector) || !reflect.DeepEqual(actual.Public.RetentionBaseline, want.RetentionBaseline) {
				t.Fatal("closed continuation changed finite profile or generated identities", err)
			}
			continuation = true
		}
	}
	if !preparation || !continuation || !bootstrapInput || !runner {
		t.Fatal("actual chart omitted selected source or exact five-command runner", preparation, continuation, bootstrapInput, runner)
	}
}

// Read-only listener/unauthenticated-session readiness never repeats login,
// token issuance or an audited product operation. Original parent wins.
func waitHelmBundledPublicListener(ctx context.Context, client *http.Client, origin string) error {
	return wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, 30*time.Second, true, func(current context.Context) (bool, error) {
		request, err := http.NewRequestWithContext(current, http.MethodGet, origin+"/api/v1/session", nil)
		if err != nil {
			return false, err
		}
		response, err := client.Do(request)
		if err != nil {
			if errors.Is(err, syscall.ECONNREFUSED) {
				return false, nil
			}
			return false, err
		}
		defer response.Body.Close()
		io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		if response.StatusCode == http.StatusServiceUnavailable {
			return false, nil
		}
		if response.StatusCode != http.StatusOK {
			return false, fmt.Errorf("public session readiness status %d", response.StatusCode)
		}
		return true, nil
	})
}
