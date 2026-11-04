package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"asservat.local/asservat/internal/contracts"
	"github.com/google/pprof/profile"
	"k8s.io/client-go/kubernetes"
)

// Synthetic fixture material only. It is supplied through the real private
// installer projection and app-only Secret, never a public capture parameter.
const manualProfileAuthorizationSentinel = "Bearer synthetic-installed-profile-authorization-9b670871"
const manualProfileWrongAudienceProfile = "go-cpu-wrong-auth-audience"
const manualProfileWrongAudienceEndpoint = "go-pprof-wrong-auth-audience"

func installedProfileAuthorization() bool {
	switch os.Getenv("ASSERVAT_PROFILE_AUTH") {
	case "", "none":
		return false
	case "required":
		if !installedTLSProfileTransport() {
			panic("profile authorization fixture requires TLS CPU")
		}
		return true
	default:
		panic("unknown installed profile authorization fixture")
	}
}

func manualAuthenticatedProfileEndpoints(roots []byte, cluster, namespaceUID, workloadUID string) []contracts.RegionalProfileEndpoint {
	endpoints := manualTLSProfileEndpoints(roots)
	for i := range endpoints {
		endpoints[i].Credential = &contracts.RegionalProfileEndpointCredential{Audiences: []contracts.RegionalProfileEndpointAudience{{ClusterID: cluster, NamespaceUID: namespaceUID, WorkloadKind: "Deployment", WorkloadUID: workloadUID}}}
	}
	wrong := endpoints[0]
	wrong.Name = manualProfileWrongAudienceEndpoint
	wrong.Credential = &contracts.RegionalProfileEndpointCredential{Audiences: []contracts.RegionalProfileEndpointAudience{{ClusterID: cluster, NamespaceUID: namespaceUID, WorkloadKind: "Deployment", WorkloadUID: "00000000-0000-4000-8000-000000000099"}}}
	return append(endpoints, wrong)
}

func writeManualProfileAuthorization(t *testing.T, directory string, endpoints []contracts.RegionalProfileEndpoint) string {
	t.Helper()
	material := contracts.RegionalProfileAuthorization{Format: contracts.RegionalProfileAuthorizationFormat}
	for _, endpoint := range endpoints {
		material.Entries = append(material.Entries, contracts.RegionalProfileAuthorizationEntry{Name: endpoint.Name, Authorization: []byte(manualProfileAuthorizationSentinel)})
	}
	defer material.Clear()
	raw, err := json.Marshal(material)
	if err != nil {
		t.Fatal("synthetic profile authorization projection encoding")
	}
	defer clear(raw)
	path := filepath.Join(directory, contracts.RegionalProfileAuthorizationFile)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal("private profile authorization fixture file")
	}
	return path
}

func qualifyManualProfileAuthorization(t *testing.T, ctx context.Context, api kubernetes.Interface, namespace, pod, uid, regionalConfig, cluster, workload string, native []byte, publicFacts any, invoke func(string, any) (installedJourneyEnvelope, string)) {
	t.Helper()
	state, err := profileWorkloadControl(ctx, api, namespace, pod, uid, "state")
	if err != nil || state.ProfileRequests != 1 || state.AuthRequests != 1 || state.AuthDenied != 0 {
		t.Fatal("original app did not receive exactly one authenticated TLS profile request", state, err)
	}
	parsed, err := profile.ParseData(native)
	if err != nil {
		t.Fatal("authenticated native profile parse", err)
	}
	public, err := json.Marshal(publicFacts)
	if err != nil {
		t.Fatal(err)
	}
	marker := []byte(manualProfileAuthorizationSentinel)
	if bytes.Contains(native, marker) || bytes.Contains([]byte(parsed.String()), marker) || bytes.Contains(public, marker) {
		t.Fatal("private profile authorization escaped into native profile or public capture results")
	}
	definition := manualWrongTLSProfileDefinition(t)
	definition["displayName"] = "Synthetic wrong authorization audience"
	definition["recipe"].(map[string]any)["endpointBindings"].([]any)[0].(map[string]any)["templateRef"] = manualProfileWrongAudienceEndpoint
	publishNamespaceCaptureProfile(t, ctx, regionalConfig, namespace, manualProfileWrongAudienceProfile, "v1", definition)
	arguments := manualWrongTLSProfileArguments(cluster, namespace, workload)
	arguments["profile_composition"].(map[string]any)["components"].([]any)[0].(map[string]any)["profileRef"] = map[string]string{"catalog": "namespace", "name": manualProfileWrongAudienceProfile, "version": "v1"}
	reply, code := invoke("preview_capture", arguments)
	if code != "EndpointDenied" || reply.Status != "error" {
		t.Fatal("wrong workload audience was not refused before admission", code, reply.Status)
	}
	var refusal struct {
		PreviewID string `json:"preview_id"`
		CaptureID string `json:"capture_id"`
	}
	if json.Unmarshal(reply.Data, &refusal) != nil || refusal.PreviewID != "" || refusal.CaptureID != "" || bytes.Contains(reply.Data, marker) {
		t.Fatal("wrong audience refusal exposed collection identity or private material")
	}
	after, err := profileWorkloadControl(ctx, api, namespace, pod, uid, "state")
	if err != nil || after != state {
		t.Fatal("wrong audience preview contacted original application", err)
	}
	t.Logf("installed profile authorization: original Pod=%s; exactly one authenticated TLS CPU GET; private sentinel absent native/parsed profile/public preview/progress/catalog; wrong workload-root audience refused before collection approval and no app request", uid)
}
