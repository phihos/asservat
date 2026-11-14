package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

// Synthetic fixture material only. It is supplied through the real private
// installer projection and app-only Secret, never a public capture parameter.
const manualProfileAuthorizationSentinel = "Bearer synthetic-installed-profile-authorization-9b670871"

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
