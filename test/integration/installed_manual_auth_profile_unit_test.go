package integration

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	fake "k8s.io/client-go/kubernetes/fake"
)

func TestInstalledManualProfileAuthClosedTLSCPUSelection(t *testing.T) {
	t.Setenv("ASSERVAT_JOURNEY_FOCUS", "manual-profile")
	t.Setenv("ASSERVAT_PROFILE_VARIANT", "cpu")
	t.Setenv("ASSERVAT_PROFILE_TRANSPORT", "tls")
	for _, mode := range []string{"", "none", "required"} {
		t.Setenv("ASSERVAT_PROFILE_AUTH", mode)
		if installedProfileAuthorization() != (mode == "required") {
			t.Fatal("auth selection changed")
		}
	}
	for _, tc := range []struct{ mode, transport, variant, focus string }{{"typo", "tls", "cpu", "manual-profile"}, {"required", "http", "cpu", "manual-profile"}, {"required", "tls", "heap", "manual-profile"}, {"required", "tls", "cpu", "policy-profile"}} {
		t.Run(tc.mode+tc.transport+tc.variant+tc.focus, func(t *testing.T) {
			t.Setenv("ASSERVAT_PROFILE_AUTH", tc.mode)
			t.Setenv("ASSERVAT_PROFILE_TRANSPORT", tc.transport)
			t.Setenv("ASSERVAT_PROFILE_VARIANT", tc.variant)
			t.Setenv("ASSERVAT_JOURNEY_FOCUS", tc.focus)
			defer func() {
				if recover() == nil {
					t.Fatal("incompatible auth fixture accepted")
				}
			}()
			installedProfileAuthorization()
		})
	}
}

func TestInstalledManualProfileAuthPrivateInstallerMapAndOriginalAppSecret(t *testing.T) {
	t.Setenv("ASSERVAT_JOURNEY_FOCUS", "manual-profile")
	t.Setenv("ASSERVAT_PROFILE_VARIANT", "cpu")
	t.Setenv("ASSERVAT_PROFILE_TRANSPORT", "tls")
	t.Setenv("ASSERVAT_PROFILE_AUTH", "required")
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	material := manualProfileTLSFixture(t, directory)
	defer clear(material.Key)
	const cluster = "00000000-0000-4000-8000-000000000001"
	endpoints := manualAuthenticatedProfileEndpoints(material.Roots, cluster, "00000000-0000-4000-8000-000000000002", "00000000-0000-4000-8000-000000000003")
	if !kube.ProfileEndpointsValid(endpoints) || len(endpoints) != 3 {
		t.Fatal("invalid authenticated endpoint fixtures")
	}
	for i, endpoint := range endpoints {
		a := endpoint.Credential.Audiences[0]
		if a.ClusterID != cluster || a.NamespaceUID != "00000000-0000-4000-8000-000000000002" || a.WorkloadKind != "Deployment" || (i < 2 && a.WorkloadUID != "00000000-0000-4000-8000-000000000003") || (i == 2 && a.WorkloadUID == "00000000-0000-4000-8000-000000000003") {
			t.Fatal("exact root audience lost")
		}
	}
	public, err := json.Marshal(endpoints)
	if err != nil || bytes.Contains(public, []byte(manualProfileAuthorizationSentinel)) {
		t.Fatal("private material in public endpoint configuration")
	}
	path := writeManualProfileAuthorization(t, directory, endpoints)
	raw, err := os.ReadFile(path)
	if err != nil || filepath.Base(path) != contracts.RegionalProfileAuthorizationFile {
		t.Fatal("private installer input missing")
	}
	decoded, err := contracts.DecodeRegionalProfileAuthorization(bytes.NewReader(raw))
	if err != nil || len(decoded.Entries) != len(endpoints) {
		t.Fatal("private installer map rejected", err)
	}
	defer decoded.Clear()
	for i, entry := range decoded.Entries {
		if entry.Name != endpoints[i].Name || string(entry.Authorization) != manualProfileAuthorizationSentinel {
			t.Fatal("private map name/value mismatch")
		}
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("private installer file permissions")
	}
	api := fake.NewClientset()
	workload := createRegionalWorkload(t, t.Context(), api, "synthetic-image", "apps-regional", false, directory)
	command := workload.app.Spec.Template.Spec.Containers[0].Command
	if len(command) != 6 || command[4] != "--authorization" || command[5] != "/run/profile-tls/authorization" {
		t.Fatal("original app lacks its fixed auth input")
	}
	secret, err := api.CoreV1().Secrets(workload.ns.Name).Get(t.Context(), "profile-application-tls", meta.GetOptions{})
	if err != nil || len(secret.Data) != 3 || string(secret.Data["authorization"]) != manualProfileAuthorizationSentinel || secret.Immutable == nil || !*secret.Immutable {
		t.Fatal("app-only immutable auth material missing", err)
	}
}
