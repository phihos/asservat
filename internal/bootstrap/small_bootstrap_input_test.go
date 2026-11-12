package bootstrap

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
)

func smallBootstrapInput(t *testing.T) (contracts.InitialBootstrapInput, []byte) {
	t.Helper()
	plan := contracts.SmallPostgresPlan{Format: contracts.SmallPostgresFormat, Namespace: "trusted-bootstrap", Name: "install"}
	material, err := kube.BuildSmallPostgresMaterial(plan, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ca := material["ca.crt"]
	v := contracts.InitialBootstrapInput{Format: contracts.InitialBootstrapInputFormat, Name: plan.Name, BootstrapNamespace: plan.Namespace, TargetNamespace: "asservat", RunnerAccount: "install-bootstrap-runner", Image: "registry.invalid/asservat@sha256:" + strings.Repeat("a", 64), ProbeAudience: "api-audience",
		Kubernetes: contracts.InitialBootstrapEndpointInput{Endpoint: "https://kubernetes.example", RootsPEM: string(ca)},
		Postgres:   contracts.InitialBootstrapPostgresInput{Host: plan.Host(), Port: 5432, Database: "asservat", MaxConnections: 2, RootsSource: contracts.InitialBootstrapBundledPostgresRoots},
		AuditStore: contracts.InitialBootstrapAuditStoreInput{Endpoint: "https://storage.example", Region: "test", Bucket: "audit", RootsPEM: string(ca)},
		KeyService: contracts.InitialBootstrapKeyServiceInput{Endpoint: "https://bao.example", AuditMount: "transit", AuditKey: "audit", RootsPEM: string(ca)},
		Providers:  contracts.InitialBootstrapProviders{IssuerPolicy: "issuer", WrapRole: "wrap", WrapPolicy: "encrypt", UnwrapRole: "unwrap", UnwrapPolicy: "decrypt"}}
	return v, ca
}

func smallBootstrapFiles(t *testing.T, input contracts.InitialBootstrapInput, ca []byte) *os.Root {
	t.Helper()
	dir := t.TempDir()
	data, err := json.Marshal(input)
	if err != nil || os.WriteFile(filepath.Join(dir, "bootstrap.json"), data, 0600) != nil {
		t.Fatal("public fixture", err)
	}
	if ca != nil {
		if err := os.WriteFile(filepath.Join(dir, contracts.InitialBootstrapPostgresCAFile), ca, 0600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return root
}

func TestSmallPostgresTrustIsResolvedBeforeCanonicalBootstrap(t *testing.T) {
	v, ca := smallBootstrapInput(t)
	if _, err := providerconfig.CompileInitialBootstrapInput(v, nil, nil, time.Now()); err == nil {
		t.Fatal("unresolved generated source reached canonical compilation")
	}
	got, err := readInitialBootstrapDesired(t.Context(), smallBootstrapFiles(t, v, ca))
	if err != nil {
		t.Fatal("actual generated-root consumer", err)
	}
	v.Postgres.RootsSource, v.Postgres.RootsPEM = "", string(ca)
	explicit, err := readInitialBootstrapDesired(t.Context(), smallBootstrapFiles(t, v, nil))
	if err != nil {
		t.Fatal("existing explicit roots changed", err)
	}
	a, _ := json.Marshal(got)
	b, _ := json.Marshal(explicit)
	if !bytes.Equal(a, b) || len(got.Postgres.Roots) != 1 || got.Postgres.MaxConnections != 2 {
		t.Fatal("generated trust lost canonical bytes or confused client/server connection budgets")
	}
	_, other := smallBootstrapInput(t)
	v.Postgres.RootsSource, v.Postgres.RootsPEM = contracts.InitialBootstrapBundledPostgresRoots, ""
	changed, err := readInitialBootstrapDesired(t.Context(), smallBootstrapFiles(t, v, other))
	if err != nil {
		t.Fatal(err)
	}
	c, _ := json.Marshal(changed)
	if bytes.Equal(a, c) {
		t.Fatal("actual generated CA was excluded from original installation identity")
	}
}

func TestSmallPostgresTrustRefusesUnknownAmbiguousOrMissingSources(t *testing.T) {
	for _, mode := range []string{"missing", "unknown", "path", "ambiguous", "invalid-cert"} {
		t.Run(mode, func(t *testing.T) {
			v, ca := smallBootstrapInput(t)
			switch mode {
			case "missing":
				ca = nil
			case "unknown":
				v.Postgres.RootsSource = "another-provider"
			case "path":
				v.Postgres.RootsSource = "../../private-key"
			case "ambiguous":
				v.Postgres.RootsPEM = string(ca)
			case "invalid-cert":
				ca = []byte("not a certificate")
			}
			if _, err := readInitialBootstrapDesired(t.Context(), smallBootstrapFiles(t, v, ca)); err == nil {
				t.Fatal("unrecognized generated trust became an installation input")
			}
		})
	}
}
