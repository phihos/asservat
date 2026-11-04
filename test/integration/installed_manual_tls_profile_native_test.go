package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"k8s.io/client-go/kubernetes"
)

const manualProfileTLSServerName = "profile.fixture.invalid"
const manualProfileWrongTLSName = "wrong-profile.fixture.invalid"
const manualProfileWrongTLSProfile = "go-cpu-wrong-tls-peer"

// Transport is independent of profile type. Only this focused CPU fixture uses
// TLS; ordinary HTTP, heap and prepared resource variants keep their paths.
func installedTLSProfileTransport() bool {
	switch transport := os.Getenv("ASSERVAT_PROFILE_TRANSPORT"); transport {
	case "", "http":
		return false
	case "tls":
		variant := os.Getenv("ASSERVAT_PROFILE_VARIANT")
		if installedJourneyFocus() != "manual-profile" || variant != "" && variant != "cpu" {
			panic("TLS profile fixture transport requires manual-profile CPU")
		}
		return true
	default:
		panic("unknown installed profile fixture transport: " + transport)
	}
}

type manualProfileTLSMaterial struct{ Roots, Certificate, Key []byte }

// The harness supplies an existing private0700 work directory. Only the app
// key/certificate become an app Secret; root public material becomes protected
// endpoint configuration. No private key enters installer or collector input.
func manualProfileTLSFixture(t *testing.T, directory string) manualProfileTLSMaterial {
	t.Helper()
	info, err := os.Stat(directory)
	if !filepath.IsAbs(directory) || err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("private profile TLS fixture directory unavailable")
	}
	var material manualProfileTLSMaterial
	paths := []string{"root.pem", "tls.crt", "tls.key"}
	if _, err := os.Stat(filepath.Join(directory, paths[0])); os.IsNotExist(err) {
		caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic installed profile root"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		caCert, err := x509.ParseCertificate(caDER)
		if err != nil {
			t.Fatal(err)
		}
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{manualProfileTLSServerName}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		data := [][]byte{pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})}
		clear(keyDER)
		for index, path := range paths {
			if err := os.WriteFile(filepath.Join(directory, path), data[index], 0600); err != nil {
				t.Fatal("write private synthetic app TLS file", err)
			}
		}
		clear(data[2])
	}
	for index, target := range []*[]byte{&material.Roots, &material.Certificate, &material.Key} {
		raw, err := os.ReadFile(filepath.Join(directory, paths[index]))
		if err != nil || len(raw) > 8<<10 {
			t.Fatal("bounded profile TLS fixture unavailable", err)
		}
		*target = raw
	}
	pair, err := tls.X509KeyPair(material.Certificate, material.Key)
	if err != nil {
		t.Fatal("synthetic app keypair", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(material.Roots) {
		t.Fatal("synthetic app roots")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: manualProfileTLSServerName}); err != nil {
		t.Fatal("synthetic app TLS material changed", err)
	}
	t.Logf("synthetic app TLS public provenance: rootsSHA256=%x certificateSHA256=%x serverName=%s; private key is app-only fixture input", sha256.Sum256(material.Roots), sha256.Sum256(material.Certificate), manualProfileTLSServerName)
	return material
}

func manualTLSProfileEndpoints(roots []byte) []contracts.RegionalProfileEndpoint {
	endpoints := manualProfileEndpoints()
	endpoints[0].TLS = &contracts.RegionalProfileEndpointTLS{RootsPEM: string(roots), ServerName: manualProfileTLSServerName}
	wrong := endpoints[0]
	wrong.Name = "go-pprof-wrong-tls"
	wrong.TLS = &contracts.RegionalProfileEndpointTLS{RootsPEM: string(roots), ServerName: manualProfileWrongTLSName}
	return append(endpoints, wrong)
}

func manualWrongTLSProfileDefinition(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("../../internal/application/planning/profiles/go-cpu-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Definition map[string]any `json:"definition"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		t.Fatal("CPU profile fixture definition")
	}
	doc.Definition["displayName"] = "Synthetic wrong TLS peer"
	recipe := doc.Definition["recipe"].(map[string]any)
	bindings := recipe["endpointBindings"].([]any)
	bindings[0].(map[string]any)["templateRef"] = "go-pprof-wrong-tls"
	return doc.Definition
}

func manualWrongTLSProfileArguments(cluster, namespace, workload string) map[string]any {
	arguments := manualProfileArguments(cluster, namespace, workload)
	component := arguments["profile_composition"].(map[string]any)["components"].([]any)[0].(map[string]any)
	component["profileRef"] = map[string]string{"catalog": "namespace", "name": manualProfileWrongTLSProfile, "version": "v1"}
	return arguments
}

// A second independently reviewed CPU action exercises a valid named endpoint
// whose server name intentionally differs from the original app certificate.
// It must fail before pprof HTTP, with retained admission and no artifact.
func qualifyManualProfileTLSWrongPeer(t *testing.T, ctx context.Context, api kubernetes.Interface, namespace, pod, uid, regionalConfig, cluster, workload string, read func(string, any, any), readContext func(context.Context, string, any, any), invoke func(string, any) (installedJourneyEnvelope, string), approve func(string), check func(string, string, string) time.Time) {
	t.Helper()
	if check == nil {
		t.Fatal("TLS refusal SQL evidence reader missing")
	}
	publishNamespaceCaptureProfile(t, ctx, regionalConfig, namespace, manualProfileWrongTLSProfile, "v1", manualWrongTLSProfileDefinition(t))
	state := func() profileWorkloadState {
		value, err := profileWorkloadControl(ctx, api, namespace, pod, uid, "state")
		if err != nil {
			t.Fatal("original TLS app state", err)
		}
		return value
	}
	before := state()
	capture, grant := requestRefusedManualProfile(t, ctx, "wrong-tls-peer", pod, uid, manualWrongTLSProfileArguments(cluster, namespace, workload), read, invoke, approve, func() {
		if state() != before {
			t.Fatal("TLS preview/review contacted pprof")
		}
	})
	poll, stop := context.WithTimeout(ctx, 30*time.Second)
	defer stop()
	var progress installedJourneyCaptureProgress
	for {
		readContext(poll, "get_capture", map[string]string{"capture_id": capture}, &progress)
		if progress.CaptureID != capture {
			t.Fatal("TLS refusal replaced capture")
		}
		if progress.Phase == "Failed" {
			break
		}
		if progress.Phase != "Pending" && progress.Phase != "Running" {
			t.Fatal("TLS refusal not a bounded terminal failure", progress)
		}
		if err := installedJourneyPause(poll, time.Second); err != nil {
			t.Fatal(err)
		}
	}
	if progress.CaseID != "" || len(progress.Actions) != 1 || progress.Actions[0].Phase != "Failed" || progress.Actions[0].ReasonCode != "ProfileUnavailable" {
		t.Fatal("wrong TLS peer exposed evidence or lost known refusal", progress)
	}
	cutoff := check(capture, grant, "ProfileUnavailable")
	if cutoff.IsZero() {
		t.Fatal("TLS refusal original slot cutoff missing")
	}
	if remaining := time.Until(cutoff); remaining > 0 {
		if err := installedJourneyPause(ctx, remaining); err != nil {
			t.Fatal(err)
		}
	}
	if state() != before {
		t.Fatal("wrong TLS peer reached pprof HTTP, changed app profiler or retried")
	}
	var replay installedJourneyCaptureProgress
	read("get_capture", map[string]string{"capture_id": capture}, &replay)
	if replay.CaptureID != capture || replay.Phase != "Failed" || replay.CaseID != "" || len(replay.Actions) != 1 || replay.Actions[0] != progress.Actions[0] || state() != before {
		t.Fatal("TLS refusal passive replay changed original outcome or reached pprof")
	}
	t.Logf("installed TLS wrong peer: original Pod=%s capture=%s; independently approved Failed/ProfileUnavailable, zero pprof GET delta, no artifact/retry, retained admission/control charge; health/control8080 separate from TLS6060", uid, capture)
}
