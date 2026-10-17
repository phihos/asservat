package bootstrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
)

func startupFixture(t *testing.T) (WorkerStartup, []byte, []string) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	id := "10000000-0000-4000-8000-000000000001"
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic-startup-ca"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	wire := contracts.WorkerControl{Format: contracts.WorkerControlFormat, InstallationID: id, ClusterID: id, Endpoint: "https://control.invalid", ServerRoots: [][]byte{der}, IssuerRoots: [][]byte{der}}
	raw, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := mtls.WorkerControlDigest(map[string]string{"worker.json": string(raw)})
	if err != nil {
		t.Fatal(err)
	}
	input := WorkerStartup{Target: value.WorkerCredentialTarget{InstallationID: id, SessionID: id, WorkerID: id, PodUID: id, CreatedAt: now, RunUntil: now.Add(time.Minute)}, ClusterID: id, ControlDigest: digest}
	args := []string{"--installation", id, "--cluster", id, "--dispatch", id, "--session", id, "--created-at", now.Format(time.RFC3339Nano), "--until", input.Target.RunUntil.Format(time.RFC3339Nano), "--control-sha256", hex.EncodeToString(digest[:]), "--control", contracts.WorkerControlPath, "--token", contracts.WorkerTokenPath}
	return input, raw, args
}
func TestWorkerStartupExactArgumentsAndConfigPin(t *testing.T) {
	input, raw, args := startupFixture(t)
	got, err := ParseWorkerStartup(args, input.Target.PodUID)
	if err != nil || got != input {
		t.Fatal(err)
	}
	if _, err := LoadWorkerTrust(got, raw, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"missing-pod", "duplicate", "path", "alternate-flag", "positional", "date", "unknown", "digest"} {
		t.Run(name, func(t *testing.T) {
			a := append([]string(nil), args...)
			pod := input.Target.PodUID
			switch name {
			case "missing-pod":
				pod = ""
			case "duplicate":
				a[2] = a[0]
			case "path":
				a[len(a)-1] = "/var/run/secrets/kubernetes.io/serviceaccount/token"
			case "alternate-flag":
				a[0] = "-installation"
			case "positional":
				a = append(a, "payload")
			case "date":
				a[9] = "2026-10-10T12:00:00+00:00"
			case "unknown":
				a[0] = "--credential"
			case "digest":
				a[13] = "0"
			}
			if _, err := ParseWorkerStartup(a, pod); err == nil {
				t.Fatal("invalid startup accepted")
			}
		})
	}
	for _, name := range []string{"digest", "installation", "cluster", "expired-root", "changed-bytes"} {
		t.Run(name, func(t *testing.T) {
			in := input
			b := append([]byte(nil), raw...)
			now := time.Now()
			switch name {
			case "digest":
				in.ControlDigest = artifact.Digest{1}
			case "installation":
				in.Target.InstallationID = "20000000-0000-4000-8000-000000000002"
			case "cluster":
				in.ClusterID = "20000000-0000-4000-8000-000000000002"
			case "expired-root":
				now = now.Add(2 * time.Hour)
			case "changed-bytes":
				b = append(b, ' ')
			}
			if _, err := LoadWorkerTrust(in, b, now); err == nil {
				t.Fatal("changed/expired config accepted")
			}
		})
	}
}
func TestWorkerWaitCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if waitWorker(ctx, time.Hour) == nil {
		t.Fatal("cancelled wait")
	}
}

func TestWorkerControlRejectsUntrustedPayloads(t *testing.T) {
	input, raw, _ := startupFixture(t)
	var original contracts.WorkerControl
	if json.Unmarshal(raw, &original) != nil {
		t.Fatal("fixture")
	}
	for _, mode := range []string{"unknown", "duplicate", "private-key", "empty-roots", "duplicate-roots", "too-many-roots", "not-a-certificate", "callback-path", "credentials", "http", "fragment", "empty-fragment", "query", "empty-query", "wrong-format", "missing"} {
		t.Run(mode, func(t *testing.T) {
			wire := original
			b := append([]byte(nil), raw...)
			switch mode {
			case "unknown", "private-key":
				b = append(b[:len(b)-1], []byte(",\"privateKey\":\"forbidden\"}")...)
			case "duplicate":
				b = append(b[:len(b)-1], []byte(",\"format\":\"asservat-worker-control/v1\"}")...)
			case "missing":
				b = []byte("{}")
			default:
				switch mode {
				case "empty-roots":
					wire.ServerRoots = nil
				case "duplicate-roots":
					wire.IssuerRoots = append(wire.IssuerRoots, wire.IssuerRoots[0])
				case "too-many-roots":
					wire.ServerRoots = [][]byte{wire.ServerRoots[0], wire.ServerRoots[0], wire.ServerRoots[0], wire.ServerRoots[0], wire.ServerRoots[0]}
				case "not-a-certificate":
					wire.IssuerRoots = [][]byte{[]byte("synthetic")}
				case "callback-path":
					wire.Endpoint += "/chosen-by-caller"
				case "credentials":
					wire.Endpoint = "https://token@control.invalid"
				case "http":
					wire.Endpoint = "http://control.invalid"
				case "fragment":
					wire.Endpoint += "#fragment"
				case "empty-fragment":
					wire.Endpoint += "#"
				case "query":
					wire.Endpoint += "?query"
				case "empty-query":
					wire.Endpoint += "?"
				case "wrong-format":
					wire.Format = "other"
				}
				b, _ = json.Marshal(wire)
			}
			if _, err := mtls.WorkerControlDigest(map[string]string{"worker.json": string(b)}); err == nil {
				t.Fatal("invalid control payload admitted")
			}
			if _, err := LoadWorkerTrust(input, b, time.Now()); err == nil {
				t.Fatal("invalid control payload loaded")
			}
		})
	}
}
