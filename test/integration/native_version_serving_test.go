package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net"
	"os"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/authorization"
	native "asservat.local/asservat/internal/transport/native"
)

// The old roles are actual separately linked processes; synthetic admission
// facts do not qualify protected peer/issuer discovery or installed draining.
func TestNativeActualVersionServingWire(t *testing.T) {
	manifest := nativeVersionManifestFor(t)
	for _, role := range []string{"hub", "connector"} {
		for _, duration := range []time.Duration{3 * time.Second, 20 * time.Second} {
			name := role + "/short"
			if duration == 20*time.Second {
				name = role + "/long-refusal"
			}
			t.Run(name, func(t *testing.T) {
				started := time.Now()
				ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
				defer cancel()
				const size = 64 << 10
				source, operation, lease, delivery, command := nativeVersionOperation(t, duration, size)
				id, now := operation.Reference.InstallationID, operation.StartedAt
				keys := nativeVersionCertificates(t, id)
				workerCertificate := keys.certificateForPeer(t, "acquisition", id)
				connectorCertificate := keys.certificateForPeer(t, "connector", id)
				serverCertificate, serverKey := nativeVersionCertificatePEM(t, keys.certificate(t, "server"))
				roots := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: keys.root.Raw})
				old := nativeVersionInput{Action: role, Roots: roots, ServerCertificate: serverCertificate, ServerKey: serverKey, ExpectedPeer: sha256.Sum256(workerCertificate.Certificate[0]), Operation: operation, Lease: lease, Delivery: delivery, Command: command, Source: source, BodyBytes: size}
				var hub *native.HubOperation
				if role == "connector" {
					gate, err := evidence.NewNativeFrameGate(ctx, func(context.Context) (value.NativeLease, error) { return lease, nil }, time.Now)
					if err != nil {
						t.Fatal(err)
					}
					defer func() { gate.Close(); _ = gate.Wait(context.Background()) }()
					hub, err = native.NewHubResponseOperation(gate, command, source, delivery, func(context.Context, value.NativeLease) error { return nil })
					if err != nil {
						t.Fatal(err)
					}
					defer hub.Close()
					endpoint, closeServer := nativeVersionServer(t, ctx, hub, command.Reference, keys, connectorCertificate, contracts.NativeOwnerPath)
					defer closeServer()
					old.Endpoint = endpoint
					old.Certificate, old.PrivateKey = nativeVersionCertificatePEM(t, connectorCertificate)
				}
				endpoint, listenerFile := nativeVersionInheritedListener(t)
				defer listenerFile.Close()
				certificate, privateKey := nativeVersionCertificatePEM(t, workerCertificate)
				warmup := operation
				warmup.Kind, warmup.Until = value.NativePrepare, now.Add(3*time.Second)
				worker := nativeVersionInput{Action: "worker", Endpoint: endpoint, Roots: roots, Certificate: certificate, PrivateKey: privateKey, Hello: contracts.NativeHello{Format: contracts.NativeExchangeFormat, Reference: contracts.NativeReference{InstallationID: id, SessionID: id, WorkerID: id}, Nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", WorkerToken: []byte("synthetic.native.token")}, Worker: value.WorkerCredentialTarget{InstallationID: id, SessionID: id, WorkerID: id, PodUID: id, CreatedAt: now, RunUntil: now.Add(time.Minute)}, WorkerKey: operation.WorkerPublicKey, Source: source, Warmup: &warmup, BodyBytes: size}
				// The listener already exists before either process starts; backlog queues
				// the first TLS connection without readiness polls or a free-port race.
				oldDone := nativeVersionAsync(ctx, manifest.Binaries["old"], old, listenerFile)
				workerDone := nativeVersionAsync(ctx, manifest.Binaries["new"], worker)
				oldJoined, workerJoined := false, false
				defer func() {
					cancel()
					if !oldJoined {
						<-oldDone
					}
					if !workerJoined {
						<-workerDone
					}
				}()
				var delivered, acknowledged int64
				if role == "connector" && duration == 3*time.Second {
					chunk, err := hub.ReadChunk(ctx, delivery, 0, size)
					if err != nil || !bytes.Equal(chunk.Bytes, nativeVersionBody(0, size)) {
						clear(chunk.Bytes)
						t.Fatal("connector exact native body", err)
					}
					delivered = int64(len(chunk.Bytes))
					clear(chunk.Bytes)
					if err = hub.AcknowledgeNativeChunk(ctx, delivery, 0, size); err != nil {
						t.Fatal("connector final sink acknowledgement", err)
					}
					acknowledged++
				}
				oldResult := <-oldDone
				oldJoined = true
				workerResult := <-workerDone
				workerJoined = true
				if oldResult.err != nil || workerResult.err != nil {
					t.Fatal("version subprocess result", oldResult.err, workerResult.err)
				}
				out, w := oldResult.output, workerResult.output
				encoded, _ := json.Marshal(operation)
				sum := sha256.Sum256(encoded)
				if out.OperationSHA256 != hex.EncodeToString(sum[:]) || out.Stage != "serve" || out.AuthenticatedRequests != 1 {
					t.Fatal("old role did not bind the exact operation and authenticated request", out)
				}
				if role == "hub" {
					delivered, acknowledged = out.DeliveredBytes, out.AcknowledgedChunks
				}
				t.Logf("oldRole=%s operationSHA256=%s construction=%s/%s/%s authenticatedRequests=%d upstreamOpens=%d deliveredBytes=%d acknowledgedChunks=%d oldAccepted=%t oldClass=%s workerStage=%s workerAccepted=%t workerClass=%s readerCalls=%d dataFrames=%d dataBytes=%d elapsed=%s", role, out.OperationSHA256, out.ConstructionStage, out.ConstructionClass, out.ConstructionStep, out.AuthenticatedRequests, out.UpstreamOpens, delivered, acknowledged, out.Accepted, out.ErrorClass, w.Stage, w.Accepted, w.ErrorClass, w.ReaderCalls, w.DataFrames, w.DataBytes, time.Since(started))
				if duration == 20*time.Second {
					if out.Accepted || out.ConstructionStage != "gate" || out.ConstructionClass != "unavailable" || out.ConstructionStep != "operation" || out.ErrorClass != "unavailable" || out.UpstreamOpens != 0 || delivered != 0 || acknowledged != 0 || w.Accepted || w.Stage != "open" || w.ReaderCalls != 1 || w.DataFrames != 0 || w.DataBytes != 0 {
						t.Fatal("old role did not preserve its earliest actual refusal", out, w)
					}
					return
				}
				wantStage, wantOpens := "hub", int64(0)
				if role == "connector" {
					wantStage, wantOpens = "gate", 1
				}
				if !out.Accepted || out.ConstructionStage != wantStage || out.ConstructionClass != "none" || out.ConstructionStep != "" || out.ErrorClass != "none" || out.UpstreamOpens != wantOpens || delivered != size || acknowledged != 1 || !w.Accepted || w.NativeState != contracts.NativeJoined || w.ReaderCalls != 2 || w.DataFrames != 1 || w.DataBytes != size {
					t.Fatal("old role short positive did not deliver, acknowledge and join", out, w)
				}
			})
		}
	}
}

type nativeVersionOutcome struct {
	output nativeVersionOutput
	err    error
}

func nativeVersionAsync(ctx context.Context, binary nativeVersionBinary, input nativeVersionInput, files ...*os.File) <-chan nativeVersionOutcome {
	done := make(chan nativeVersionOutcome, 1)
	go func() {
		out, err := invokeNativeVersion(ctx, binary, input, files...)
		done <- nativeVersionOutcome{out, err}
	}()
	return done
}
func nativeVersionCertificatePEM(t *testing.T, certificate tls.Certificate) ([]byte, []byte) {
	t.Helper()
	key, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})
}
func nativeVersionInheritedListener(t *testing.T) (string, *os.File) {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	file, err := listener.File()
	if err != nil {
		t.Fatal(err)
	}
	return "https://" + listener.Addr().String() + contracts.NativeWorkerPath, file
}
