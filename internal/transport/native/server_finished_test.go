package native_test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	native "asservat.local/asservat/internal/transport/native"
)

type finishedAdmission struct {
	finished *evidence.NativeParentFinished
}

func (a finishedAdmission) OpenNative(context.Context, *tls.ConnectionState, contracts.NativeHello) (native.Conversation, error) {
	return nil, fmt.Errorf("worker: %w", a.finished)
}

// A download worker whose parent session completed after serving gets the
// exact "finished" answer over the actual listener and client, so it stops
// cleanly instead of failing at native/open. Another worker's finished
// observation stays an ordinary refusal.
func TestNativeServeAnswersFinishedOnlyForTheExactWorker(t *testing.T) {
	for _, exact := range []bool{true, false} {
		t.Run(fmt.Sprint(exact), func(t *testing.T) {
			cert, clientCert, roots := testCertificates(t)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			worker := syntheticNativeIdle(t).Worker.Worker
			finished := &evidence.NativeParentFinished{}
			finished.Worker.Intent.ID, finished.Worker.Intent.SessionID, finished.Worker.Binding.InstallationID = worker.Intent.ID, worker.Intent.Parent.ID, worker.Binding.InstallationID
			if !exact {
				finished.Worker.Intent.ID = "22222222-2222-4222-8222-222222222222"
			}
			handler, err := native.NewHandler(contracts.NativeWorkerPath, listener.Addr().String(), finishedAdmission{finished}, 1)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			done := make(chan error, 1)
			go func() { done <- native.Serve(ctx, listener, roots, syntheticServingCertificate{cert}, handler, 1) }()
			defer func() { cancel(); <-done }()
			client, err := mtls.NewNativeClient("https://"+listener.Addr().String()+contracts.NativeWorkerPath, &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{clientCert}})
			if err != nil {
				t.Fatal(err)
			}
			stream, err := client.Open(ctx, workerHello())
			if stream != nil {
				stream.Close()
				t.Fatal("finished created a stream")
			}
			var got *contracts.NativeFinished
			if errors.As(err, &got) != exact {
				t.Fatalf("finished=%t error=%v", exact, err)
			}
			if exact && (got.Reference != workerHello().Reference || got.Nonce != workerHello().Nonce) {
				t.Fatal("finished identity changed")
			}
		})
	}
}
