package node

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/domain/collector"
)

type streamAttester struct{ reviews atomic.Int32 }

func (a *streamAttester) AttestNode(_ context.Context, token []byte) (collector.Identity, error) {
	a.reviews.Add(1)
	if string(token) != "token" {
		return collector.Identity{}, delivery.ErrNodeDenied
	}
	return collector.Identity{NodeName: "node-a", NodeUID: "node-uid", PodName: "collector", PodUID: "pod-uid", BootID: "boot"}, nil
}

func TestStreamPushesWorkAndReviewsTokenOncePerConnection(t *testing.T) {
	ch, err := delivery.NewNodeChannel(time.Now, nil)
	if err != nil {
		t.Fatal(err)
	}
	attester := &streamAttester{}
	h, err := NewHandler(ch, attester)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(h)
	server.EnableHTTP2 = true
	server.Config.ConnContext = ConnContext
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	token := "token"
	client, err := NewClient(server.URL, "example.com", roots, func(context.Context) ([]byte, error) { return []byte(token), nil })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	stream, err := client.Connect(ctx, []collector.WorkKind{collector.WorkStopSource})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	r := sampleReport()
	r.Receipts = nil
	if err := stream.Status(r); err != nil {
		t.Fatal(err)
	}
	for n := 0; len(ch.Nodes()) == 0 || !ch.Nodes()[0].Current; n++ {
		if n > 500 {
			t.Fatal("status did not arrive")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := ch.Enqueue("node-uid", collector.WorkSnapshot, time.Now().Add(time.Minute)); !errors.Is(err, delivery.ErrNodeUnavailable) {
		t.Fatalf("unannounced kind queued: %v", err)
	}
	w, err := ch.Enqueue("node-uid", collector.WorkStopSource, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	got, err := stream.Receive()
	if err != nil || got.ID != w.ID || got.Kind != collector.WorkStopSource {
		t.Fatalf("pushed work: %+v %v", got, err)
	}
	// An upload on the same connection reuses the stream's review.
	if err := client.UploadCapture(ctx, collector.PacketResult{WorkID: w.ID, CaptureID: w.ID}, nil); err == nil {
		t.Fatal("a capture nobody queued was accepted")
	}
	if n := attester.reviews.Load(); n != 1 {
		t.Fatalf("token reviews on one connection: %d", n)
	}
	token = "other"
	if _, err := client.Connect(ctx, nil); !errors.Is(err, ErrRefused) {
		t.Fatalf("denied token: %v", err)
	}
}
