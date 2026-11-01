package node

// This identical test-only helper is compiled separately against actual old
// and new production packages. Input is a bounded inherited descriptor, never
// argv; no copied decoder, product predicates or alternate transport exists.
import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"testing"
	"time"
)

func TestActualNodeVersionClientHelper(t *testing.T) {
	if os.Getenv("ASSERVAT_NODE_VERSION_HELPER") != "1" {
		t.Skip("owned version helper only")
	}
	in := os.NewFile(3, "private-node-helper-input")
	if in == nil {
		t.Fatal("private descriptor unavailable")
	}
	defer in.Close()
	data, err := io.ReadAll(io.LimitReader(in, 64<<10+1))
	if err != nil || len(data) > 64<<10 {
		t.Fatal("bounded helper input unavailable")
	}
	var input struct {
		Endpoint, ServerName, Roots, Certificate, Key, Epoch string
		After                                                uint64
	}
	if json.Unmarshal(data, &input) != nil {
		t.Fatal("helper input invalid")
	}
	clear(data)
	endpoint, err := url.Parse(input.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() != "127.0.0.1" {
		t.Fatal("helper loopback endpoint invalid")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(input.Roots)) {
		t.Fatal("helper roots invalid")
	}
	certificate, err := tls.X509KeyPair([]byte(input.Certificate), []byte(input.Key))
	if err != nil {
		t.Fatal("helper certificate invalid")
	}
	client, err := NewClient(input.Endpoint, input.ServerName, roots, func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &certificate, nil })
	if err != nil {
		t.Fatal("helper client construction refused")
	}
	defer client.CloseIdle()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	work, callErr := client.Poll(ctx, input.Epoch, input.After)
	observed, packetValid := false, false
	if len(work) == 1 && work[0].Packet != nil {
		packetValid = work[0].Packet.Valid()
		// Reporting only: actual Client.Poll/DomainWork above determines acceptance.
		// JSON lets the identical helper compile when the old type lacks this field.
		raw, err := json.Marshal(work[0].Packet)
		if err != nil {
			t.Fatal("helper report invalid")
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil {
			t.Fatal("helper report invalid")
		}
		v, ok := fields["Observation"]
		observed = ok && string(v) != "null"
	}
	result, _ := json.Marshal(struct {
		Accepted, Unavailable, Observed, PacketValid bool
		WorkCount                                    int
	}{callErr == nil, errors.Is(callErr, ErrUnavailable), observed, packetValid, len(work)})
	fmt.Fprintln(os.Stdout, "NODE_POLL_HELPER "+string(result))
}
