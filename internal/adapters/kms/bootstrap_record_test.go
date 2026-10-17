package kms

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
)

// ADR-193 step 5: the operator's KV record becomes the connector envelope
// exactly; aliases, extra fields and a malformed secret are refused.
func TestDecodeBootstrapRecord(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	slot := value.BootstrapSlot{ID: "10000000-0000-4000-8000-000000000001", Binding: value.PeerBinding{InstallationID: "10000000-0000-4000-8000-000000000002", ClusterID: "10000000-0000-4000-8000-000000000003", PeerID: "10000000-0000-4000-8000-000000000004", IssuerEpoch: "10000000-0000-4000-8000-000000000005", Role: value.ConnectorPeer},
		RequestDigest: artifact.Digest{7}, DeliveryProfile: "regional-installer", NotBefore: now, NotAfter: now.Add(5 * time.Minute)}
	secret := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	raw, _ := json.Marshal(bootstrapSecret{Binding: slotBinding(slot), Secret: secret})
	e, err := DecodeBootstrapRecord(raw)
	if err != nil || e.BootstrapID != slot.ID || e.Binding != slot.Binding || e.RequestDigest != slot.RequestDigest || !e.NotAfter.Equal(slot.NotAfter) || e.Secret != secret {
		t.Fatal("record not decoded exactly", err)
	}
	for _, bad := range [][]byte{
		bytes.Replace(raw, []byte(`"bootstrapID"`), []byte(`"BootstrapID"`), 1),
		bytes.Replace(raw, []byte(`"secret":`), []byte(`"extra":1,"secret":`), 1),
		bytes.Replace(raw, []byte(secret), []byte("short"), 1),
	} {
		if _, err := DecodeBootstrapRecord(bad); err == nil {
			t.Fatal("malformed record accepted", string(bad[:40]))
		}
	}
}
