package kms

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
)

func bootstrapTestSlot(now time.Time) value.BootstrapSlot {
	id := "11111111-1111-4111-8111-111111111111"
	return value.BootstrapSlot{ID: "22222222-2222-4222-8222-222222222222", Binding: value.PeerBinding{InstallationID: id, ClusterID: id, PeerID: id, IssuerEpoch: id, Role: value.ConnectorPeer}, RequestDigest: artifact.Digest{1}, DeliveryProfile: "channel", NotBefore: now, NotAfter: now.Add(5 * time.Minute), CheckedAt: now, ValidUntil: now.Add(5 * time.Second)}
}
func TestBootstrapChannelRecordValidation(t *testing.T) {
	for _, mode := range []string{"valid", "future-soft-deletion", "wrong-scope", "case-alias", "binding-alias", "version", "deleted", "expired-read", "invalid-secret", "duplicate", "oversize", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Microsecond)
			slot := bootstrapTestSlot(now)
			secret := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
			b, _ := json.Marshal(bootstrapSecret{Binding: slotBinding(slot), Secret: secret})
			switch mode {
			case "wrong-scope":
				b = bytes.ReplaceAll(b, []byte(slot.Binding.ClusterID), []byte("33333333-3333-4333-8333-333333333333"))
			case "case-alias":
				b = bytes.Replace(b, []byte(`"secret"`), []byte(`"Secret"`), 1)
			case "binding-alias":
				b = bytes.Replace(b, []byte(`"installationID"`), []byte(`"InstallationID"`), 1)
			case "invalid-secret":
				b = bytes.Replace(b, []byte(secret), []byte("bad"), 1)
			case "duplicate":
				b = append([]byte(`{"secret":"duplicate",`), b[1:]...)
			case "oversize":
				b = append([]byte(strings.Repeat(" ", 16384)), b...)
			case "unknown":
				b = append([]byte(`{"extra":true,`), b[1:]...)
			}
			var clock atomic.Int64
			clock.Store(now.UnixNano())
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" {
					t.Error("attempted to replace existing credential")
					w.WriteHeader(403)
					return
				}
				if mode == "expired-read" {
					clock.Add(int64(5 * time.Second))
				}
				version := 1
				if mode == "version" {
					version = 2
				}
				deletion := ""
				if mode == "future-soft-deletion" {
					deletion = now.Add(time.Minute).Format(time.RFC3339Nano)
				}
				metadata, _ := json.Marshal(map[string]any{"version": version, "destroyed": mode == "deleted", "deletion_time": deletion})
				// Preserve deliberately duplicated and oversized record bytes.
				w.Write([]byte(`{"data":{"data":`))
				w.Write(b)
				w.Write([]byte(`,"metadata":`))
				w.Write(metadata)
				w.Write([]byte(`}}`))
			}))
			defer server.Close()
			channel, err := NewBootstrapChannel(server.URL, "synthetic-token", "kv", "prefix", "channel", slot.Binding.InstallationID, server.Client(), func() time.Time { return time.Unix(0, clock.Load()).UTC() })
			if err != nil {
				t.Fatal(err)
			}
			receipt, err := channel.EnsureBootstrapCredential(context.Background(), slot)
			if mode == "valid" || mode == "future-soft-deletion" {
				if err != nil || !receipt.Matches(slot) {
					t.Fatal(receipt, err)
				}
			} else if err == nil {
				t.Fatal("unsafe credential record accepted", mode)
			}
			if err != nil && strings.Contains(err.Error(), secret) {
				t.Fatal("secret leaked in error")
			}
			encoded, _ := json.Marshal(receipt)
			if bytes.Contains(encoded, []byte(secret)) {
				t.Fatal("secret in result")
			}
		})
	}
}
func TestBootstrapChannelCreateOnlyAndRecoverLostReply(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	slot := bootstrapTestSlot(now)
	var mu sync.Mutex
	var stored json.RawMessage
	var writes int
	var lost bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method == "POST" {
			writes++
			var v struct {
				Options struct {
					CAS int `json:"cas"`
				} `json:"options"`
				Data json.RawMessage `json:"data"`
			}
			if json.NewDecoder(r.Body).Decode(&v) != nil || v.Options.CAS != 0 {
				t.Error("bad create-only write")
				w.WriteHeader(400)
				return
			}
			if stored != nil {
				w.WriteHeader(403)
				return
			}
			stored = bytes.Clone(v.Data)
			if !lost {
				lost = true
				connection, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					connection.Close()
				}
				return
			}
		}
		if stored == nil {
			w.WriteHeader(404)
			return
		}
		w.Write([]byte(`{"data":{"data":`))
		w.Write(stored)
		w.Write([]byte(`,"metadata":{"version":1,"destroyed":false,"deletion_time":""}}}`))
	}))
	defer server.Close()
	channel, err := NewBootstrapChannel(server.URL, "synthetic-token", "kv", "prefix", "channel", slot.Binding.InstallationID, server.Client(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	first, err := channel.EnsureBootstrapCredential(context.Background(), slot)
	if err != nil {
		t.Fatal("lost reply was not resolved", err)
	}
	again, err := channel.EnsureBootstrapCredential(context.Background(), slot)
	if err != nil || again != first {
		t.Fatal("retry changed credential", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if writes != 1 {
		t.Fatal("POST retried", writes)
	}
}

func TestBootstrapChannelReadOriginalEnvelope(t *testing.T) {
	for _, mode := range []string{"valid", "future-soft-deletion", "wrong-id", "wrong-installation", "wrong-profile", "future-start", "expired", "expiry-after-read", "version", "destroyed", "deleted", "invalid-deletion", "missing", "alias", "duplicate", "oversize", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Microsecond)
			slot := bootstrapTestSlot(now)
			slot.DeliveryProfile = "regional-installer"
			secret := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
			record := bootstrapSecret{Binding: slotBinding(slot), Secret: secret}
			switch mode {
			case "wrong-id":
				record.Binding.BootstrapID = "33333333-3333-4333-8333-333333333333"
			case "wrong-installation":
				record.Binding.InstallationID = "33333333-3333-4333-8333-333333333333"
			case "wrong-profile":
				record.Binding.DeliveryProfile = "other"
			case "future-start":
				record.Binding.NotBefore = now.Add(time.Minute).Format(time.RFC3339Nano)
			case "expired":
				record.Binding.NotBefore = now.Add(-time.Minute).Format(time.RFC3339Nano)
				record.Binding.NotAfter = now.Format(time.RFC3339Nano)
			}
			body, _ := json.Marshal(record)
			switch mode {
			case "alias":
				body = bytes.Replace(body, []byte(`"secret"`), []byte(`"Secret"`), 1)
			case "duplicate":
				body = append([]byte(`{"secret":"duplicate",`), body[1:]...)
			case "oversize":
				body = append([]byte(strings.Repeat(" ", 16384)), body...)
			}
			var clock atomic.Int64
			clock.Store(now.UnixNano())
			var reads atomic.Int64
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reads.Add(1)
				if r.Method != "GET" || r.URL.Path != "/v1/kv/data/connector/"+slot.Binding.InstallationID+"/"+slot.ID || r.URL.RawQuery != "version=1" {
					t.Error("read selected a different record or effect")
					w.WriteHeader(400)
					return
				}
				if mode == "missing" {
					w.WriteHeader(404)
					return
				}
				if mode == "expiry-after-read" {
					clock.Add(int64(6 * time.Minute))
				}
				version := 1
				if mode == "version" {
					version = 2
				}
				deletion := ""
				switch mode {
				case "deleted":
					deletion = now.Format(time.RFC3339Nano)
				case "invalid-deletion":
					deletion = "broken"
				case "future-soft-deletion":
					deletion = now.Add(time.Minute).Format(time.RFC3339Nano)
				}
				metadata, _ := json.Marshal(map[string]any{"version": version, "destroyed": mode == "destroyed", "deletion_time": deletion})
				w.Write([]byte(`{"data":{"data":`))
				w.Write(body)
				w.Write([]byte(`,"metadata":`))
				w.Write(metadata)
				w.Write([]byte(`}}`))
			}))
			defer server.Close()
			channel, err := NewBootstrapChannel(server.URL, "synthetic-token", "kv", "connector", slot.DeliveryProfile, slot.Binding.InstallationID, server.Client(), func() time.Time { return time.Unix(0, clock.Load()).UTC() })
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if mode == "cancelled" {
				cancel()
			}
			got, err := channel.ReadBootstrapEnvelope(ctx, slot.ID)
			if mode == "valid" || mode == "future-soft-deletion" {
				if err != nil || !got.Valid() || got.BootstrapID != slot.ID || got.Binding != slot.Binding || got.RequestDigest != slot.RequestDigest || got.NotBefore != slot.NotBefore || got.NotAfter != slot.NotAfter || got.Secret != secret {
					t.Fatal("original record changed or unavailable", err)
				}
			} else if err == nil {
				t.Fatal("invalid or changed bootstrap record accepted")
			}
			if err != nil && strings.Contains(err.Error(), secret) {
				t.Fatal("secret leaked")
			}
			want := int64(1)
			if mode == "cancelled" {
				want = 0
			}
			if reads.Load() != want {
				t.Fatal("unexpected retry or create", reads.Load())
			}
		})
	}
}
