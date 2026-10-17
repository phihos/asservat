package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"github.com/google/uuid"
)

func TestBootstrapChannelWithRealOpenBao(t *testing.T) {
	path := os.Getenv("ASSERVAT_FLEET_FIXTURES")
	if path == "" {
		t.Skip("run make fleet-integration")
	}
	var f fixture
	b, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(b, &f) != nil {
		t.Fatal("fixture unavailable")
	}
	request(t, f.KMS, "synthetic-root", "sys/mounts/bootstrap-kv", map[string]any{"type": "kv", "options": map[string]string{"version": "2"}}, 204)
	if err = waitFixtureKV(context.Background(), f.KMS, "bootstrap-kv"); err != nil {
		t.Fatal(err)
	}
	request(t, f.KMS, "synthetic-root", "bootstrap-kv/config", map[string]any{"cas_required": true, "max_versions": 1, "delete_version_after": "5m"}, 204)
	installation := uuid.NewString()
	policy := `path "bootstrap-kv/data/connector/` + installation + `/*" { capabilities=["create","read"] }`
	request(t, f.KMS, "synthetic-root", "sys/policies/acl/bootstrap-channel", map[string]any{"policy": policy}, 204)
	token := request(t, f.KMS, "synthetic-root", "auth/token/create", map[string]any{"policies": []string{"bootstrap-channel"}, "no_default_policy": true, "ttl": "15m"}, 200)["auth"].(map[string]any)["client_token"].(string)
	bridge := tlsBridge(t, f.KMS)
	channel, err := kms.NewBootstrapChannel(bridge.URL, token, "bootstrap-kv", "connector", "ops", installation, bridge.Client(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	slot := value.BootstrapSlot{ID: uuid.NewString(), Binding: value.PeerBinding{InstallationID: installation, ClusterID: uuid.NewString(), PeerID: uuid.NewString(), IssuerEpoch: uuid.NewString(), Role: value.ConnectorPeer}, RequestDigest: artifact.Digest{1}, DeliveryProfile: "ops", NotBefore: now, NotAfter: now.Add(5 * time.Minute), CheckedAt: now, ValidUntil: now.Add(5 * time.Second)}
	ctx := context.Background()
	var wg sync.WaitGroup
	var mu sync.Mutex
	var receipts []value.BootstrapCredential
	for range 8 {
		wg.Go(func() {
			r, err := channel.EnsureBootstrapCredential(ctx, slot)
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			receipts = append(receipts, r)
			mu.Unlock()
		})
	}
	wg.Wait()
	if len(receipts) != 8 {
		t.Fatal("concurrent credential creation failed")
	}
	for _, r := range receipts {
		if r != receipts[0] || !r.Matches(slot) {
			t.Fatal("concurrent request changed credential")
		}
	}
	get := func(path string) map[string]any {
		t.Helper()
		r, err := http.NewRequestWithContext(ctx, http.MethodGet, bridge.URL+"/v1/"+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("X-Vault-Token", "synthetic-root")
		response, err := bridge.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != 200 {
			t.Fatal("fixture GET", response.StatusCode)
		}
		var body map[string]any
		if json.NewDecoder(io.LimitReader(response.Body, 16384)).Decode(&body) != nil {
			t.Fatal("invalid fixture GET")
		}
		return body["data"].(map[string]any)
	}
	key := "connector/" + installation + "/" + slot.ID
	stored := get("bootstrap-kv/data/" + key)
	record := stored["data"].(map[string]any)
	secret, ok := record["secret"].(string)
	if !ok {
		t.Fatal("credential missing")
	}
	digest, err := mtls.BootstrapDigest(installation, slot.ID, secret)
	if err != nil || digest != receipts[0].SecretDigest {
		t.Fatal("wrong credential digest", err)
	}
	if stored["metadata"].(map[string]any)["version"].(float64) != 1 {
		t.Fatal("retry created another secret version")
	}
	t.Run("immutable-channel-role-and-binding", func(t *testing.T) {
		request(t, f.KMS, token, "bootstrap-kv/data/"+key, map[string]any{"options": map[string]int{"cas": 1}, "data": record}, 403)
		request(t, f.KMS, token, "bootstrap-kv/destroy/"+key, map[string]any{"versions": []int{1}}, 403)
		request(t, f.KMS, token, "bootstrap-kv/metadata/"+key, map[string]any{"max_versions": 2}, 403)
		changed := slot
		changed.RequestDigest[0]++
		if _, err := channel.EnsureBootstrapCredential(ctx, changed); err == nil {
			t.Fatal("rebound existing credential")
		}
		changed = slot
		changed.NotAfter = changed.NotAfter.Add(-time.Second)
		if _, err := channel.EnsureBootstrapCredential(ctx, changed); err == nil {
			t.Fatal("rewrote original expiry")
		}
	})
	t.Run("replaced-version-rejected", func(t *testing.T) {
		request(t, f.KMS, "synthetic-root", "bootstrap-kv/data/"+key, map[string]any{"options": map[string]int{"cas": 1}, "data": record}, 200)
		if _, err := channel.EnsureBootstrapCredential(ctx, slot); err == nil {
			t.Fatal("replacement version accepted")
		}
	})
	t.Run("deleted-credential-is-not-recreated", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Microsecond)
		second := slot
		second.ID = uuid.NewString()
		second.CheckedAt = now
		second.ValidUntil = now.Add(5 * time.Second)
		if _, err := channel.EnsureBootstrapCredential(ctx, second); err != nil {
			t.Fatal(err)
		}
		path := "connector/" + installation + "/" + second.ID
		request(t, f.KMS, "synthetic-root", "bootstrap-kv/delete/"+path, map[string]any{"versions": []int{1}}, 204)
		if _, err := channel.EnsureBootstrapCredential(ctx, second); err == nil {
			t.Fatal("soft-deleted credential recreated")
		}
		metadata := get("bootstrap-kv/metadata/" + path)
		if metadata["current_version"].(float64) != 1 {
			t.Fatal("deletion created new version")
		}
	})
	t.Run("expiry-and-provider-revocation", func(t *testing.T) {
		bad := slot
		bad.ValidUntil = bad.CheckedAt
		if _, err := channel.EnsureBootstrapCredential(ctx, bad); err == nil {
			t.Fatal("expired instruction accepted")
		}
		request(t, f.KMS, "synthetic-root", "auth/token/revoke", map[string]any{"token": token}, 204)
		bad = slot
		bad.ID = uuid.NewString()
		bad.CheckedAt = time.Now().UTC()
		bad.ValidUntil = bad.CheckedAt.Add(5 * time.Second)
		if _, err := channel.EnsureBootstrapCredential(ctx, bad); err == nil {
			t.Fatal("revoked provider role created a credential")
		}
	})
}
