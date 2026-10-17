package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// OpenBao's KV-v2 upgradeCheck also guards freshly mounted backends. Poll only
// the read-only config route, never replay configuration or credential writes.
// https://github.com/openbao/openbao/blob/main/internal/builtin/logical/kv/upgrade.go
const kvFixtureUpgrading = "Upgrading from non-versioned to versioned data. This backend will be unavailable for a brief period and will resume service shortly."

func waitFixtureKV(ctx context.Context, endpoint, mount string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for attempt := 0; attempt < 40; attempt++ {
		r, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/v1/"+mount+"/config", nil)
		if err != nil {
			return errors.New("invalid fixture readiness request")
		}
		r.Header.Set("X-Vault-Token", "synthetic-root")
		response, err := client.Do(r)
		if err != nil {
			return errors.New("fixture readiness unavailable")
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, 4097))
		response.Body.Close()
		var out struct {
			Data   map[string]json.RawMessage `json:"data"`
			Errors []string                   `json:"errors"`
		}
		if err != nil || len(body) > 4096 || json.Unmarshal(body, &out) != nil {
			return errors.New("invalid fixture readiness response")
		}
		if response.StatusCode == 200 && out.Data != nil && len(out.Errors) == 0 {
			return nil
		}
		if response.StatusCode != 400 || len(out.Errors) != 1 || out.Errors[0] != kvFixtureUpgrading {
			return fmt.Errorf("fixture readiness rejected with status %d", response.StatusCode)
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return errors.New("fixture KV readiness exhausted")
}

func TestKVFixtureReadinessOnlyRetriesKnownReadOnlyStartup(t *testing.T) {
	for _, mode := range []string{"ready", "upgrade", "other-error", "forbidden", "malformed", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := calls.Add(1)
				if r.Method != http.MethodGet || r.URL.Path != "/v1/fixture/config" {
					t.Error("non-readiness operation")
				}
				if mode == "deadline" || mode == "upgrade" && n < 3 {
					w.WriteHeader(400)
					json.NewEncoder(w).Encode(map[string]any{"errors": []string{kvFixtureUpgrading}})
					return
				}
				switch mode {
				case "other-error":
					w.WriteHeader(400)
					w.Write([]byte(`{"errors":["invalid configuration"]}`))
				case "forbidden":
					w.WriteHeader(403)
				case "malformed":
					w.Write([]byte("broken"))
				default:
					w.Write([]byte(`{"data":{"cas_required":false,"max_versions":0}}`))
				}
			}))
			defer srv.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if mode == "deadline" {
				ctx, cancel = context.WithTimeout(ctx, 40*time.Millisecond)
				defer cancel()
			}
			err := waitFixtureKV(ctx, srv.URL, "fixture")
			good := mode == "ready" || mode == "upgrade"
			if (err == nil) != good {
				t.Fatal("unexpected readiness", err)
			}
			if mode == "upgrade" && calls.Load() != 3 {
				t.Fatal("upgrade not observed", calls.Load())
			}
			if mode != "upgrade" && mode != "deadline" && calls.Load() != 1 {
				t.Fatal("retried ordinary error", calls.Load())
			}
		})
	}
}
