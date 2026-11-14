package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

func fastStartupWait(t *testing.T) {
	first, max := startupWaitFirst, startupWaitMax
	startupWaitFirst, startupWaitMax = time.Millisecond, 4*time.Millisecond
	t.Cleanup(func() { startupWaitFirst, startupWaitMax = first, max })
}

func TestWaitStartupRetriesUnavailableAndLogsRecovery(t *testing.T) {
	fastStartupWait(t)
	var lines []string
	n := 0
	err := waitStartup(t.Context(), "demo", func(s string) { lines = append(lines, s) }, func(context.Context) error {
		if n++; n < 4 {
			return &fixedStepError{"offer", &fixedStepError{"pending", mounts.ErrUnavailable}}
		}
		return nil
	}, nil)
	if err != nil || n != 4 {
		t.Fatal(err, n)
	}
	want := []string{"startup demo: waiting at offer/pending (unavailable), retrying with backoff", "startup demo: ok after 3 failed attempts"}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("lines %q", lines)
	}
}

func TestWaitStartupKeepsInvalidConfigurationFatal(t *testing.T) {
	fastStartupWait(t)
	n := 0
	err := waitStartup(t.Context(), "demo", nil, func(context.Context) error { n++; return &fixedStepError{"config", cfg.ErrInvalid} }, nil)
	if !errors.Is(err, cfg.ErrInvalid) || n != 1 {
		t.Fatal(err, n)
	}
}

func TestWaitStartupStopsWithContext(t *testing.T) {
	fastStartupWait(t)
	ctx, cancel := context.WithCancel(t.Context())
	n := 0
	err := waitStartup(ctx, "demo", nil, func(context.Context) error {
		if n++; n == 3 {
			cancel()
		}
		return mounts.ErrUnavailable
	}, nil)
	if err == nil || n != 3 {
		t.Fatal(err, n)
	}
}

// Issue 3: Helm renders the combined-mode offer ConfigMap empty and the
// hub-api fills it later. The connector waits for it instead of exiting; a
// written but malformed offer stays fatal.
func TestCombinedOfferWaitsUntilTheHubWritesIt(t *testing.T) {
	fastStartupWait(t)
	offer := connectorTestOffer(t, nil)
	raw, _ := json.Marshal(offer)
	var reads atomic.Int32
	var body atomic.Value
	body.Store("")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n := reads.Add(1); n == 1 {
			http.NotFound(w, r) // the release has not rendered it yet
			return
		} else if n == 4 {
			body.Store(string(raw))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(core.ConfigMap{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}, ObjectMeta: meta.ObjectMeta{Name: "asservat-regional-offer"}, Data: map[string]string{contracts.RegionalOfferFile: body.Load().(string)}})
	}))
	defer server.Close()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, contracts.ConnectorKubeTokenFile), []byte("synthetic-only"), 0600); err != nil {
		t.Fatal(err)
	}
	files, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer files.Close()
	in := &providerInputs{files: files, kubernetesEndpoint: contracts.OwnerProviderEndpoint{Endpoint: server.URL, Roots: [][]byte{server.Certificate().Raw}}}
	var lines []string
	var got contracts.RegionalOffer
	err = waitStartup(t.Context(), "connector", func(s string) { lines = append(lines, s) }, func(ctx context.Context) (err error) {
		got, err = readCombinedOffer(ctx, in, "asservat-region", "asservat-regional-offer")
		return err
	}, nil)
	if err != nil || got.InstallationID != offer.InstallationID || reads.Load() != 4 {
		t.Fatal("offer wait", err, reads.Load())
	}
	if len(lines) != 3 || !strings.Contains(lines[0], "get/404") || !strings.Contains(lines[1], "at pending") || !strings.Contains(lines[2], "ok after 3") {
		t.Fatalf("lines %q", lines)
	}
	body.Store("{not json")
	if _, err = readCombinedOffer(t.Context(), in, "asservat-region", "asservat-regional-offer"); !errors.Is(err, cfg.ErrInvalid) || startupRetryable(err) {
		t.Fatal("malformed offer retried", err)
	}
}
