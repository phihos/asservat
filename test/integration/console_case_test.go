package integration

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	app "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/catalog"
	"asservat.local/asservat/internal/domain/identity"
)

// Test-only C16 state qualifies browser rendering and real transport checks. It
// supplies no production permission, publication, audit or decryption authority.
// There is intentionally no download service or native byte success fixture.
type consoleSyntheticCases struct {
	mu        sync.Mutex
	state     string
	expiresAt time.Time
	calls     int
}

func (s *consoleSyntheticCases) GetContextCase(ctx context.Context, current app.CurrentIdentity, id string) (catalog.ContextCase, error) {
	started := time.Now()
	i, err := current.ResolveIdentity(ctx)
	if err != nil {
		return catalog.ContextCase{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.state != "ready" || id != consoleCaptureID(80) || !time.Now().Before(s.expiresAt) {
		return catalog.ContextCase{}, catalog.ErrUnavailable
	}
	until := identity.Earlier(started.Add(5*time.Second), identity.Earlier(i.ValidUntil, s.expiresAt))
	if ctx.Err() != nil || !time.Now().Before(until) {
		return catalog.ContextCase{}, catalog.ErrUnavailable
	}
	return catalog.ContextCase{CaseID: id, ObservedAt: started, ValidUntil: until, Artifacts: []catalog.ContextCaseArtifact{{ArtifactID: consoleCaptureID(81), CaptureID: consoleCaptureID(8), Target: authorization.Target{ClusterID: consoleCaptureID(1), NamespaceUID: "synthetic-namespace-uid", WorkloadUID: "synthetic-workload-uid", PodUID: "synthetic-pod-uid"}, Version: artifact.Digest{9}, ExpiresAt: s.expiresAt, DeleteBy: s.expiresAt.Add(5 * time.Minute)}}}, nil
}
func (s *consoleSyntheticCases) control(w http.ResponseWriter, r *http.Request, origin string) {
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("Content-Type", "application/json")
	if r.TLS == nil || "https://"+r.Host != origin || r.URL.RawQuery != "" {
		w.WriteHeader(400)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.URL.Path == "/test/evidence-stats" && r.Method == "GET" {
		_ = json.NewEncoder(w).Encode(map[string]any{"case_reads": s.calls})
		return
	}
	if r.URL.Path != "/test/evidence" || r.Method != "POST" || r.Header.Get("Origin") != origin {
		w.WriteHeader(403)
		return
	}
	var in struct {
		State       string `json:"state"`
		ExpiresInMS *int   `json:"expires_in_ms,omitempty"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	dec.DisallowUnknownFields()
	if dec.Decode(&in) != nil || !errors.Is(dec.Decode(new(any)), io.EOF) || in.ExpiresInMS != nil && (*in.ExpiresInMS < 1 || *in.ExpiresInMS > 120000) {
		w.WriteHeader(400)
		return
	}
	switch in.State {
	case "ready":
		s.state = "ready"
		s.expiresAt = time.Now().Add(time.Hour)
	case "unavailable", "revoked":
		s.state = in.State
	case "expired":
		s.state = "ready"
		s.expiresAt = time.Now().Add(-time.Second)
	default:
		w.WriteHeader(400)
		return
	}
	if in.ExpiresInMS != nil {
		s.expiresAt = time.Now().Add(time.Duration(*in.ExpiresInMS) * time.Millisecond)
	}
	w.WriteHeader(204)
}
