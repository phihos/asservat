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
	"asservat.local/asservat/internal/application/sharing"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	capture "asservat.local/asservat/internal/domain/capture"
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

// consoleSyntheticShares is the test-only ADR-232 share service behind the
// actual browser route, CSRF/idempotency checks and canonical contracts. It
// grants nothing: recipient reads are not modeled here.
type consoleSyntheticShares struct {
	mu     sync.Mutex
	shares []authorization.Share
}

func (s *consoleSyntheticShares) Create(ctx context.Context, current app.CurrentIdentity, in sharing.CreateInput) (authorization.Share, bool, error) {
	i, err := current.ResolveIdentity(ctx)
	if err != nil {
		return authorization.Share{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if in.CaseID != consoleCaptureID(80) || in.ArtifactID != consoleCaptureID(81) || in.Version != (artifact.Digest{9}) || len(in.Recipients) != 1 || in.Recipients[0].Issuer != i.Principal.Issuer || in.ExpiresAt.After(time.Now().Add(7*24*time.Hour)) {
		return authorization.Share{}, false, capture.ErrInvalid
	}
	share := authorization.Share{ID: consoleCaptureID(600 + len(s.shares)), CaseID: in.CaseID, ArtifactID: in.ArtifactID, Creator: i.Principal, Recipients: in.Recipients, ExpiresAt: in.ExpiresAt, Revision: 1}
	s.shares = append(s.shares, share)
	return share, false, nil
}

func (s *consoleSyntheticShares) List(ctx context.Context, current app.CurrentIdentity, view string, _ int) ([]sharing.View, time.Time, error) {
	i, err := current.ResolveIdentity(ctx)
	if err != nil {
		return nil, time.Time{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []sharing.View{}
	for _, share := range s.shares {
		if view == "owned" {
			phase := authorization.ShareActive
			if share.Revision == 2 {
				phase = authorization.ShareRevoked
			}
			out = append(out, sharing.View{Share: share, Phase: phase})
		}
	}
	return out, i.ValidUntil, nil
}

func (s *consoleSyntheticShares) Revoke(_ context.Context, _ app.CurrentIdentity, id string, expected int64, _ string) (authorization.Share, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for n := range s.shares {
		if s.shares[n].ID == id && s.shares[n].Revision == expected {
			s.shares[n].Revision, s.shares[n].RevokedAt = 2, time.Now()
			return s.shares[n], false, nil
		}
	}
	return authorization.Share{}, false, capture.ErrConflict
}

// ListAdministered (ADR-238) is not modeled by this route test.
func (s *consoleSyntheticShares) ListAdministered(context.Context, app.CurrentIdentity, string, int) ([]sharing.View, string, time.Time, error) {
	return nil, "", time.Time{}, capture.ErrDenied
}

// Transfer (ADR-238) is not modeled by this route test.
func (s *consoleSyntheticShares) Transfer(context.Context, app.CurrentIdentity, sharing.TransferInput) (authorization.Share, bool, error) {
	return authorization.Share{}, false, capture.ErrDenied
}
