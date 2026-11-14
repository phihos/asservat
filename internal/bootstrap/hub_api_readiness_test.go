package bootstrap

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The probe answers 200 only while the runtime is Ready; other paths and
// methods are not served.
func TestHubAPIReadinessHandler(t *testing.T) {
	ready := false
	h := readinessHandler(func() bool { return ready })
	for _, c := range []struct {
		method, path string
		ready        bool
		want         int
	}{{http.MethodGet, "/readyz", false, http.StatusServiceUnavailable}, {http.MethodGet, "/readyz", true, http.StatusOK}, {http.MethodHead, "/readyz", true, http.StatusOK},
		{http.MethodPost, "/readyz", true, http.StatusNotFound}, {http.MethodGet, "/", true, http.StatusNotFound}} {
		ready = c.ready
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(c.method, c.path, nil))
		if w.Code != c.want || w.Body.Len() != 0 && c.want != http.StatusNotFound {
			t.Fatal(c, w.Code)
		}
	}
}
