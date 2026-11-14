package kubernetes

import (
	"net/http"
	"time"
)

// Diagnostic only: actual production limiter and original proof interval are
// unchanged. The transport records closed operation classes/timing only; no
// URL, token, request/response body or private role state is printed.
type projectionTimingTransport struct {
	base    http.RoundTripper
	observe func(*http.Request, time.Duration, int, bool)
}

func (r projectionTimingTransport) RoundTrip(in *http.Request) (*http.Response, error) {
	start := time.Now()
	out, err := r.base.RoundTrip(in)
	status := 0
	if out != nil {
		status = out.StatusCode
	}
	r.observe(in, time.Since(start), status, err != nil)
	return out, err
}
