package bootstrap

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"time"
)

// HubAPIReadinessPort serves the kubelet's readiness probe (GET /readyz) on
// plain HTTP. It is bound only after the full composition has started and
// answers 200 only while the owner runtime is Ready (activated server and
// client keys and a current enrollment proof, rechecked every second), else
// 503. It carries no data and accepts no other path or method.
const HubAPIReadinessPort = 9449

func readinessHandler(ready func() bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/readyz" || r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.NotFound(w, r)
			return
		}
		if !ready() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
}

// serveReadiness serves the probe until ctx ends; the returned function
// stops it and waits for the server to return.
func serveReadiness(ctx context.Context, ready func() bool) (func(), error) {
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", net.JoinHostPort("", strconv.Itoa(HubAPIReadinessPort)))
	if err != nil {
		return nil, err
	}
	server := &http.Server{Handler: readinessHandler(ready), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 4 << 10}
	done := make(chan struct{})
	go func() { _ = server.Serve(listener); close(done) }()
	stop := context.AfterFunc(ctx, func() { _ = server.Close() })
	return func() { stop(); _ = server.Close(); <-done }, nil
}
