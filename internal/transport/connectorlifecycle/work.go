package connectorlifecycle

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// A hint opens an authenticated exchange to the owner waiting for this
// cluster. It carries neither command parameters nor execution authority.
const WorkPath = "/v1/connector-work"

type WorkHint struct {
	Cluster string
	Owner   fleet.OwnerBinding
	Until   time.Time
}

func (h WorkHint) valid() bool {
	return authorization.UUID(h.Cluster) && h.Owner.Valid() && time.Now().Before(h.Until)
}

type workSubscriber struct {
	hints  chan WorkHint
	resync chan struct{}
}

// WorkHandler fans out the federation's database subscription to registered
// connectors. On subscription or database reconnect, owners reannounce only
// the work for this cluster that they are still waiting to run.
type WorkHandler struct {
	Tokens      TunnelTokens
	Ready       func(context.Context, string) error
	Concurrency int
	mu          sync.Mutex
	subscribers map[string]map[*workSubscriber]bool
}

func (h *WorkHandler) Publish(payload string) {
	var hint WorkHint
	if payload != "" && (json.Unmarshal([]byte(payload), &hint) != nil || !hint.valid()) {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if payload == "" {
		// LISTEN is established. Notifications sent during a disconnection
		// may have been missed, including the first notification at startup.
		for _, subscribers := range h.subscribers {
			for sub := range subscribers {
				select {
				case sub.resync <- struct{}{}:
				default:
				}
			}
		}
		return
	}
	for sub := range h.subscribers[hint.Cluster] {
		select {
		case sub.hints <- hint:
		default:
			// A slow stream drains its accepted hints, then reconnects for
			// remaining demand. It cannot stall another cluster or grow an
			// unbounded queue in the federation.
			delete(h.subscribers[hint.Cluster], sub)
			close(sub.hints)
		}
	}
}

func (h *WorkHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if h == nil || h.Tokens == nil || h.Ready == nil || h.Concurrency < 1 || r.ProtoMajor != 2 || r.Method != http.MethodPost || r.URL.Path != WorkPath || r.URL.RawQuery != "" || len(r.Header.Values("Authorization")) != 1 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	check, stop := context.WithTimeout(r.Context(), 5*time.Second)
	cluster, until, err := h.Tokens.VerifyConnectorUntil(check, token)
	stop()
	if err != nil || !authorization.UUID(cluster.ClusterID) || !time.Now().Before(until) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	ctx, cancel := context.WithDeadline(r.Context(), until)
	defer cancel()
	sub := &workSubscriber{hints: make(chan WorkHint, h.Concurrency), resync: make(chan struct{}, 1)}
	h.mu.Lock()
	if h.subscribers == nil {
		h.subscribers = make(map[string]map[*workSubscriber]bool)
	}
	if h.subscribers[cluster.ClusterID] == nil {
		h.subscribers[cluster.ClusterID] = make(map[*workSubscriber]bool)
	}
	h.subscribers[cluster.ClusterID][sub] = true
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		delete(h.subscribers[cluster.ClusterID], sub)
		if len(h.subscribers[cluster.ClusterID]) == 0 {
			delete(h.subscribers, cluster.ClusterID)
		}
	}()
	// Register before asking owners for pending work so their response can
	// arrive immediately, even before the HTTP stream has flushed its headers.
	ready := func() error {
		announce, end := context.WithTimeout(ctx, 5*time.Second)
		defer end()
		return h.Ready(announce, cluster.ClusterID)
	}
	if ready() != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", ContentType)
	control := http.NewResponseController(w)
	if control.SetWriteDeadline(until) != nil || control.Flush() != nil {
		return
	}
	enc := json.NewEncoder(w)
	for ctx.Err() == nil {
		select {
		case <-ctx.Done():
			return
		case <-sub.resync:
			if ready() != nil {
				return
			}
		case hint, ok := <-sub.hints:
			if !ok {
				return
			}
			if !hint.valid() || ctx.Err() != nil {
				continue
			}
			if control.SetWriteDeadline(identity.Earlier(until, hint.Until)) != nil || enc.Encode(hint) != nil || control.Flush() != nil || control.SetWriteDeadline(until) != nil {
				return
			}
		}
	}
}

func (c *Client) WatchWork(ctx context.Context, connectedSettings func(context.Context) error, receive func(WorkHint)) (connected bool, err error) {
	if c == nil || ctx == nil || receive == nil {
		return false, ErrChannel
	}
	resp, err := c.open(ctx, WorkPath, nil, nil)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.Header.Get("Content-Type") != ContentType {
		return false, ErrChannel
	}
	if connectedSettings != nil {
		if err := connectedSettings(ctx); err != nil {
			return false, err
		}
	}
	return true, readWorkHints(resp.Body, receive)
}

func readWorkHints(body io.Reader, receive func(WorkHint)) error {
	scanner := bufio.NewScanner(body)
	// One NDJSON control frame at a time, independent of subscription lifetime.
	scanner.Buffer(make([]byte, 4096), MaxFrameBytes+1)
	for scanner.Scan() {
		var hint WorkHint
		if err := json.Unmarshal(scanner.Bytes(), &hint); err != nil {
			return err
		}
		if hint.valid() {
			receive(hint)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return io.EOF
}
