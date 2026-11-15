package node

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/collector"
	"github.com/google/uuid"
	"golang.org/x/time/rate"
)

// Handler serves the node routes. Every request carries the collector's
// projected token; the connector reviews it once per connection (and again
// only after the kubelet rotated it). Error bodies are empty: status codes
// are the only signal (400 invalid, 401 unknown or replaced collector, 403
// denied, 409 stale work, 429 too many new streams, 503 unavailable).
type Handler struct {
	channel  *delivery.NodeChannel
	attester delivery.NodeAttester
	// reviews bounds TokenReviews within the connector's API-client QPS:
	// 5,000 nodes reconnect in about 100 seconds.
	reviews *rate.Limiter
}

func NewHandler(ch *delivery.NodeChannel, attester delivery.NodeAttester) (*Handler, error) {
	if ch == nil || attester == nil {
		return nil, delivery.ErrNodeInvalid
	}
	return &Handler{channel: ch, attester: attester, reviews: rate.NewLimiter(50, 200)}, nil
}

type connKey struct{}

// connAuth is one connection's reviewed token.
type connAuth struct {
	mu     sync.Mutex
	digest [32]byte
	id     collector.Identity
}

// ConnContext gives each connection its own authentication slot.
func ConnContext(ctx context.Context, _ net.Conn) context.Context {
	return context.WithValue(ctx, connKey{}, &connAuth{})
}

func status(err error) int {
	switch {
	case errors.Is(err, delivery.ErrNodeInvalid):
		return http.StatusBadRequest
	case errors.Is(err, delivery.ErrNodeUnauthenticated):
		return http.StatusUnauthorized
	case errors.Is(err, delivery.ErrNodeDenied):
		return http.StatusForbidden
	case errors.Is(err, delivery.ErrNodeConflict):
		return http.StatusConflict
	case errors.Is(err, delivery.ErrNodeRateLimited):
		return http.StatusTooManyRequests
	}
	return http.StatusServiceUnavailable
}

func fail(w http.ResponseWriter, err error) {
	if errors.Is(err, delivery.ErrNodeRateLimited) {
		w.Header().Set("Retry-After", "1")
	}
	w.WriteHeader(status(err))
}

func (h *Handler) authenticate(r *http.Request) (collector.Identity, error) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	a, _ := r.Context().Value(connKey{}).(*connAuth)
	if !ok || !contracts.ValidWorkerToken([]byte(token)) || a == nil {
		return collector.Identity{}, delivery.ErrNodeUnauthenticated
	}
	digest := sha256.Sum256([]byte(token))
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.id.NodeUID != "" && a.digest == digest {
		return a.id, nil
	}
	if !h.reviews.Allow() {
		return collector.Identity{}, delivery.ErrNodeRateLimited
	}
	id, err := h.attester.AttestNode(r.Context(), []byte(token))
	if err != nil {
		return collector.Identity{}, err
	}
	a.digest, a.id = digest, id
	return id, nil
}

func (h *Handler) peer(r *http.Request) (delivery.NodePeer, error) {
	id, err := h.authenticate(r)
	return delivery.NodePeer{NodeUID: id.NodeUID, PodUID: id.PodUID}, err
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.RawQuery != "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	switch r.URL.Path {
	case contracts.NodeConnectPath:
		h.connect(w, r)
	case contracts.NodeCapturePath:
		h.capture(w, r)
	case contracts.NodeProfileCapturePath:
		h.profile(w, r)
	case contracts.NodeLivePath:
		h.live(w, r)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// connect runs one stream: Hello, then status reports from the collector and
// pushed work from the connector until either side ends it or a stream from
// another collector Pod replaces it.
func (h *Handler) connect(w http.ResponseWriter, r *http.Request) {
	id, err := h.authenticate(r)
	if err != nil {
		fail(w, err)
		return
	}
	first, err := contracts.ReadNodeFrame[contracts.NodeUp](r.Body)
	if err != nil || first.Hello == nil || first.Hello.Version != contracts.NodeChannelVersion {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var kinds []collector.WorkKind
	for _, k := range first.Hello.Capabilities {
		if kind := collector.WorkKind(k); kind.Valid() {
			kinds = append(kinds, kind)
		}
	}
	id.Epoch = uuid.NewString()
	peer, stream, err := h.channel.Connect(id, kinds)
	if err != nil {
		fail(w, err)
		return
	}
	defer h.channel.Disconnect(peer, stream)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	if rc.Flush() != nil {
		return
	}
	go func() {
		defer cancel()
		for {
			up, err := contracts.ReadNodeFrame[contracts.NodeUp](r.Body)
			if err != nil || up.Status == nil {
				return
			}
			report, ok := DomainStatus(*up.Status)
			if !ok || h.channel.Report(peer, report) != nil {
				return
			}
		}
	}()
	var after uint64
	for {
		work, err := h.channel.Next(ctx, peer, stream, after)
		if err != nil {
			return
		}
		for _, item := range work {
			wire := WireWork(item)
			if profile := wire.ProfileCapture; profile != nil && profile.AuthorizationRequired {
				profile.Authorization, err = h.channel.ProfileAuthorization(ctx, peer, item)
				if err != nil {
					if ctx.Err() != nil || errors.Is(err, delivery.ErrNodeUnauthenticated) {
						return
					}
					profile.Authorization, profile.AuthorizationUnavailable = nil, true
				}
			}
			err = contracts.WriteNodeFrame(w, wire)
			if wire.ProfileCapture != nil {
				clear(wire.ProfileCapture.Authorization)
			}
			if err != nil {
				return
			}
			after = item.Sequence
		}
		if rc.Flush() != nil {
			return
		}
	}
}

// capture receives one finished packet capture (ADR-248): a 4-byte
// big-endian header length, the JSON header, then exactly CapturedBytes of
// PCAPNG. The peer must be the collector Pod the capture was queued for.
func (h *Handler) capture(w http.ResponseWriter, r *http.Request) {
	p, err := h.peer(r)
	if err != nil {
		fail(w, err)
		return
	}
	if r.Header.Get("Content-Type") != contracts.NodeCaptureContentType || r.ContentLength < 4 || r.ContentLength > 4+contracts.NodeCaptureMaxHeader+collector.MaxPacketCaptureBytes {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	body := http.MaxBytesReader(w, r.Body, r.ContentLength)
	var size [4]byte
	if _, err := io.ReadFull(body, size[:]); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	n := binary.BigEndian.Uint32(size[:])
	if n == 0 || n > contracts.NodeCaptureMaxHeader {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	head, err := contracts.DecodeNodePacketResult(io.LimitReader(body, int64(n)))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	result, ok := DomainPacketResult(head)
	if !ok || r.ContentLength != 4+int64(n)+result.CapturedBytes {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := h.channel.DeliverPacket(r.Context(), p, result, body); err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
