package kubernetes

import (
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/flowcontrol"
)

// OpeningQPS and OpeningBurst bound clients that serve only context-start
// openings and queries (ADR-208). One opening needs about 60–80 sequential
// reads per side; at 20/20 every read past the twentieth waited about 50 ms
// and exhausted the original five seconds (installed native 55). With burst
// 100 at 20 QPS, about eight retried openings drained the bucket and reads
// again failed fast with seconds left (installed native 57).
const (
	OpeningQPS   = 50
	OpeningBurst = 100
)

// WithOpeningBurst copies config with the opening limiter. Checks, identities
// and deadlines are unchanged.
func WithOpeningBurst(config *rest.Config) *rest.Config {
	if config == nil {
		return nil
	}
	c := rest.CopyConfig(config)
	c.RateLimiter = flowcontrol.NewTokenBucketRateLimiter(OpeningQPS, OpeningBurst)
	return c
}
