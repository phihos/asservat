package kubernetes

import (
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/flowcontrol"
)

// OpeningBurst is the token bucket size for clients that serve only context
// start openings (ADR-208). The sustained rate stays the fixed 20 QPS, so a
// full bucket refills within one original five-second window.
const OpeningBurst = 100

// WithOpeningBurst copies config with a 20 QPS/burst-100 limiter. One opening
// needs about 60–80 sequential reads per side; at burst 20 every read past the
// twentieth waited about 50 ms and exhausted the original five seconds
// (installed native 55). Checks, identities and deadlines are unchanged.
func WithOpeningBurst(config *rest.Config) *rest.Config {
	if config == nil {
		return nil
	}
	c := rest.CopyConfig(config)
	c.RateLimiter = flowcontrol.NewTokenBucketRateLimiter(20, OpeningBurst)
	return c
}
