package capture

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
)

// A preview stores nothing (ADR-330 D9). The IDs of a plan come from its plan
// scope: a preview draws random ones, a request derives them from the
// requester, its idempotency key and the reviewed plan digest, so a retry
// recomputes the same capture, case and approval binding.
type planScope struct {
	seed   []byte
	issued []string
}

type planScopeKey struct{}

// WithPlanScope starts the plan scope of one preview. The returned digest
// function names the plan of a preview computed under ctx.
func WithPlanScope(ctx context.Context) (context.Context, func(value.ContextPreview) artifact.Digest) {
	s := &planScope{}
	return context.WithValue(ctx, planScopeKey{}, s), s.digest
}

func requestPlanScope(ctx context.Context, root string, actor identity.Principal, key string, plan artifact.Digest) (context.Context, *planScope) {
	seed := sha256.Sum256(fmt.Appendf(nil, "asservat-capture-request/v1\x00%s\x00%s\x00%s\x00%s\x00%s\x00%x", root, actor.Issuer, actor.Subject, actor.ClientID, key, plan))
	s := &planScope{seed: seed[:]}
	return context.WithValue(ctx, planScopeKey{}, s), s
}

// planID issues the next ID of the plan computed under ctx. Outside a plan
// scope (tests, internal callers) it uses random.
func planID(ctx context.Context, random func() string) string {
	s, _ := ctx.Value(planScopeKey{}).(*planScope)
	if s == nil {
		return random()
	}
	id := seededID(s.seed, uint64(len(s.issued)))
	if s.seed == nil {
		id = random()
	}
	s.issued = append(s.issued, id)
	return id
}

// seededID is the n-th UUID of a request's plan; n = ^0 names the request.
func seededID(seed []byte, n uint64) string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], n)
	h := sha256.Sum256(append(append([]byte{}, seed...), b[:]...))
	h[6] = h[6]&0x0f | 0x40
	h[8] = h[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
}

// digest names the reviewed plan: its target, scopes, retention, audience and
// normalized request. Issued IDs and computed times are replaced, and
// storage placement is left out, so a request recomputing the same plan
// later gets the same digest.
func (s *planScope) digest(p value.ContextPreview) artifact.Digest {
	p.Storage = value.ContextStorageSelection{}
	p.ID = ""
	b, err := json.Marshal(p)
	if err != nil {
		return artifact.Digest{}
	}
	var doc any
	if json.Unmarshal(b, &doc) != nil {
		return artifact.Digest{}
	}
	ids := make(map[string]string, len(s.issued))
	for n, id := range s.issued {
		ids[id] = fmt.Sprintf("id-%d", n)
	}
	out, err := json.Marshal(normalizePlan(doc, ids))
	if err != nil {
		return artifact.Digest{}
	}
	return artifact.Digest(sha256.Sum256(out))
}

func normalizePlan(v any, ids map[string]string) any {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			switch k {
			case "ScopeDigest", "ExecutionDigest":
				delete(x, k)
				continue
			case "CanonicalScope":
				if s, ok := e.(string); ok {
					if raw, err := base64.StdEncoding.DecodeString(s); err == nil {
						var scope any
						if json.Unmarshal(raw, &scope) == nil {
							x[k] = normalizePlan(scope, ids)
							continue
						}
					}
				}
			}
			x[k] = normalizePlan(e, ids)
		}
		return x
	case []any:
		for n := range x {
			x[n] = normalizePlan(x[n], ids)
		}
		return x
	case string:
		if id, ok := ids[x]; ok {
			return id
		}
		if _, err := time.Parse(time.RFC3339Nano, x); err == nil {
			return "time"
		}
		return x
	}
	return v
}
