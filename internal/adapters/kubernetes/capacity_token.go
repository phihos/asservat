package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	auth "k8s.io/api/authentication/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const capacityTokenSeconds = 600

// CapacityTokens mints the capacity account's token for this execution Pod
// (ADR-175): 600 seconds and one installer-pinned API audience. The API server
// refuses to bind it to a Pod of another account, so it is unbound; admission
// requires the requester to be the execution account's own Pod-bound
// credential. The token lives only in memory and is reused until one minute
// before expiry, so no TokenRequest lands on a start's five-second path.
type CapacityTokens struct {
	client            *PermissionClient
	account, audience string
	podUID            string
	mu                sync.Mutex
	token             []byte
	until             time.Time
}

// NewCapacityTokens requires the client to be this Pod's own Pod-bound
// execution credential (SelfSubjectReview pod-uid extra).
func NewCapacityTokens(ctx context.Context, client *PermissionClient, account, audience, podUID string) (*CapacityTokens, error) {
	if ctx == nil || client == nil || !identity.Text(account, 253) || !identity.Text(audience, 256) || !installationRefValid(account, podUID) {
		return nil, cfg.ErrInvalid
	}
	raw, err := client.proofPost(ctx, "/apis/authentication.k8s.io/v1/selfsubjectreviews", auth.SelfSubjectReview{TypeMeta: meta.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "SelfSubjectReview"}}, nil)
	var who auth.SelfSubjectReview
	if err != nil || strictGuardJSON(raw, &who) != nil {
		return nil, cfg.ErrUnavailable
	}
	if uid := who.Status.UserInfo.Extra["authentication.kubernetes.io/pod-uid"]; len(uid) != 1 || uid[0] != podUID {
		return nil, cfg.ErrInvalid
	}
	return &CapacityTokens{client: client, account: account, audience: audience, podUID: podUID}, nil
}

// Token returns a copy of the current capacity token; callers may clear it.
func (c *CapacityTokens) Token(ctx context.Context) ([]byte, error) {
	if c == nil || ctx == nil || ctx.Err() != nil {
		return nil, cfg.ErrUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != nil && c.client.now().Before(c.until.Add(-time.Minute)) {
		return bytes.Clone(c.token), nil
	}
	clear(c.token)
	c.token = nil
	seconds := int64(capacityTokenSeconds)
	request := auth.TokenRequest{TypeMeta: meta.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "TokenRequest"}, Spec: auth.TokenRequestSpec{Audiences: []string{c.audience}, ExpirationSeconds: &seconds}}
	started := c.client.now()
	raw, err := c.client.proofPost(ctx, "/api/v1/namespaces/"+c.client.control.Name+"/serviceaccounts/"+c.account+"/token", request, nil)
	defer clear(raw)
	var out auth.TokenRequest
	if err != nil || json.Unmarshal(raw, &out) != nil || out.Status.Token == "" || len(out.Status.Token) > 16384 {
		return nil, cfg.ErrUnavailable
	}
	// Never trust a longer server-reported lifetime than was requested.
	until := out.Status.ExpirationTimestamp.Time
	if latest := started.Add(capacityTokenSeconds * time.Second); until.IsZero() || until.After(latest) {
		until = latest
	}
	c.token, c.until = []byte(out.Status.Token), until
	return bytes.Clone(c.token), nil
}

// Close forgets the cached token.
func (c *CapacityTokens) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	clear(c.token)
	c.token = nil
	c.mu.Unlock()
}
