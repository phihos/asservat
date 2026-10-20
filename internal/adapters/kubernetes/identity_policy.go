package kubernetes

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"sync"
	"time"

	port "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/identity"
)

// IdentityPolicyClient reads installation settings whose protection and provider
// qualification are established by role bootstrap. An issuer from a token can
// only match the pinned issuer; it cannot choose an object, URL or trust profile.
type IdentityPolicyClient struct {
	client            *PermissionClient
	name, uid, issuer string
	mu                sync.Mutex
	policy            value.Policy
	lastNow           time.Time
	read              *identityPolicyRead
}

type identityPolicyRead struct {
	done   chan struct{}
	policy value.Policy
	err    error
}

var _ port.PolicyReader = (*IdentityPolicyClient)(nil)

func NewIdentityPolicyClient(client *PermissionClient, name, uid, issuer string) (*IdentityPolicyClient, error) {
	u, err := url.Parse(issuer)
	if client == nil || !installationRefValid(name, uid) || err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || !value.Text(issuer, 2048) {
		return nil, value.ErrInvalid
	}
	return &IdentityPolicyClient{client: client, name: name, uid: uid, issuer: issuer}, nil
}

// Retain one successful observation only until its original thirty-second
// FreshUntil, refreshing on demand when less than the existing five-second
// operation budget remains. Token/session validation remains outside this
// reader. A refresh belongs to its initiating caller; concurrent callers may
// join it while preserving their own cancellation, without background I/O or
// implicit retry. Already-owned requests retain their original cutoffs.
func (c *IdentityPolicyClient) IdentityPolicy(ctx context.Context, issuer string) (value.Policy, error) {
	var zero value.Policy
	if c == nil {
		return zero, value.ErrUnavailable
	}
	if issuer != c.issuer {
		return zero, value.ErrDenied
	}
	c.mu.Lock()
	now, err := c.policyTime(ctx)
	if err != nil {
		c.mu.Unlock()
		return zero, err
	}
	if c.policy.Validate(now) == nil && c.policy.FreshUntil.Sub(now) >= 5*time.Second {
		out := cloneIdentityPolicy(c.policy)
		c.mu.Unlock()
		return out, nil
	}
	c.policy = zero
	if read := c.read; read != nil {
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return zero, errors.Join(value.ErrUnavailable, ctx.Err())
		case <-read.done:
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		now, err = c.policyTime(ctx)
		if err != nil {
			return zero, err
		}
		if read.err != nil {
			return zero, read.err
		}
		if read.policy.Validate(now) != nil || read.policy.FreshUntil.Sub(now) < 5*time.Second {
			return zero, value.ErrUnavailable
		}
		return cloneIdentityPolicy(read.policy), nil
	}
	read := &identityPolicyRead{done: make(chan struct{})}
	c.read = read
	c.mu.Unlock()

	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	readUntil, _ := call.Deadline()
	out, err := c.readPolicy(call, issuer)
	if call.Err() != nil {
		err = errors.Join(value.ErrUnavailable, call.Err())
	}
	cancel()
	c.mu.Lock()
	defer c.mu.Unlock()
	now, currentErr := c.policyTime(ctx)
	if !time.Now().Before(readUntil) {
		err = errors.Join(value.ErrUnavailable, context.DeadlineExceeded)
	}
	if currentErr != nil {
		err = currentErr
	}
	if err == nil && out.Validate(now) != nil {
		err = value.ErrUnavailable
	}
	if err == nil {
		// Neither publication nor a later cache hit changes observation times.
		c.policy = cloneIdentityPolicy(out)
		read.policy = c.policy
	}
	read.err = err
	c.read = nil
	close(read.done)
	if err != nil {
		return zero, err
	}
	return cloneIdentityPolicy(out), nil
}

// policyTime runs with mu held. Remembering the greatest observed clock keeps
// a rollback from reviving an expired observation or starting an older one.
func (c *IdentityPolicyClient) policyTime(ctx context.Context) (time.Time, error) {
	if ctx == nil {
		return time.Time{}, value.ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return time.Time{}, errors.Join(value.ErrUnavailable, err)
	}
	if until, ok := ctx.Deadline(); ok && !time.Now().Before(until) {
		return time.Time{}, errors.Join(value.ErrUnavailable, context.DeadlineExceeded)
	}
	now := c.client.now()
	if now.IsZero() || now.Before(c.lastNow) {
		return time.Time{}, value.ErrUnavailable
	}
	c.lastNow = now
	return now, nil
}

func cloneIdentityPolicy(p value.Policy) value.Policy {
	p.Clients = slices.Clone(p.Clients)
	p.EligibleSubjects = slices.Clone(p.EligibleSubjects)
	p.EligibleGroups = slices.Clone(p.EligibleGroups)
	return p
}

func (c *IdentityPolicyClient) readPolicy(ctx context.Context, issuer string) (value.Policy, error) {
	var out value.Policy
	start := c.client.now()
	data, ref, err := c.client.installationConfig(ctx, c.name, c.uid)
	if err != nil || len(data) != 1 || data["identity.json"] == "" {
		return out, value.ErrUnavailable
	}
	var wire contracts.IdentitySettings
	digest, err := decodePermissionSpec([]byte(data["identity.json"]), c.client.validator.identitySchema, &wire)
	if err != nil || wire.Issuer != issuer {
		return out, value.ErrUnavailable
	}
	out = value.Policy{Revision: value.Revision{UID: ref.UID, Generation: wire.Revision, Digest: digest}, Issuer: wire.Issuer, ObservedAt: start, FreshUntil: start.Add(30 * time.Second), EligibleGroups: wire.EligibleGroups, GroupsAtIssueQualified: wire.GroupsAtIssueQualified, GroupMaxAge: time.Duration(wire.GroupMaxAgeSeconds) * time.Second}
	for _, v := range wire.Clients {
		out.Clients = append(out.Clients, value.Client{ID: v.ID, Kind: value.Kind(v.Kind), ClassQualified: v.ClassQualified})
	}
	for _, v := range wire.EligibleSubjects {
		out.EligibleSubjects = append(out.EligibleSubjects, value.Subject{ID: v.ID, Kind: value.Kind(v.Kind)})
	}
	if c.client.current(ctx, start, 5*time.Second) != nil || out.Validate(c.client.now()) != nil {
		return value.Policy{}, value.ErrUnavailable
	}
	return out, nil
}
