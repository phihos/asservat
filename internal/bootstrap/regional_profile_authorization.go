package bootstrap

import (
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/planning"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"sync"
)

// The existing protected input guard pins the immutable bundle's UID/version.
// It loads immutable private configuration once; rotation requires guarded restart.
type regionalProfileAuthorizationReader struct {
	mu       sync.RWMutex
	closed   bool
	material map[string][]byte
	inputs   *providerInputs
	policies map[string]planning.GoEndpointSource
}

func newRegionalProfileAuthorizationReader(ctx context.Context, in *providerInputs, c regionalConfig) (*regionalProfileAuthorizationReader, error) {
	if ctx == nil || ctx.Err() != nil || in == nil || c.Executor == nil {
		return nil, mounts.ErrUnavailable
	}
	entries, err := kube.ProfileEndpointEntries(c.ClusterID, c.Executor.ProfileEndpoints)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	r := &regionalProfileAuthorizationReader{inputs: in, policies: map[string]planning.GoEndpointSource{}}
	for _, e := range entries {
		if p := e.Definition.Credential; p != nil {
			r.policies[p.Policy.Name] = p.Policy
		}
	}
	if len(r.policies) == 0 {
		return nil, nil
	}
	if err := r.load(ctx); err != nil {
		return nil, err
	}
	return r, nil
}
func (r *regionalProfileAuthorizationReader) load(ctx context.Context) error {
	raw, err := r.inputs.read(ctx, contracts.RegionalProfileAuthorizationFile, contracts.RegionalProfileAuthorizationMaxBytes)
	defer clear(raw)
	if err != nil {
		return mounts.ErrUnavailable
	}
	all, err := contracts.DecodeRegionalProfileAuthorization(bytes.NewReader(raw))
	if err != nil || len(all.Entries) != len(r.policies) {
		all.Clear()
		return mounts.ErrUnavailable
	}
	for _, e := range all.Entries {
		if _, ok := r.policies[e.Name]; !ok {
			all.Clear()
			return mounts.ErrUnavailable
		}
	}
	if ctx.Err() != nil {
		all.Clear()
		return mounts.ErrUnavailable
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.material != nil {
		all.Clear()
		return mounts.ErrUnavailable
	}
	r.material = map[string][]byte{}
	for _, e := range all.Entries {
		r.material[e.Name] = e.Authorization
	}
	return nil
}
func (r *regionalProfileAuthorizationReader) ReadProfileAuthorization(ctx context.Context, source planning.GoEndpointSource) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || r == nil || r.inputs == nil || !source.Valid() || r.policies[source.Name] != source {
		return nil, mounts.ErrUnavailable
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed || ctx.Err() != nil {
		return nil, mounts.ErrUnavailable
	}
	if b := r.material[source.Name]; len(b) > 0 {
		return slices.Clone(b), nil
	}
	return nil, mounts.ErrUnavailable
}

func readInstallerProfileAuthorization(ctx context.Context, path string) ([]byte, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	defer root.Close()
	return mounts.Read(ctx, root, filepath.Base(path), contracts.RegionalProfileAuthorizationMaxBytes)
}

func (r *regionalProfileAuthorizationReader) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	for _, b := range r.material {
		clear(b)
	}
	r.material = nil
}
