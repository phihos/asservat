package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"time"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
)

// The original canonical producer input remains accepted byte-for-byte. The
// official chart selects a distinct public normalization format; there is no
// fallback from malformed canonical input and no private setup file read here.
func readInitialBootstrapDesired(ctx context.Context, input *os.Root) (contracts.InitialBootstrap, error) {
	d, _, err := readInitialBootstrapDesiredAndServices(ctx, input)
	return d, err
}

func readInitialBootstrapDesiredAndServices(ctx context.Context, input *os.Root) (contracts.InitialBootstrap, initialBootstrapServices, error) {
	var zero contracts.InitialBootstrap
	var services initialBootstrapServices
	raw, err := mounts.Read(ctx, input, "bootstrap.json", contracts.InitialBootstrapMaxBytes)
	if err != nil {
		return zero, initialBootstrapServices{}, mounts.ErrUnavailable
	}
	defer clear(raw)
	var kind struct {
		Format string `json:"format"`
	}
	if json.Unmarshal(raw, &kind) != nil {
		return zero, initialBootstrapServices{}, mounts.ErrUnavailable
	}
	if kind.Format != contracts.InitialBootstrapInputFormat {
		d, err := contracts.DecodeInitialBootstrap(bytes.NewReader(raw))
		if err != nil || ctx.Err() != nil {
			return zero, initialBootstrapServices{}, mounts.ErrUnavailable
		}
		return d, services, nil
	}
	v, err := contracts.DecodeInitialBootstrapInput(bytes.NewReader(raw))
	if err != nil {
		return zero, initialBootstrapServices{}, mounts.ErrUnavailable
	}
	if err := resolveInitialBootstrapPostgresRoots(ctx, input, &v); err != nil {
		return zero, initialBootstrapServices{}, err
	}
	if err := resolveInitialBootstrapIdentity(ctx, input, &v); err != nil {
		return zero, initialBootstrapServices{}, err
	}
	services.ObjectStore, err = resolveInitialBootstrapObjectStore(ctx, input, &v)
	if err != nil {
		return zero, initialBootstrapServices{}, err
	}
	var ca, token []byte
	if v.Kubernetes.RootsPEM == "" {
		ca, err = mounts.Read(ctx, input, "kube-ca.crt", 32<<10)
		if err != nil {
			return zero, initialBootstrapServices{}, mounts.ErrUnavailable
		}
	}
	if v.ProbeAudience == "" {
		token, err = mounts.Read(ctx, input, "administrator-token", contracts.WorkerEnrollmentMaxToken)
		if err != nil {
			return zero, initialBootstrapServices{}, mounts.ErrUnavailable
		}
		defer clear(token)
	}
	services.KeyService, err = resolveInitialBootstrapKeyService(ctx, input, &v, ca)
	if err != nil {
		return zero, initialBootstrapServices{}, err
	}
	d, err := providerconfig.CompileInitialBootstrapInput(v, ca, token, time.Now())
	if err != nil || ctx.Err() != nil {
		return zero, initialBootstrapServices{}, mounts.ErrUnavailable
	}
	return d, services, nil
}

func resolveInitialBootstrapPostgresRoots(ctx context.Context, input *os.Root, v *contracts.InitialBootstrapInput) error {
	if v == nil || ctx == nil || input == nil {
		return mounts.ErrUnavailable
	}
	if v.Postgres.RootsSource == "" {
		return nil
	}
	if v.Postgres.RootsSource != contracts.InitialBootstrapBundledPostgresRoots || v.Postgres.RootsPEM != "" {
		return mounts.ErrUnavailable
	}
	ca, err := mounts.Read(ctx, input, contracts.InitialBootstrapPostgresCAFile, 32<<10)
	if err != nil || ctx.Err() != nil {
		return mounts.ErrUnavailable
	}
	// Trust parsing/expiry/duplication and canonical ordering remain the same
	// full compiler path as explicit operator PEM. Do not return a precompiled
	// endpoint or invent a trust observation here.
	v.Postgres.RootsPEM = string(ca)
	v.Postgres.RootsSource = ""
	return nil
}
