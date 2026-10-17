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
	var zero contracts.InitialBootstrap
	raw, err := mounts.Read(ctx, input, "bootstrap.json", contracts.InitialBootstrapMaxBytes)
	if err != nil {
		return zero, mounts.ErrUnavailable
	}
	defer clear(raw)
	var kind struct {
		Format string `json:"format"`
	}
	if json.Unmarshal(raw, &kind) != nil {
		return zero, mounts.ErrUnavailable
	}
	if kind.Format != contracts.InitialBootstrapInputFormat {
		d, err := contracts.DecodeInitialBootstrap(bytes.NewReader(raw))
		if err != nil || ctx.Err() != nil {
			return zero, mounts.ErrUnavailable
		}
		return d, nil
	}
	v, err := contracts.DecodeInitialBootstrapInput(bytes.NewReader(raw))
	if err != nil {
		return zero, mounts.ErrUnavailable
	}
	var ca, token []byte
	if v.Kubernetes.RootsPEM == "" {
		ca, err = mounts.Read(ctx, input, "kube-ca.crt", 32<<10)
		if err != nil {
			return zero, mounts.ErrUnavailable
		}
	}
	if v.ProbeAudience == "" {
		token, err = mounts.Read(ctx, input, "administrator-token", contracts.WorkerEnrollmentMaxToken)
		if err != nil {
			return zero, mounts.ErrUnavailable
		}
		defer clear(token)
	}
	d, err := providerconfig.CompileInitialBootstrapInput(v, ca, token, time.Now())
	if err != nil || ctx.Err() != nil {
		return zero, mounts.ErrUnavailable
	}
	return d, nil
}
