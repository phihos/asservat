package bootstrap

import (
	"bytes"
	"context"
	"os"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/contracts"
)

// readOwnerDeploymentFixture decodes a composed owner input written by a
// test as deployment.json and applies the production input validation. The
// production loader builds the same struct from the Helm-native inputs.
func readOwnerDeploymentFixture(ctx context.Context, files *os.Root) (*ownerInputs, error) {
	b, err := mounts.Read(ctx, files, "deployment.json", contracts.OwnerDeploymentMaxBytes)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	defer clear(b)
	c, err := contracts.DecodeOwnerDeployment(bytes.NewReader(b))
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	if err = validateOwnerDeployment(c); err != nil {
		return nil, err
	}
	return &ownerInputs{providerInputs: &providerInputs{files: files, kubernetesEndpoint: c.Kubernetes, postgresEndpoint: c.Postgres}, config: c}, nil
}
