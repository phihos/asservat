package kubernetes

import (
	"testing"

	"asservat.local/asservat/internal/contracts"
)

// Projection construction is passive provenance; these synthetic receipts do
// not replace the producer's independently enforced admission and current reads.
func TestInitialVersionedBootstrapProjectsRequiredServices(t *testing.T) {
	for _, tc := range []struct{ bootstrap, services string }{
		{contracts.InitialBootstrapPassiveFormat, contracts.InitialPreparationServicesFormat},
		{contracts.InitialBootstrapCopyClosureFormat, contracts.InitialPreparationServicesFormat},
		{contracts.InitialBootstrapVersionedAuditFormat, contracts.InitialPreparationVersionedAuditServicesFormat},
	} {
		t.Run(tc.bootstrap, func(t *testing.T) {
			d, state := bootstrapStateFixture(t)
			d.Format = tc.bootstrap
			state.DesiredDigest = bootstrapDigest(d)
			projection, err := bootstrapProjectionValue(d, state)
			if err != nil || projection.Services == nil || projection.Services.Format != tc.services {
				t.Fatal("original bootstrap did not bind its required audit service format", err)
			}
			if projection.Plan.InstallationID != state.InstallationID || projection.Plan.RequestID != state.RequestID {
				t.Fatal("version selection replaced original installation identity")
			}
		})
	}
}
