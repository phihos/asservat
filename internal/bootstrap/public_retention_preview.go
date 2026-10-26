package bootstrap

import (
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/transport/presentation"
)

// composePublicRetentionPreview composes the ADR-240 browser-only
// preview_retention_change operation: the protected fleet administration
// names the fleet operators, the hub metadata reader supplies the retention
// sources and retained catalog, and the observed EvidenceRetentionPolicy
// schema decodes proposals. Nil without fleet administration (no operator
// could call it).
func composePublicRetentionPreview(c PublicContextOperationsConfig, s PublicContextOperationServices, pc *publicContext) (*presentation.RetentionPreviewOperations, error) {
	if pc == nil || pc.fleet == nil {
		return nil, nil
	}
	v, err := composePublicContextUseCases(c, s)
	if err != nil || pc.fleet.Settings == nil || pc.retentionSources == nil {
		return nil, presentation.ErrOperationsConfiguration
	}
	decoder, err := kube.NewRetentionPolicySpecDecoder()
	if err != nil {
		return nil, presentation.ErrOperationsConfiguration
	}
	service := privacyapp.RetentionPreviewer{InstallationID: c.InstallationID, Administration: pc.fleet.Settings, Catalog: pc.retentionSources, Decoder: decoder, Recovery: v.submission.Recovery, Now: c.Now}
	return presentation.NewRetentionPreviewOperations(c.PublicOrigin, c.Now, c.NewID, service)
}
