package bootstrap

import (
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/transport/presentation"
)

// composePublicRetentionPreview composes the ADR-240 browser-only
// preview_retention_change operation: identity.administrators call it, the
// hub metadata reader supplies the stored policies and deadlines,
// and the observed EvidenceRetentionPolicy schema decodes proposals.
func composePublicRetentionPreview(c PublicContextOperationsConfig, s PublicContextOperationServices, pc *publicContext) (*presentation.RetentionPreviewOperations, error) {
	_, err := composePublicContextUseCases(c, s)
	if err != nil || pc == nil || pc.administrators == nil || pc.retentionPolicies == nil {
		return nil, presentation.ErrOperationsConfiguration
	}
	decoder, err := kube.NewRetentionPolicySpecDecoder()
	if err != nil {
		return nil, presentation.ErrOperationsConfiguration
	}
	service := privacyapp.RetentionPreviewer{InstallationID: c.InstallationID, Administrators: pc.administrators, Catalog: pc.retentionPolicies, Decoder: decoder, Now: c.Now}
	return presentation.NewRetentionPreviewOperations(c.PublicOrigin, c.Now, c.NewID, service)
}
