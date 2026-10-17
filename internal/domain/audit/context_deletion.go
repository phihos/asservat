package audit

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

func ContextDeletionKey(root, attempt string) string {
	return "context-deletion/v1/" + root + "/" + attempt + "/record"
}
func (r Receipt) ValidContextDeletion(root, attempt string) bool {
	return authorization.UUID(root) && authorization.UUID(attempt) && r.Key == ContextDeletionKey(root, attempt) && (r.Version == "" || identity.Text(r.Version, 1024)) && identity.Text(r.ETag, 256) && r.Bytes > 0 && r.Bytes <= 128<<10 && r.SHA256 != (artifact.Digest{})
}
