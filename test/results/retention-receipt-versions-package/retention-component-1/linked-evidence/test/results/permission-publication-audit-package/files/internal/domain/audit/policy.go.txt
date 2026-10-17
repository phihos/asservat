package audit

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
)

// The full minimized acceptance is the audit payload. Recipe text, signatures,
// tokens, group membership lists and collected content are absent.
type PolicyAcceptance = capture.PolicyAcceptance

func PolicyAcceptanceKey(root, event string) string {
	return "policy-acceptance/v1/" + root + "/" + event + "/record"
}
func (r Receipt) ValidPolicyAcceptance(root, event string) bool {
	return authorization.UUID(root) && authorization.UUID(event) && r.Key == PolicyAcceptanceKey(root, event) && r.Version != "null" && identity.Text(r.Version, 1024) && identity.Text(r.ETag, 256) && r.Bytes > 0 && r.Bytes <= 128<<10 && r.SHA256 != (artifact.Digest{})
}
