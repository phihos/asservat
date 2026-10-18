package bootstrap

import (
	"bytes"
	"os"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/contracts"
)

// readEvidenceDeleteCredential reads the operator's evidence delete
// credential file for installer-provider-apply (ADR-205 decision 4), or nil
// without one.
func readEvidenceDeleteCredential(file string) ([]byte, error) {
	if file == "" {
		return nil, nil
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	if !validEvidenceDeleteCredential(b) {
		clear(b)
		return nil, mounts.ErrUnavailable
	}
	return b, nil
}

// validEvidenceDeleteCredential accepts exactly a static owner storage
// credential. It lives only in the immutable EvidenceDeleteCredentialName
// Secret, which cannot renew in place, so a temporary credential is refused.
// The continuation checks the inbox copy with it again before that Secret is
// written.
func validEvidenceDeleteCredential(raw []byte) bool {
	c, err := contracts.DecodeOwnerStorageCredential(bytes.NewReader(raw))
	return err == nil && c.AccessKeyID != "" && c.SecretAccessKey != "" && c.SessionToken == ""
}
