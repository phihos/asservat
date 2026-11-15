package fleet

import (
	"net/netip"
	"strings"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

const ConnectorCertificatePeriod = 30 * time.Minute
const ConnectorCertificateRenewBefore = time.Minute

// These are separately accepted issuer/endpoint facts, not a worker's consumer
// exchange URL. Current fleet/recovery acceptance and protected source identity
// must be established by the configuration producer before this observation.
type ConnectorCredentialProfile struct {
	RootID                               string
	Binding                              PeerBinding
	Revision                             identity.Revision
	ProtectionDigest                     artifact.Digest
	ServerName                           string
	Deployment                           ConnectorDeployment
	ClientIssuerRoots, ServerIssuerRoots [][]byte
	Suspended, Retiring                  bool
}

func connectorDNSName(s string) bool {
	if len(s) < 1 || len(s) > 253 || strings.ToLower(s) != s || strings.Contains(s, "*") {
		return false
	}
	if _, e := netip.ParseAddr(s); e == nil {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// Backing is a separate complete-source observation. Behavioral identity alone
// cannot excuse a currently observed rollback or unaccepted backing revision.
type ConnectorBackingObservation struct {
	Revision             int64
	Digest, SourceDigest artifact.Digest
}

func (b ConnectorBackingObservation) Valid() bool {
	return b.Revision > 0 && b.Revision <= 1<<60 && b.Digest != (artifact.Digest{}) && b.SourceDigest != (artifact.Digest{})
}

type ConnectorCredentialObservation struct {
	Backing                ConnectorBackingObservation
	Profile                ConnectorCredentialProfile
	ObservedAt, FreshUntil time.Time
}

// A process is bound to either the historical acknowledged bootstrap key/leaf
// or a currently attested automatic Pod/process admission. Both purposes have
// distinct keys. Renewal cannot alter the origin or extend its backed lifetime;
// replacing a process is a separately charged admission under the stable peer.
type ConnectorCredentialProcess struct {
	BootstrapID                           string
	Attested                              *ConnectorProcessIdentity `json:",omitempty"`
	Binding                               PeerBinding
	ClientKeyDigest, ServerKeyDigest      artifact.Digest
	ClaimedAt, InitialCertificateNotAfter time.Time
	RunUntil                              time.Time `json:",omitzero"`
}

// This value records an already charged business signing attempt and positive
// intent acknowledgement. SQL, current authenticated TLS and configuration
// checks supply it; a serialized record or caller-created struct grants nothing.
type ConnectorCredentialPermit struct {
	ID                                         string
	Process                                    ConnectorCredentialProcess
	Usage                                      string
	Configuration                              ConnectorCredentialObservation
	CurrentPeer                                AuthenticatedPeer
	ProcessProof                               *ConnectorProcessProof `json:",omitempty"`
	Recovery                                   RecoveryState
	IntentDigest                               artifact.Digest
	Epoch                                      int64
	Ordinal                                    int
	CheckedAt, SignBefore, CertificateNotAfter time.Time
}

// Server certificates are purpose-specific values. They cannot be inserted into
// the client PeerRegistry or passed as clientAuth facts by an implicit conversion.
type ConnectorCredentialCertificate struct {
	Binding                 PeerBinding
	Usage, ServerName       string
	Digest, PublicKeyDigest artifact.Digest
	NotBefore, NotAfter     time.Time
}

type IssuedConnectorCredential struct {
	Certificate ConnectorCredentialCertificate
	DER         []byte
	ChainDER    [][]byte
}
