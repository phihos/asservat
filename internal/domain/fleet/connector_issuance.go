package fleet

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"bytes"
	"net/netip"
	"strings"
	"time"
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

func (p ConnectorCredentialProfile) Valid() bool {
	return p.ProtectionDigest != (artifact.Digest{}) && p.WellFormed()
}

// WellFormed checks public configuration syntax before an independent native
// protection check is attached. It is deliberately not an accepted observation.
func (p ConnectorCredentialProfile) WellFormed() bool {
	return (!p.Retiring || p.Suspended) && authorization.UUID(p.RootID) && p.Binding.Valid() && p.Binding.Role == ConnectorPeer && p.Revision.Valid() && p.Deployment.Valid() && connectorDNSName(p.ServerName) && connectorRoots(p.ClientIssuerRoots) && connectorRoots(p.ServerIssuerRoots)
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
func connectorRoots(roots [][]byte) bool {
	if len(roots) < 1 || len(roots) > 4 {
		return false
	}
	total := 0
	for i, der := range roots {
		total += len(der)
		if len(der) < 1 || len(der) > 16<<10 || total > 32<<10 {
			return false
		}
		for _, old := range roots[:i] {
			if bytes.Equal(old, der) {
				return false
			}
		}
	}
	return true
}
func (p ConnectorCredentialProfile) Clone() ConnectorCredentialProfile {
	clone := func(roots [][]byte) [][]byte {
		r := append([][]byte(nil), roots...)
		for i := range r {
			r[i] = bytes.Clone(r[i])
		}
		return r
	}
	p.ClientIssuerRoots = clone(p.ClientIssuerRoots)
	p.ServerIssuerRoots = clone(p.ServerIssuerRoots)
	return p
}
func (p ConnectorCredentialProfile) Equal(q ConnectorCredentialProfile) bool {
	if p.RootID != q.RootID || p.Binding != q.Binding || p.Revision != q.Revision || p.ProtectionDigest != q.ProtectionDigest || p.ServerName != q.ServerName || p.Deployment != q.Deployment || p.Suspended != q.Suspended || p.Retiring != q.Retiring || len(p.ClientIssuerRoots) != len(q.ClientIssuerRoots) || len(p.ServerIssuerRoots) != len(q.ServerIssuerRoots) {
		return false
	}
	for i := range p.ClientIssuerRoots {
		if !bytes.Equal(p.ClientIssuerRoots[i], q.ClientIssuerRoots[i]) {
			return false
		}
	}
	for i := range p.ServerIssuerRoots {
		if !bytes.Equal(p.ServerIssuerRoots[i], q.ServerIssuerRoots[i]) {
			return false
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

func (o ConnectorCredentialObservation) Valid(now time.Time) bool {
	return o.Backing.Valid() && o.Profile.Valid() && !o.Profile.Suspended && identity.Fresh(o.ObservedAt, o.FreshUntil, now, 5*time.Second)
}

// SameSource excludes freshness while preserving both immutable behavior and
// the exact complete backing observation for one live operation.
func (o ConnectorCredentialObservation) SameSource(other ConnectorCredentialObservation) bool {
	return o.Backing == other.Backing && o.Profile.Equal(other.Profile)
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

func (p ConnectorCredentialProcess) Valid() bool {
	origin := authorization.UUID(p.BootstrapID) && p.Attested == nil || p.BootstrapID == "" && p.Attested != nil && p.Attested.Valid() && p.Attested.Binding == p.Binding
	return origin && (p.Attested == nil && p.RunUntil.IsZero() || !p.RunUntil.Before(p.InitialCertificateNotAfter) && p.RunUntil.Year() <= 9998) && p.Binding.Valid() && p.Binding.Role == ConnectorPeer && p.ClientKeyDigest != (artifact.Digest{}) && p.ServerKeyDigest != (artifact.Digest{}) && p.ClientKeyDigest != p.ServerKeyDigest && !p.ClaimedAt.IsZero() && p.ClaimedAt.Year() >= 2020 && p.InitialCertificateNotAfter.Year() <= 9998 && p.InitialCertificateNotAfter.Equal(p.ClaimedAt.Add(ConnectorCertificatePeriod).UTC().Truncate(time.Second))
}

// Period zero has the original initial leaf expiry. Subsequent periods retain
// that immutable anchor; retries and process restarts do not reset a window.
func (p ConnectorCredentialProcess) Window(now time.Time) (int64, time.Time, error) {
	if !p.Valid() || now.Before(p.ClaimedAt) || now.Year() > 9998 {
		return 0, time.Time{}, ErrInvalid
	}
	seconds := int64(ConnectorCertificatePeriod / time.Second)
	start := p.InitialCertificateNotAfter.Unix() - seconds
	epoch := (now.Unix() + int64(ConnectorCertificateRenewBefore/time.Second) - start) / seconds
	until := time.Unix(p.InitialCertificateNotAfter.Unix()+epoch*seconds, 0).UTC()
	if !p.RunUntil.IsZero() {
		until = identity.Earlier(until, p.RunUntil)
	}
	if epoch < 0 || !until.After(now) || until.After(now.Add(ConnectorCertificatePeriod+ConnectorCertificateRenewBefore)) {
		return 0, time.Time{}, ErrInvalid
	}
	return epoch, until, nil
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

// WellFormed validates the historical intersection of the original observations.
// CheckedAt is the request start, which may precede sequential proof reads. A
// historical intersection never renews a permit: effects still require Valid(now)
// and their independently current SQL/source/identity checks.
func (p ConnectorCredentialPermit) WellFormed() bool {
	start := p.CheckedAt
	observe := func(at time.Time) {
		if at.After(start) {
			start = at
		}
	}
	observe(p.Configuration.ObservedAt)
	observe(p.Recovery.ObservedAt)
	if q := p.ProcessProof; q != nil {
		observe(q.ObservedAt)
		observe(q.Configuration.ObservedAt)
	} else {
		observe(p.CurrentPeer.VerifiedAt)
	}
	// Valid retains every original maximum interval and expiry, including
	// SignBefore's bound by each contributing observation's original end.
	return p.Valid(start)
}

func (p ConnectorCredentialPermit) Valid(now time.Time) bool {
	epoch, end, err := p.Process.Window(p.CheckedAt)
	peer := p.CurrentPeer
	actor := peer.Certificate.Valid(now) && peer.Certificate.Binding == p.Process.Binding && peer.RegistrationRevision.Valid() && identity.Fresh(peer.VerifiedAt, peer.ValidUntil, now, 5*time.Second) && p.ProcessProof == nil
	actorUntil := peer.ValidUntil
	if q := p.ProcessProof; q != nil {
		actor = p.Process.Attested != nil && *p.Process.Attested == q.Process && peer == (AuthenticatedPeer{}) && q.Valid(now) && q.Configuration.Profile.Equal(p.Configuration.Profile) && q.ClientKeyDigest == p.Process.ClientKeyDigest && q.ServerKeyDigest == p.Process.ServerKeyDigest
		actorUntil = q.FreshUntil
	}
	return err == nil && authorization.UUID(p.ID) && (p.Usage == "client" || p.Usage == "server") && p.Configuration.Valid(now) && p.Configuration.Profile.Binding == p.Process.Binding && actor && p.Recovery.Valid(now) && p.Recovery.InstallationID == p.Process.Binding.InstallationID && p.Recovery.IssuerEpoch == p.Process.Binding.IssuerEpoch && p.IntentDigest != (artifact.Digest{}) && p.Epoch == epoch && p.Ordinal >= 1 && p.Ordinal <= 2 && p.CertificateNotAfter.Equal(end) && identity.Fresh(p.CheckedAt, p.SignBefore, now, 5*time.Second) && !p.SignBefore.After(p.Configuration.FreshUntil) && !p.SignBefore.After(actorUntil) && !p.SignBefore.After(p.Recovery.FreshUntil) && !p.SignBefore.After(end) && !(p.Usage == "client" && epoch == 0 && p.ProcessProof == nil)
}
func (p ConnectorCredentialPermit) PublicKeyDigest() artifact.Digest {
	if p.Usage == "client" {
		return p.Process.ClientKeyDigest
	}
	if p.Usage == "server" {
		return p.Process.ServerKeyDigest
	}
	return artifact.Digest{}
}

// Server certificates are purpose-specific values. They cannot be inserted into
// the client PeerRegistry or passed as clientAuth facts by an implicit conversion.
type ConnectorCredentialCertificate struct {
	Binding                 PeerBinding
	Usage, ServerName       string
	Digest, PublicKeyDigest artifact.Digest
	NotBefore, NotAfter     time.Time
}

func (c ConnectorCredentialCertificate) Valid(now time.Time) bool {
	name := c.ServerName == "" && c.Usage == "client" || connectorDNSName(c.ServerName) && c.Usage == "server"
	return name && c.Binding.Valid() && c.Binding.Role == ConnectorPeer && c.Digest != (artifact.Digest{}) && c.PublicKeyDigest != (artifact.Digest{}) && !c.NotBefore.IsZero() && !now.Before(c.NotBefore) && now.Before(c.NotAfter) && c.NotAfter.After(c.NotBefore) && !c.NotAfter.After(c.NotBefore.Add(time.Hour))
}

type IssuedConnectorCredential struct {
	Certificate ConnectorCredentialCertificate
	DER         []byte
	ChainDER    [][]byte
}

func (c IssuedConnectorCredential) Clone() IssuedConnectorCredential {
	c.DER = bytes.Clone(c.DER)
	c.ChainDER = append([][]byte(nil), c.ChainDER...)
	for i := range c.ChainDER {
		c.ChainDER[i] = bytes.Clone(c.ChainDER[i])
	}
	return c
}
func (p ConnectorCredentialPermit) Matches(c IssuedConnectorCredential) bool {
	v := c.Certificate
	name := ""
	if p.Usage == "server" {
		name = p.Configuration.Profile.ServerName
	}
	if !p.WellFormed() || !v.Valid(p.CheckedAt) || v.Binding != p.Process.Binding || v.Usage != p.Usage || v.ServerName != name || v.PublicKeyDigest != p.PublicKeyDigest() || !v.NotAfter.Equal(p.CertificateNotAfter) || v.NotBefore.Before(p.CheckedAt.Add(-time.Minute)) || len(c.DER) < 1 || len(c.DER) > 16<<10 || len(c.ChainDER) > 3 {
		return false
	}
	total := len(c.DER)
	for _, der := range c.ChainDER {
		total += len(der)
		if len(der) < 1 || len(der) > 16<<10 || total > 32<<10 {
			return false
		}
	}
	return true
}
