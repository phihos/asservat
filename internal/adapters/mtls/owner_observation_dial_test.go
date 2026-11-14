package mtls

import (
	"io"
	"net/http"
	"strconv"
	"sync/atomic"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
)

// Actual TLS/h2 and unchanged product certificate verification; current native
// and SQL facts remain the synthetic channel fixture. The separately fixed TCP
// endpoint is not an installed endpoint producer or native availability proof.
type translatedObservationFixture struct {
	x               *observationChannelFixture
	mode            string
	base            *OwnerObservationClient
	v1              *ConnectorObservationClient
	v2              *ConnectorObservationOperationClient
	calls           atomic.Int32
	handshakes      atomic.Int32
	entered, joined chan struct{}
}

func (d *translatedObservationFixture) finiteReply(w http.ResponseWriter, r *http.Request) error {
	raw, err := io.ReadAll(io.LimitReader(r.Body, contracts.OwnerObservationBytes+1))
	if err != nil {
		return err
	}
	wire, err := contracts.DecodeOwnerObservationRequest(raw)
	if err != nil {
		return err
	}
	q, err := ownerObservationRequest(wire, d.x.f.clock())
	if err != nil {
		return err
	}
	binding, err := ownerObservationConnection(r.TLS, q)
	if err != nil {
		return err
	}
	n := d.x.f.clock()
	config := ownerBootstrapConfiguration(d.x.ownerPin.Pool, d.x.ownerCA, n)
	leaf := d.x.leaf
	proof := value.OwnerObservation{Request: q, ConnectionBinding: binding, Connector: value.PeerCertificate{Binding: leaf.Binding, Digest: leaf.Digest, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter}, Owner: value.AuthenticatedOwner{Certificate: d.x.owner, EnrollmentID: ownerTestID, Pool: d.x.ownerPin.Pool, Pod: "owner-1", ReplicaSetUID: ownerTestID, ConfigurationRevision: config.Configuration.Revision, ProtectionDigest: d.x.ownerPin.ProtectionDigest, VerifiedAt: n, ValidUntil: q.NotAfter}, Workload: value.OwnerObservationWorkload{Pin: d.x.ownerPin, Binding: d.x.owner.Binding, Pod: "owner-1", ReplicaSetUID: ownerTestID, WorkloadDigest: artifact.Digest{18}, ObservedAt: n, FreshUntil: q.NotAfter}, ObservedAt: n, FreshUntil: q.NotAfter}
	reply, err := ownerObservationReplyWire(proof)
	if err != nil {
		return err
	}
	encoded, err := contracts.EncodeOwnerObservationReply(reply)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", contracts.OwnerObservationMedia)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(encoded)))
	_, err = w.Write(encoded)
	return err
}
