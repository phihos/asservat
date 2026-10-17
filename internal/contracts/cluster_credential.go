package contracts

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"time"
)

// ADR-168 private exchange: one exporter-bound signed request per TLS
// connection. The wire carries public values only; no private key, token or
// human credential is ever serialized.
const (
	ClusterCredentialPath        = "/v1/cluster-enrollment"
	ClusterCredentialWireFormat  = "asservat-cluster-enrollment/v1"
	ClusterCredentialMaxRequest  = 8 << 10
	ClusterCredentialMaxReply    = 4 << 10
	ClusterCredentialExporterLen = 32
)

var ErrClusterCredentialWire = errors.New("invalid cluster enrollment exchange")

type ClusterCredentialWire struct {
	Format         string    `json:"format"`
	Operation      string    `json:"operation"`
	RootID         string    `json:"rootID"`
	PeerID         string    `json:"peerID"`
	InstallationID string    `json:"installationID"`
	ClusterID      string    `json:"clusterID"`
	Generation     int64     `json:"generation"`
	PodUID         string    `json:"podUID,omitempty"`
	ProcessEpoch   string    `json:"processEpoch,omitempty"`
	ClientKey      []byte    `json:"clientKey,omitempty"`
	ServerKey      []byte    `json:"serverKey,omitempty"`
	NextKey        []byte    `json:"nextKey,omitempty"`
	RequestedAt    time.Time `json:"requestedAt"`
	Signature      []byte    `json:"signature"`
}

type ClusterCredentialReply struct {
	Format     string    `json:"format"`
	LineageID  string    `json:"lineageID"`
	Generation int64     `json:"generation"`
	CheckedAt  time.Time `json:"checkedAt"`
	ValidUntil time.Time `json:"validUntil"`
}

// decodeStrict accepts exactly one JSON object with known fields only.
func decodeStrict(r io.Reader, limit int64, out any) error {
	raw, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return ErrClusterCredentialWire
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.More() {
		return ErrClusterCredentialWire
	}
	return nil
}

func DecodeClusterCredentialWire(r io.Reader) (ClusterCredentialWire, error) {
	var out ClusterCredentialWire
	if err := decodeStrict(r, ClusterCredentialMaxRequest, &out); err != nil || out.Format != ClusterCredentialWireFormat {
		return ClusterCredentialWire{}, ErrClusterCredentialWire
	}
	return out, nil
}

func DecodeClusterCredentialReply(r io.Reader) (ClusterCredentialReply, error) {
	var out ClusterCredentialReply
	if err := decodeStrict(r, ClusterCredentialMaxReply, &out); err != nil || out.Format != ClusterCredentialWireFormat {
		return ClusterCredentialReply{}, ErrClusterCredentialWire
	}
	return out, nil
}
