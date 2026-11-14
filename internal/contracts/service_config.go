package contracts

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// Helm-native service inputs (federation, key service, publisher). Each
// component reads only Helm-rendered values from config.json under its fixed
// root, the generated installation IDs from the <name>-ids Secret mounted at
// IDsRoot, PEM CA bundles beside config.json and credentials from fixed
// projected files. Kubernetes UIDs are read by name at startup; nothing here
// carries a UID, guard pin, recipe digest or activation record.
const (
	IDsRoot               = "/run/asservat/ids"
	ServiceConfigFile     = "config.json"
	ServiceConfigMaxBytes = 64 << 10

	// PEM CA bundles of the providers each component dials.
	PostgresRootsFile    = "postgres-ca.crt"
	ObjectStoreRootsFile = "objectstore-ca.crt"
	OpenBaoRootsFile     = "openbao-ca.crt"
	KeyServiceRootsFile  = "key-service-ca.crt"

	// ArtifactKeyFile is the key service's mounted <name>-artifact-key
	// Secret (key keys.json, the local key secret format).
	ArtifactKeyFile = "artifact-key.json"
)

// ServiceIDs are the generated installation identities (<name>-ids keys).
type ServiceIDs = InstallationIDs

type ServicePostgres struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Database string `json:"database"`
}

type ServiceObjectStore struct {
	Endpoint string `json:"endpoint"`
	Region   string `json:"region"`
	Bucket   string `json:"bucket"`
}

// ServiceTopology names a retention topology ConfigMap of one target cluster.
type ServiceTopology struct {
	TargetClusterID string `json:"targetClusterID"`
	Name            string `json:"name"`
}

// FederationConfig, KeyServiceConfig and PublisherConfig carry only values
// Helm knows. Name is installation.name: object names (`<name>-<component>`,
// `<name>-owner-source`, `<name>-cluster-catalog`, ...) and the OpenBao role
// names (`<name>-<component>-<purpose>`) derive from it. OpenBao mounts are
// the contracts.SmallOpenBao* constants; key and PKI role names derive from
// the installation ID (providerconfig.OpenBaoNamesFor).
type FederationConfig struct {
	Name        string             `json:"name"`
	Namespace   string             `json:"namespace"`
	Port        int                `json:"port"`
	Concurrency int                `json:"concurrency"`
	Postgres    ServicePostgres    `json:"postgres"`
	AuditStore  ServiceObjectStore `json:"auditStore"`
	OpenBao     string             `json:"openBao"`
}

type KeyServiceConfig struct {
	Name        string          `json:"name"`
	Namespace   string          `json:"namespace"`
	Port        int             `json:"port"`
	Concurrency int             `json:"concurrency"`
	Postgres    ServicePostgres `json:"postgres"`
	// OpenBao serves the worker and connector PKI CAs the key service trusts
	// for client certificates (unauthenticated ca/pem reads).
	OpenBao   string                     `json:"openBao"`
	Downloads *KeyServiceDownloadsConfig `json:"downloads,omitempty"`
}

// KeyServiceDownloadsConfig enables acquisition unwraps (ADR-204): the worker
// configuration ConfigMap selects the profile SQL must currently audit, and
// the topologies (plus the catalog's joined slots) bound retention.
type KeyServiceDownloadsConfig struct {
	RetentionTopologies []ServiceTopology `json:"retentionTopologies"`
	// RemoteClusters are the joined mode=cluster clusters' IDs; each gets
	// the in-process topology of the hub retention source.
	RemoteClusters []string `json:"remoteClusters,omitempty"`
}

type PublisherConfig struct {
	Name                string             `json:"name"`
	Namespace           string             `json:"namespace"`
	PollSeconds         int                `json:"pollSeconds"`
	Batch               int                `json:"batch"`
	Postgres            ServicePostgres    `json:"postgres"`
	AuditStore          ServiceObjectStore `json:"auditStore"`
	Evidence            ServiceObjectStore `json:"evidence"`
	OpenBao             string             `json:"openBao"`
	RetentionTopologies []ServiceTopology  `json:"retentionTopologies"`
	RemoteClusters      []string           `json:"remoteClusters,omitempty"`
}

// decodeServiceConfig is a closed decode (no unknown fields, one value) that,
// unlike the RPC codec, accepts Helm's rendering of omitted or reordered keys.
func decodeServiceConfig[T any](r io.Reader) (T, error) {
	var out T
	if r == nil {
		return out, errors.New("service config unavailable")
	}
	b, err := io.ReadAll(io.LimitReader(r, ServiceConfigMaxBytes+1))
	if err != nil || len(b) == 0 || len(b) > ServiceConfigMaxBytes {
		return out, errors.New("service config unavailable")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&out) != nil || d.Decode(new(any)) != io.EOF {
		var zero T
		return zero, errors.New("service config invalid")
	}
	return out, nil
}

func DecodeFederationConfig(r io.Reader) (FederationConfig, error) {
	return decodeServiceConfig[FederationConfig](r)
}
func DecodeKeyServiceConfig(r io.Reader) (KeyServiceConfig, error) {
	return decodeServiceConfig[KeyServiceConfig](r)
}
func DecodePublisherConfig(r io.Reader) (PublisherConfig, error) {
	return decodeServiceConfig[PublisherConfig](r)
}
