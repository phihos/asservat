package contracts

import "io"

const WorkerNativeStartupFormat = "asservat-context-native-startup/v1"
const WorkerStoreCredentialsPath = "/run/asservat/native-store/credentials.json"
const WorkerStoreCredentialsMaxBytes = 16 << 10

// Public installation pins, never per-request work or a disclosure grant.
type WorkerNativeControl struct {
	Format              string                 `json:"format"`
	ExchangeEndpoint    string                 `json:"exchangeEndpoint"`
	ExchangeServerRoots [][]byte               `json:"exchangeServerRoots"`
	ObjectStore         WorkerNativeStore      `json:"objectStore"`
	KeyService          WorkerNativeKeyService `json:"keyService"`
}

type WorkerNativeStore struct {
	ID                   string   `json:"id"`
	Endpoint             string   `json:"endpoint"`
	Region               string   `json:"region"`
	Bucket               string   `json:"bucket"`
	ServerRoots          [][]byte `json:"serverRoots"`
	CredentialSecretName string   `json:"credentialSecretName"`
	CredentialSecretUID  string   `json:"credentialSecretUID"`
}

type WorkerNativeKeyService struct {
	Endpoint    string   `json:"endpoint"`
	ServerRoots [][]byte `json:"serverRoots"`
	Scope       KeyScope `json:"scope"`
}

// Secret file at one fixed read-only projection; it cannot choose an endpoint,
// principal, callback, filesystem path or credential fallback mechanism.
type WorkerStoreCredentials struct {
	AccessKeyID     string `json:"accessKeyID"`
	SecretAccessKey string `json:"secretAccessKey"`
	SessionToken    string `json:"sessionToken,omitempty"`
	ExpiresAt       string `json:"expiresAt,omitempty"`
}

func DecodeWorkerStoreCredentials(r io.Reader) (WorkerStoreCredentials, error) {
	return decodeClosedRPC[WorkerStoreCredentials](r, WorkerStoreCredentialsMaxBytes)
}

func (WorkerStoreCredentials) String() string   { return "protected worker storage credentials" }
func (WorkerStoreCredentials) GoString() string { return "protected worker storage credentials" }
