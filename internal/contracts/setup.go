package contracts

import "io"

// SetupFormat is the `asservat setup` configuration format, rendered by Helm
// into ConfigMap `<name>-setup-config`, key `config.json`.
const SetupFormat = "asservat-setup/v1"
const SetupMaxBytes = 64 << 10

// Fixed mount layout of the setup Job.
const (
	SetupRoot = "/run/asservat/setup"
	// SetupConfigFile is the Helm-rendered configuration.
	SetupConfigFile = SetupRoot + "/config.json"
	// SetupIDsRoot holds the `<name>-ids` Secret, one file per key.
	SetupIDsRoot = "/run/asservat/ids"
	// SetupSQLRoot holds every `<name>-sql-<component>` Secret in its own
	// subdirectory; each `sql-*.json` file is one OwnerSQLCredential.
	SetupSQLRoot = SetupRoot + "/sql"
	// SetupPostgresRoot holds `administrator.json` (role administration),
	// optional `ddl.json` (schema owner, defaults to the administrator) and
	// `ca.crt`.
	SetupPostgresRoot = SetupRoot + "/postgres"
	// SetupOpenBaoRoot holds `ca.crt` and the projected service account
	// `token` (audience SmallOpenBaoSetupAudience).
	SetupOpenBaoRoot = SetupRoot + "/openbao"
	// SetupObjectStoreRoot holds `ca.crt` and the bucket administrator's
	// `credentials.json` (SeaweedCredential for the bundled store, key
	// `administrator.json` of `<name>-objectstore-state`) and
	// `bucket-policies.json` (bucket name -> policy) of `<name>-objectstore-iam`.
	SetupObjectStoreRoot = SetupRoot + "/objectstore"
)

// SetupConfiguration contains only Helm-rendered values; generated IDs are
// read from SetupIDsRoot and credentials from the mounted Secrets.
type SetupConfiguration struct {
	Format string `json:"format"`
	// Name is `.Values.installation.name`, the prefix of every object name.
	Name string `json:"name"`
	// Namespace is the release (hub) namespace.
	Namespace string `json:"namespace"`
	// FleetSource is the fleet settings ConfigMap name in Namespace.
	FleetSource string           `json:"fleetSource"`
	Postgres    SetupPostgres    `json:"postgres"`
	OpenBao     SetupOpenBao     `json:"openBao"`
	ObjectStore SetupObjectStore `json:"objectStore"`
}

type SetupPostgres struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Database string `json:"database"`
}

type SetupOpenBao struct {
	Endpoint string `json:"endpoint"`
	// Bundled selects the bundled provider; an external provider is prepared
	// by its operator (docs/installation/helm.md, "External key service").
	Bundled bool `json:"bundled"`
	// Accounts are the service account names of the hub components that
	// authenticate to OpenBao, keyed by component (hub-api, hub-worker,
	// federation, publisher, key-service).
	Accounts map[string]string `json:"accounts"`
}

type SetupObjectStore struct {
	Endpoint string `json:"endpoint"`
	Region   string `json:"region"`
	// Bundled selects the bundled SeaweedFS store; an external store's buckets
	// are created by its operator.
	Bundled bool `json:"bundled"`
	// Buckets are the audit and evidence bucket names.
	AuditBucket    string `json:"auditBucket"`
	EvidenceBucket string `json:"evidenceBucket"`
}

func DecodeSetupConfiguration(r io.Reader) (SetupConfiguration, error) {
	return decodeClosedRPC[SetupConfiguration](r, SetupMaxBytes)
}
