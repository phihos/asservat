package fleet

import (
	"time"

	auditport "asservat.local/asservat/internal/application/audit"
)

// FleetBootstrapIssuance holds hub-api's shared bootstrap issuance
// dependencies: the protected fleet settings and the audited credential,
// record and activation effects. The installation's own and each remote
// Helm-registered cluster's bootstrap (hub_api_local_bootstrap.go,
// hub_api_remote_clusters.go) combine them with a reservation fixed to that
// cluster and peer; there is no operator-driven issuance.
type FleetBootstrapIssuance struct {
	Settings    AdministrationReader
	Credentials BootstrapCredentials
	Records     BootstrapCredentialRecorder
	Audits      auditport.BootstrapIssueLedger
	Objects     auditport.BootstrapIssueWriter
	Activation  BootstrapActivator
	Now         func() time.Time
}
