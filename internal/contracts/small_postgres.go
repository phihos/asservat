package contracts

import (
	"io"
	"k8s.io/apimachinery/pkg/util/validation"
)

const SmallPostgresFormat = "asservat-small-postgres/v1"

// SmallPostgresPlan contains public choices only. All names and credentials are
// owned by the selected installation, independently of Helm release storage.
type SmallPostgresPlan struct {
	Format    string `json:"format"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Keycloak  bool   `json:"keycloak"`
}

func (p SmallPostgresPlan) Valid() bool {
	return p.Format == SmallPostgresFormat && len(p.Name) > 0 && len(p.Name) <= 30 && len(validation.IsDNS1123Label(p.Name)) == 0 && len(validation.IsDNS1123Label(p.Namespace)) == 0
}
func (p SmallPostgresPlan) StateSecretName() string { return p.Name + "-postgres-state" }
func (p SmallPostgresPlan) DataPVCName() string     { return p.Name + "-postgres-data" }
func (p SmallPostgresPlan) BackupPVCName() string   { return p.Name + "-postgres-backup" }
func (p SmallPostgresPlan) ServiceName() string     { return p.Name + "-postgres" }
func (p SmallPostgresPlan) Host() string            { return p.ServiceName() + "." + p.Namespace + ".svc" }
func (p SmallPostgresPlan) MaxConnections() int32 {
	if p.Keycloak {
		return 122
	}
	return 117
}
func DecodeSmallPostgresPlan(r io.Reader) (SmallPostgresPlan, error) {
	return decodeClosedRPC[SmallPostgresPlan](r, 2048)
}
