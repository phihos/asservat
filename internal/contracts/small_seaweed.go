package contracts

import (
	"io"
	"k8s.io/apimachinery/pkg/util/validation"
	"regexp"
)

const SmallSeaweedFormat = "asservat-small-seaweed/v1"
const SmallSeaweedStateLimit = 32 << 10
const SmallSeaweedAdminKey = "administrator.json"
const SmallSeaweedBackendKey = "backend-id"
const SmallSeaweedInitializationKey = "initialization-id"
const SmallSeaweedPlanKey = "plan.json"

var smallSeaweedImage = regexp.MustCompile(`^[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}$`)

// This public infrastructure plan deliberately has no root/installation ID.
// Those IDs are minted later by the existing installation-state producer.
type SmallSeaweedPlan struct {
	Format    string `json:"format"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Image     string `json:"image"`
}

func (p SmallSeaweedPlan) Valid() bool {
	return p.Format == SmallSeaweedFormat && len(p.Name) > 0 && len(p.Name) <= 30 && len(validation.IsDNS1123Label(p.Name)) == 0 && len(validation.IsDNS1123Label(p.Namespace)) == 0 && smallSeaweedImage.MatchString(p.Image)
}
func (p SmallSeaweedPlan) ServiceName() string     { return p.Name + "-objectstore" }
func (p SmallSeaweedPlan) StateSecretName() string { return p.ServiceName() + "-state" }
func (p SmallSeaweedPlan) IAMSecretName() string   { return p.ServiceName() + "-iam" }
func (p SmallSeaweedPlan) DataPVCName() string {
	return p.ServiceName() + "-data"
}
func (p SmallSeaweedPlan) Host() string     { return p.ServiceName() + "." + p.Namespace + ".svc" }
func (p SmallSeaweedPlan) Endpoint() string { return "https://" + p.Host() + ":8333" }
func DecodeSmallSeaweedPlan(r io.Reader) (SmallSeaweedPlan, error) {
	return decodeClosedRPC[SmallSeaweedPlan](r, 2048)
}

// SmallSeaweedPrepared is private setup output. Admin must never be passed to
// ordinary runtime credential projections. No root or bucket is activated.
type SmallSeaweedPrepared struct {
	State            WorkerObjectReference
	IAM              WorkerObjectReference
	BackendID        string
	InitializationID string
	RootsPEM         []byte
	Admin            SeaweedCredential
}
