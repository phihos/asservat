package contracts

import (
	"crypto/x509"
	"io"
	"net/url"
	"regexp"

	"k8s.io/apimachinery/pkg/util/validation"
)

const SmallOpenBaoFormat = "asservat-small-openbao/v1"
const SmallOpenBaoImage = "ghcr.io/openbao/openbao@sha256:5046911075e137e154ce49ab051502f4ec7cf367d484ae4a4dce665d9b90561f"
const SmallOpenBaoVersion = "2.7.2"
const SmallOpenBaoPlanLimit = 96 << 10
const SmallOpenBaoStateLimit = 192 << 10
const SmallOpenBaoRoot = "/run/asservat/openbao"
const SmallOpenBaoData = "/data"
const SmallOpenBaoExecutable = "/usr/bin/bao"
const SmallOpenBaoPlanKey = "plan.json"
const SmallOpenBaoBackendKey = "backend-id"
const SmallOpenBaoSealKey = "seal.key"
const SmallOpenBaoConfigKey = "config.hcl"
const SmallOpenBaoSetupMount = "asservat-setup"
const SmallOpenBaoSetupRole = "asservat-setup"
const SmallOpenBaoSetupPolicy = "asservat-setup"
const SmallOpenBaoSetupAudience = "https://asservat.io/openbao/setup"
const SmallOpenBaoConfigurationAuthMount = "asservat-configuration"
const SmallOpenBaoOwnerAuthMount = "asservat-owner"
const SmallOpenBaoBackendPolicyName = "asservat-backend"
const SmallOpenBaoBackendPolicyPath = "sys/policies/acl/" + SmallOpenBaoBackendPolicyName
const SmallOpenBaoAuditMount = "asservat-audit"
const SmallOpenBaoTransitMount = "public-transit"
const SmallOpenBaoOwnerPKIMount = "owner-pki"
const SmallOpenBaoConnectorPKIMount = "connector-pki"
const SmallOpenBaoWorkerPKIMount = "worker-pki"
const SmallOpenBaoBootstrapMount = "fleet-bootstrap"
const SmallOpenBaoInitialIssuerRole = "asservat-install-issuer-issue"

func SmallOpenBaoInitialProviders() InitialBootstrapProviders {
	return InitialBootstrapProviders{IssuerPolicy: "asservat-install-issuer", WrapRole: "asservat-install-wrap", WrapPolicy: "asservat-install-encrypt", UnwrapRole: "asservat-install-unwrap", UnwrapPolicy: "asservat-install-decrypt"}
}

var smallOpenBaoImage = regexp.MustCompile(`^[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}$`)

// SmallOpenBaoPlan is public, derived infrastructure input. SetupAccount must
// name the fixed trusted setup runner; it is not an operator-selected identity
// or an Asservat evidence/installation authority.
type SmallOpenBaoPlan struct {
	Format       string                `json:"format"`
	Namespace    string                `json:"namespace"`
	Name         string                `json:"name"`
	Image        string                `json:"image"`
	Kubernetes   OwnerProviderEndpoint `json:"kubernetes"`
	SetupAccount string                `json:"setupAccount"`
}

func (p SmallOpenBaoPlan) Valid() bool {
	u, err := url.Parse(p.Kubernetes.Endpoint)
	if p.Format != SmallOpenBaoFormat || len(p.Name) < 1 || len(p.Name) > 30 || len(validation.IsDNS1123Label(p.Name)) != 0 || len(validation.IsDNS1123Label(p.Namespace)) != 0 || len(p.Image) > 512 || !smallOpenBaoImage.MatchString(p.Image) || p.SetupAccount != p.Name+"-bootstrap-runner" || err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || len(p.Kubernetes.Endpoint) > 2048 || len(p.Kubernetes.Roots) < 1 || len(p.Kubernetes.Roots) > 4 {
		return false
	}
	for i, der := range p.Kubernetes.Roots {
		c, err := x509.ParseCertificate(der)
		if err != nil || len(der) > 16<<10 || !c.IsCA || !c.BasicConstraintsValid {
			return false
		}
		for _, old := range p.Kubernetes.Roots[:i] {
			if string(old) == string(der) {
				return false
			}
		}
	}
	return true
}

func (p SmallOpenBaoPlan) ServiceName() string     { return p.Name + "-openbao" }
func (p SmallOpenBaoPlan) StateSecretName() string { return p.ServiceName() + "-state" }
func (p SmallOpenBaoPlan) DataPVCName() string     { return p.ServiceName() + "-data" }
func (p SmallOpenBaoPlan) Host() string            { return p.ServiceName() + "." + p.Namespace + ".svc" }
func (p SmallOpenBaoPlan) Endpoint() string        { return "https://" + p.Host() + ":8200" }
func (p SmallOpenBaoPlan) SetupAudience() string   { return SmallOpenBaoSetupAudience }

func DecodeSmallOpenBaoPlan(r io.Reader) (SmallOpenBaoPlan, error) {
	return decodeClosedRPC[SmallOpenBaoPlan](r, SmallOpenBaoPlanLimit)
}

// SmallOpenBaoServerCommand is a fresh fixed slice, overriding the upstream
// image's dev-mode default and privileged entrypoint.
func SmallOpenBaoServerCommand() []string {
	return []string{SmallOpenBaoExecutable, "server", "-config=" + SmallOpenBaoRoot + "/" + SmallOpenBaoConfigKey}
}
