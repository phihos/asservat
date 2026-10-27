package kubernetes

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"
)

// RegionalNodes names the connector's node listener objects in the connector
// namespace (ADR-246 decision 9): the server certificate Secret, the
// ClusterIP Service and the public ConfigMap holding the chart's
// collector.connector values.
const (
	RegionalNodes = "connector-nodes"
	// The listener certificate has no renewal path: rotating it means
	// reinstalling the connector, like every other fixed regional input.
	regionalNodeValidity = 10 * 365 * 24 * time.Hour
)

// RegionalCollectorPlan names the chart's collector namespace and the name
// its DaemonSet and service account share (`<release>-node`).
type RegionalCollectorPlan struct {
	Namespace string
	Name      string
}

// RegionalNodeEndpoint is the public collector.connector value set: the
// listener's in-cluster endpoint, the certificate's server name and the PEM
// root that issued it. It holds no credential.
type RegionalNodeEndpoint struct {
	Endpoint   string `json:"endpoint"`
	ServerName string `json:"serverName"`
	RootsPEM   string `json:"rootsPEM"`
	// serverInput is installation-only metadata from the acknowledged Secret,
	// never another public endpoint field or copied key material.
	serverInput contracts.ConnectorAPIInput
}

func (c *RegionalCollectorPlan) valid(connector string) bool {
	return c == nil || identity.Text(c.Namespace, 63) && len(validation.IsDNS1123Label(c.Namespace)) == 0 && !strings.HasPrefix(c.Namespace, "kube-") && c.Namespace != "default" && c.Namespace != connector &&
		len(validation.IsDNS1123Subdomain(c.Name)) == 0
}

// regionalNodeEndpoint is the fixed Service DNS name and port 8444.
func regionalNodeEndpoint(namespace string) (endpoint, serverName string) {
	serverName = RegionalNodes + "." + namespace + ".svc"
	return "https://" + serverName + contracts.RegionalNodeListenAddress, serverName
}

// regionalCollectorRBAC is the observer account's attestation reads in the
// collector namespace: the token's Pod and the named DaemonSet. TokenReview
// create is already in regionalRBAC; get nodes is added cluster-wide by the
// caller (Nodes are cluster-scoped).
func regionalCollectorRBAC(connector string, c RegionalCollectorPlan) *rbac.Role {
	return &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: connector + "-connector-nodes"}, Rules: []rbac.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
		{APIGroups: []string{"apps"}, Resources: []string{"daemonsets"}, ResourceNames: []string{c.Name}, Verbs: []string{"get"}},
	}}
}

// regionalNodeInputReadRule permits the executor's existing input-proof check
// to read metadata of the exact listener Secret it already projects. Kubernetes
// RBAC cannot constrain GET to metadata, so no other name/list/watch is granted.
func regionalNodeInputReadRule() rbac.PolicyRule {
	return rbac.PolicyRule{APIGroups: []string{""}, Resources: []string{"secrets"}, ResourceNames: []string{RegionalNodes}, Verbs: []string{"get"}}
}

func regionalNodeReadRule() rbac.PolicyRule {
	return rbac.PolicyRule{APIGroups: []string{""}, Resources: []string{"nodes"}, Verbs: []string{"get"}}
}

// regionalNodeService exposes the connector Pod's node listener in-cluster.
func regionalNodeService() *core.Service {
	return &core.Service{ObjectMeta: meta.ObjectMeta{Name: RegionalNodes}, Spec: core.ServiceSpec{Type: core.ServiceTypeClusterIP,
		Selector: map[string]string{"app.kubernetes.io/name": "asservat-connector"},
		Ports:    []core.ServicePort{{Name: "nodes", Protocol: core.ProtocolTCP, Port: 8444, TargetPort: intstr.FromInt32(8444)}}}}
}

// ensureRegionalCollector provisions the connector's `collector` input: the
// attestation Role and binding in the collector namespace, the listener's
// server certificate Secret (generated once, reopened on reruns), the Service
// and the public endpoint ConfigMap. The collector namespace must exist.
func ensureRegionalCollector(ctx context.Context, api kubernetes.Interface, p RegionalInstallPlan, marker string) (contracts.RegionalCollector, RegionalNodeEndpoint, error) {
	var none contracts.RegionalCollector
	c := *p.Collector
	ns, err := api.CoreV1().Namespaces().Get(ctx, c.Namespace, meta.GetOptions{})
	if err != nil {
		return none, RegionalNodeEndpoint{}, &regionalAPIError{reason: string(apierrors.ReasonForError(err))}
	}
	if ns.DeletionTimestamp != nil || ref(ns.ObjectMeta).UID == "" {
		return none, RegionalNodeEndpoint{}, cfg.ErrUnavailable
	}
	role := regionalCollectorRBAC(p.Namespace, c)
	if _, err = ensureRegional(ctx, api.RbacV1().Roles(c.Namespace), role, marker); err != nil {
		return none, RegionalNodeEndpoint{}, err
	}
	if _, err = ensureRegional(ctx, api.RbacV1().RoleBindings(c.Namespace), &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: role.Name}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: role.Name},
		Subjects: []rbac.Subject{{Kind: "ServiceAccount", Namespace: p.Namespace, Name: RegionalAccount}}}, marker); err != nil {
		return none, RegionalNodeEndpoint{}, err
	}
	endpoint, serverName := regionalNodeEndpoint(p.Namespace)
	roots, serverInput, err := ensureRegionalNodeSecret(ctx, api, p.Namespace, serverName, marker)
	if err != nil {
		return none, RegionalNodeEndpoint{}, err
	}
	if _, err = ensureRegional(ctx, api.CoreV1().Services(p.Namespace), regionalNodeService(), marker); err != nil {
		return none, RegionalNodeEndpoint{}, err
	}
	out := RegionalNodeEndpoint{Endpoint: endpoint, ServerName: serverName, RootsPEM: roots, serverInput: serverInput}
	if _, err = ensureRegional(ctx, api.CoreV1().ConfigMaps(p.Namespace), &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: RegionalNodes}, Immutable: ptr.To(true),
		Data: map[string]string{"endpoint": out.Endpoint, "serverName": out.ServerName, "rootsPEM": out.RootsPEM}}, marker); err != nil {
		return none, RegionalNodeEndpoint{}, err
	}
	return contracts.RegionalCollector{Namespace: ref(ns.ObjectMeta), DaemonSet: c.Name, ServiceAccount: c.Name}, out, nil
}

// ensureRegionalNodeSecret creates the immutable listener Secret with a fresh
// key, or reopens this installation's existing one: a rerun must not replace
// a certificate the collectors already pin. It returns the PEM root.
func ensureRegionalNodeSecret(ctx context.Context, api kubernetes.Interface, namespace, serverName, marker string) (string, contracts.ConnectorAPIInput, error) {
	secrets := api.CoreV1().Secrets(namespace)
	existing, err := secrets.Get(ctx, RegionalNodes, meta.GetOptions{})
	switch {
	case err == nil:
		if existing.DeletionTimestamp != nil || existing.Annotations[regionalInstall] != marker {
			return "", contracts.ConnectorAPIInput{}, cfg.ErrChanged
		}
	case apierrors.IsNotFound(err):
		chain, key, err := newRegionalNodeCertificate(serverName, time.Now())
		defer clear(key)
		if err != nil {
			return "", contracts.ConnectorAPIInput{}, cfg.ErrUnavailable
		}
		if existing, err = ensureRegional(ctx, secrets, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: RegionalNodes}, Type: core.SecretTypeOpaque, Immutable: ptr.To(true),
			Data: map[string][]byte{contracts.RegionalNodeServerFile: chain, contracts.RegionalNodeServerKeyFile: key}}, marker); err != nil {
			return "", contracts.ConnectorAPIInput{}, err
		}
	default:
		return "", contracts.ConnectorAPIInput{}, &regionalAPIError{reason: string(apierrors.ReasonForError(err))}
	}
	roots, err := regionalNodeRoots(existing.Data[contracts.RegionalNodeServerFile], existing.Data[contracts.RegionalNodeServerKeyFile], serverName, time.Now())
	if err != nil {
		return "", contracts.ConnectorAPIInput{}, err
	}
	return roots, contracts.ConnectorAPIInput{Kind: "Secret", Name: RegionalNodes, UID: string(existing.UID), ResourceVersion: existing.ResourceVersion, DedicatedToAPI: true}, nil
}

// newRegionalNodeCertificate makes a P-256 root and a server leaf for the
// Service DNS name. The root's key is discarded after signing; the collector
// requires a CA root (node.go), so the leaf cannot be self-signed. The chain
// file holds the leaf, then the root.
func newRegionalNodeCertificate(serverName string, now time.Time) (chain, keyPEM []byte, err error) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	start, end := now.Add(-5*time.Minute).UTC().Truncate(time.Second), now.Add(regionalNodeValidity).UTC().Truncate(time.Second)
	serial := func() (*big.Int, error) { return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127)) }
	rs, err := serial()
	if err != nil {
		return nil, nil, err
	}
	root := &x509.Certificate{SerialNumber: rs, Subject: pkix.Name{CommonName: "asservat connector node listener root"}, NotBefore: start, NotAfter: end,
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, err
	}
	if root, err = x509.ParseCertificate(rootDER); err != nil {
		return nil, nil, err
	}
	ls, err := serial()
	if err != nil {
		return nil, nil, err
	}
	leaf := &x509.Certificate{SerialNumber: ls, Subject: pkix.Name{CommonName: serverName}, DNSNames: []string{serverName}, NotBefore: start, NotAfter: end,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	defer clear(keyDER)
	if err != nil {
		return nil, nil, err
	}
	chain = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})...)
	return chain, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

// regionalNodeRoots checks a stored pair exactly as the connector loads it
// and as the collector verifies it: key matches, the leaf chains to the CA
// root for serverName at now. It returns that root's PEM.
func regionalNodeRoots(chain, key []byte, serverName string, now time.Time) (string, error) {
	pair, err := tls.X509KeyPair(chain, key)
	if err != nil || len(pair.Certificate) != 2 {
		return "", cfg.ErrChanged
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return "", cfg.ErrChanged
	}
	root, err := x509.ParseCertificate(pair.Certificate[1])
	if err != nil || !root.IsCA {
		return "", cfg.ErrChanged
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	if _, err = leaf.Verify(x509.VerifyOptions{DNSName: serverName, Roots: pool, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return "", cfg.ErrChanged
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})), nil
}
