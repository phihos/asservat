package kubernetes

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// ADR-246 decision 9: the installer provisions the connector's node listener:
// a Secret the Deployment projects, a Service on 8444, the observer's four
// attestation reads and the public endpoint/root the chart's collector reads.
func TestRegionalCollectorProvisioning(t *testing.T) {
	var uid atomic.Int64
	api := fake.NewClientset(&core.Namespace{ObjectMeta: meta.ObjectMeta{Name: "asservat-collector", UID: types.UID(ownerID(90))}})
	api.PrependReactor("create", "*", func(a k8stesting.Action) (bool, runtime.Object, error) {
		o := a.(k8stesting.CreateAction).GetObject().(meta.Object)
		o.SetUID(types.UID(ownerID(int(100 + uid.Add(1)))))
		o.SetResourceVersion("created-version")
		return false, nil, nil
	})
	p := RegionalInstallPlan{Namespace: "asservat-connector", Collector: &RegionalCollectorPlan{Namespace: "asservat-collector", Name: "asservat-node"}}
	ctx := context.Background()
	c, nodes, err := ensureRegionalCollector(ctx, api, p, "installation/cluster")
	if err != nil {
		t.Fatal(err)
	}
	if c.Namespace != (contracts.WorkerObjectReference{Name: "asservat-collector", UID: ownerID(90)}) || c.DaemonSet != "asservat-node" || c.ServiceAccount != "asservat-node" {
		t.Fatal("collector input", c)
	}
	if nodes.Endpoint != "https://connector-nodes.asservat-connector.svc:8444" || nodes.ServerName != "connector-nodes.asservat-connector.svc" {
		t.Fatal("endpoint", nodes)
	}
	// The stored pair loads as the connector loads it and verifies against
	// the published CA root as the collector verifies it.
	secret, err := api.CoreV1().Secrets("asservat-connector").Get(ctx, RegionalNodes, meta.GetOptions{})
	if err != nil || !*secret.Immutable {
		t.Fatal("server Secret", err)
	}
	if nodes.serverInput != (contracts.ConnectorAPIInput{Kind: "Secret", Name: RegionalNodes, UID: string(secret.UID), ResourceVersion: secret.ResourceVersion, DedicatedToAPI: true}) {
		t.Fatal("listener input pin did not come from acknowledged Secret", nodes.serverInput)
	}
	pair, err := tls.X509KeyPair(secret.Data[contracts.RegionalNodeServerFile], secret.Data[contracts.RegionalNodeServerKeyFile])
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(nodes.RootsPEM))
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !root.IsCA {
		t.Fatal("published root is not a CA", err)
	}
	leaf, _ := x509.ParseCertificate(pair.Certificate[0])
	pool := x509.NewCertPool()
	pool.AddCert(root)
	if _, err = leaf.Verify(x509.VerifyOptions{DNSName: nodes.ServerName, Roots: pool}); err != nil || leaf.PublicKeyAlgorithm != x509.ECDSA {
		t.Fatal("leaf does not verify for the Service name", err)
	}
	if _, err = leaf.Verify(x509.VerifyOptions{DNSName: nodes.ServerName, Roots: pool, CurrentTime: time.Now().Add(9 * 365 * 24 * time.Hour)}); err != nil {
		t.Fatal("leaf validity shorter than documented", err)
	}
	published, err := api.CoreV1().ConfigMaps("asservat-connector").Get(ctx, RegionalNodes, meta.GetOptions{})
	if err != nil || published.Data["rootsPEM"] != nodes.RootsPEM || published.Data["endpoint"] != nodes.Endpoint || published.Data["serverName"] != nodes.ServerName {
		t.Fatal("published endpoint ConfigMap", err)
	}
	service, err := api.CoreV1().Services("asservat-connector").Get(ctx, RegionalNodes, meta.GetOptions{})
	if err != nil || service.Spec.Type != core.ServiceTypeClusterIP || len(service.Spec.Ports) != 1 || service.Spec.Ports[0].Port != 8444 || service.Spec.Ports[0].TargetPort.IntValue() != 8444 || service.Spec.Selector["app.kubernetes.io/name"] != "asservat-connector" {
		t.Fatal("node Service", err)
	}
	role, err := api.RbacV1().Roles("asservat-collector").Get(ctx, "asservat-connector-connector-nodes", meta.GetOptions{})
	if err != nil || len(role.Rules) != 2 {
		t.Fatal("attestation Role", err)
	}
	for _, r := range role.Rules {
		if len(r.Verbs) != 1 || r.Verbs[0] != "get" || r.Resources[0] == "daemonsets" && (len(r.ResourceNames) != 1 || r.ResourceNames[0] != "asservat-node") {
			t.Fatal("attestation Role beyond get pods and the named DaemonSet", r)
		}
	}
	binding, err := api.RbacV1().RoleBindings("asservat-collector").Get(ctx, role.Name, meta.GetOptions{})
	if err != nil || len(binding.Subjects) != 1 || binding.Subjects[0].Namespace != "asservat-connector" || binding.Subjects[0].Name != RegionalAccount {
		t.Fatal("attestation binding", err)
	}
	// A rerun reopens the certificate the collectors already pin.
	_, again, err := ensureRegionalCollector(ctx, api, p, "installation/cluster")
	if err != nil || again != nodes {
		t.Fatal("rerun replaced the listener certificate", err)
	}
	// Another installation's Secret is never adopted.
	if _, _, err = ensureRegionalCollector(ctx, api, p, "other/cluster"); !errors.Is(err, cfg.ErrChanged) {
		t.Fatal("foreign listener objects adopted", err)
	}
	// A missing collector namespace stops the step.
	missing := p
	missing.Collector = &RegionalCollectorPlan{Namespace: "absent", Name: "asservat-node"}
	if _, _, err = ensureRegionalCollector(ctx, api, missing, "installation/cluster"); err == nil {
		t.Fatal("collector input without its namespace")
	}
}

func TestRegionalCollectorShape(t *testing.T) {
	for _, bad := range []RegionalCollectorPlan{{Namespace: "asservat-connector", Name: "n"}, {Namespace: "kube-system", Name: "n"}, {Namespace: "default", Name: "n"}, {Namespace: "Upper", Name: "n"}, {Namespace: "c", Name: ""}} {
		if (&bad).valid("asservat-connector") {
			t.Fatal("collector plan accepted", bad)
		}
	}
	if !(&RegionalCollectorPlan{Namespace: "asservat-collector", Name: "asservat-node"}).valid("asservat-connector") || !(*RegionalCollectorPlan)(nil).valid("asservat-connector") {
		t.Fatal("collector plan refused")
	}
	offer := contracts.RegionalOffer{InstallationID: ownerID(1), Image: "registry.invalid/asservat@sha256:" + "ab"}
	secrets := 0
	for _, s := range RegionalWorkload(offer, false, true).Spec.Template.Spec.Volumes[0].Projected.Sources {
		if s.Secret != nil {
			if s.Secret.Name != RegionalNodes || len(s.Secret.Items) != 2 || s.Secret.Items[0].Path != contracts.RegionalNodeServerFile || s.Secret.Items[1].Path != contracts.RegionalNodeServerKeyFile {
				t.Fatal("collector connector mounts another Secret", s.Secret.Name)
			}
			secrets++
		}
	}
	if secrets != 1 {
		t.Fatal("collector connector does not mount its listener Secret")
	}
	// A stored pair for another name or with a mismatched key is refused.
	chain, key, err := newRegionalNodeCertificate("connector-nodes.a.svc", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = regionalNodeRoots(chain, key, "connector-nodes.b.svc", time.Now()); !errors.Is(err, cfg.ErrChanged) {
		t.Fatal("certificate for another Service name reopened")
	}
	_, other, _ := newRegionalNodeCertificate("connector-nodes.a.svc", time.Now())
	if _, err = regionalNodeRoots(chain, other, "connector-nodes.a.svc", time.Now()); !errors.Is(err, cfg.ErrChanged) {
		t.Fatal("mismatched key reopened")
	}
	if _, err = regionalNodeRoots(chain, key, "connector-nodes.a.svc", time.Now()); err != nil {
		t.Fatal("own pair refused", err)
	}
}
