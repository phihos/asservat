package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type helmOriginalStorage struct {
	installation string
	request      string
	seedUID      types.UID
	credential   contracts.OwnerStorageCredential
	err          error
}

type helmBundledObjectStore struct {
	plan                         contracts.SmallSeaweedPlan
	storage                      chan helmOriginalStorage
	stateUID, iamUID, bindingUID types.UID
	seedUID                      types.UID
	installation                 string
	iamVersion, bindingVersion   string
	iamData                      []byte
	bindingData                  string
}

// This is fixture storage administration inside the owned Kind node only. A
// static local PV avoids installing another storage operator. Its advertised
// size is configuration, not a measured capacity or durability guarantee.
func newHelmBundledObjectStore(t *testing.T, ctx context.Context, api kubernetes.Interface, d contracts.InitialBootstrap, x helmBootstrapFixture) *helmBundledObjectStore {
	t.Helper()
	p := contracts.SmallSeaweedPlan{Format: contracts.SmallSeaweedFormat, Namespace: d.BootstrapNamespace, Name: d.Name, Image: x.ObjectStoreImage}
	if !p.Valid() {
		t.Fatal("selected actual chart object-store image unavailable")
	}
	node, err := api.CoreV1().Nodes().Get(ctx, x.NodeA, meta.GetOptions{})
	if err != nil || string(node.UID) != x.NodeAUID || node.Labels[core.LabelHostname] == "" {
		t.Fatal("owned PV node changed", err)
	}
	directory := "/var/local/asservat-bundled-s3/" + p.Namespace + "/" + p.Name
	output, err := exec.CommandContext(ctx, "docker", "exec", x.NodeA, "install", "-d", "-m", "0700", "-o", "65532", "-g", "65532", directory).CombinedOutput()
	if err != nil {
		t.Fatalf("owned node backing directory: %v %s", err, output)
	}
	pvName := p.Namespace + "-objectstore"
	volume, err := api.CoreV1().PersistentVolumes().Create(ctx, &core.PersistentVolume{ObjectMeta: meta.ObjectMeta{Name: pvName, Labels: map[string]string{"asservat.test.owner": p.Namespace}}, Spec: core.PersistentVolumeSpec{Capacity: core.ResourceList{core.ResourceStorage: resource.MustParse("32Gi")}, AccessModes: []core.PersistentVolumeAccessMode{core.ReadWriteOnce}, PersistentVolumeReclaimPolicy: core.PersistentVolumeReclaimRetain, StorageClassName: "asservat-owned-local", ClaimRef: &core.ObjectReference{Namespace: p.Namespace, Name: p.DataPVCName()}, PersistentVolumeSource: core.PersistentVolumeSource{Local: &core.LocalVolumeSource{Path: directory}}, NodeAffinity: &core.VolumeNodeAffinity{Required: &core.NodeSelector{NodeSelectorTerms: []core.NodeSelectorTerm{{MatchExpressions: []core.NodeSelectorRequirement{{Key: core.LabelHostname, Operator: core.NodeSelectorOpIn, Values: []string{node.Labels[core.LabelHostname]}}}}}}}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal("owned empty static local PV", err)
	}
	t.Cleanup(func() {
		if keepFailedFixture(t) {
			return
		}
		cleanup, end := context.WithTimeout(context.Background(), 60*time.Second)
		defer end()
		got, e := api.CoreV1().PersistentVolumes().Get(cleanup, pvName, meta.GetOptions{})
		if apierrors.IsNotFound(e) {
			return
		}
		if e != nil || got.UID != volume.UID || got.Labels["asservat.test.owner"] != p.Namespace {
			t.Error("owned local PV cleanup identity", e)
			return
		}
		if e = api.CoreV1().PersistentVolumes().Delete(cleanup, pvName, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &volume.UID}}); e != nil && !apierrors.IsNotFound(e) {
			t.Error("owned local PV cleanup", e)
		}
	})
	b := &helmBundledObjectStore{plan: p, storage: make(chan helmOriginalStorage, 1)}
	observer, cancel := context.WithCancel(ctx)
	list, err := api.CoreV1().Secrets(p.Namespace).List(observer, meta.ListOptions{FieldSelector: "metadata.name=" + p.Name + "-bootstrap-state", Limit: 2})
	if err != nil || len(list.Items) != 0 || list.ResourceVersion == "" {
		cancel()
		t.Fatal("original generated-key observation requires fresh absence", err)
	}
	stream, err := api.CoreV1().Secrets(p.Namespace).Watch(observer, meta.ListOptions{FieldSelector: "metadata.name=" + p.Name + "-bootstrap-state", ResourceVersion: list.ResourceVersion})
	if err != nil {
		cancel()
		t.Fatal("original generated-key watch", err)
	}
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		defer stream.Stop()
		for events := 0; events < 128; events++ {
			select {
			case <-observer.Done():
				return
			case event, ok := <-stream.ResultChan():
				if !ok || event.Type == watch.Error || event.Type == watch.Deleted {
					b.storage <- helmOriginalStorage{err: errors.New("original generated-key event unavailable")}
					return
				}
				secret, ok := event.Object.(*core.Secret)
				if !ok {
					continue
				}
				state, e := contracts.DecodeInitialBootstrapState(bytes.NewReader(secret.Data["state.json"]))
				for _, raw := range secret.Data {
					clear(raw)
				}
				if e != nil {
					b.storage <- helmOriginalStorage{err: errors.New("original generated-key state invalid")}
					return
				}
				if state.Material == nil || state.Material.Storage.AccessKeyID == "" {
					continue
				}
				c := state.Material.Storage
				bound := contracts.SeaweedCredential{Principal: contracts.SeaweedPrincipalKey{Purpose: "initial-audit", ScopeID: state.InstallationID}, AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey}
				if c.SessionToken != "" || providerconfig.ValidateSeaweedCredential(bound) != nil {
					b.storage <- helmOriginalStorage{err: errors.New("original stored credential was not generated and scoped")}
					return
				}
				b.storage <- helmOriginalStorage{installation: state.InstallationID, request: state.RequestID, seedUID: secret.UID, credential: c}
				return
			}
		}
		b.storage <- helmOriginalStorage{err: errors.New("original generated-key event bound exhausted")}
	}()
	t.Cleanup(func() { cancel(); stream.Stop(); <-joined; clear(b.iamData) })
	return b
}

func (b *helmBundledObjectStore) Values(values map[string]any) {
	services, ok := values["services"].(map[string]any)
	if !ok {
		services = map[string]any{}
		values["services"] = services
	}
	services["objectStore"] = map[string]any{"provider": "seaweedfs", "seaweedfs": map[string]any{"image": b.plan.Image, "persistence": map[string]any{"storageClass": "asservat-owned-local", "size": "32Gi"}}}
}

// Verify using the exact credential observed from the acknowledged original
// bootstrap state. It never regenerates a candidate or uses the backend admin
// to read the activation audit. Host transport keeps the real TLS/SigV4 origin.
func (b *helmBundledObjectStore) VerifiedStore(t *testing.T, ctx context.Context, api kubernetes.Interface, kc *rest.Config, input contracts.InitialBootstrapInput, token []byte, node *core.Node) (contracts.InitialBootstrap, *s3.Client) {
	t.Helper()
	var original helmOriginalStorage
	select {
	case original = <-b.storage:
	case <-ctx.Done():
		t.Fatal("original stored generated credential missing")
	}
	if original.err != nil {
		t.Fatal(original.err)
	}
	b.seedUID, b.installation = original.seedUID, original.installation
	state, err := api.CoreV1().Secrets(b.plan.Namespace).Get(ctx, b.plan.StateSecretName(), meta.GetOptions{})
	if err != nil || kube.ValidateSmallSeaweedMaterial(b.plan, state.Data, time.Now()) != nil {
		t.Fatal("actual bundled provider state", err)
	}
	defer func() {
		for _, v := range state.Data {
			clear(v)
		}
	}()
	b.stateUID = state.UID
	input.AuditStore.RootsPEM = string(state.Data["ca.crt"])
	input.AuditStore.RootsSource = ""
	desired, err := providerconfig.CompileInitialBootstrapInput(input, kc.CAData, token, time.Now())
	if err != nil {
		t.Fatal("full canonical bundled trust compilation", err)
	}
	iam, err := api.CoreV1().Secrets(b.plan.Namespace).Get(ctx, b.plan.IAMSecretName(), meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, v := range iam.Data {
			clear(v)
		}
	}()
	var database struct {
		Identities []struct {
			Name        string `json:"name"`
			Credentials []struct {
				Access string `json:"accessKey"`
				Secret string `json:"secretKey"`
			} `json:"credentials"`
		} `json:"identities"`
	}
	if json.Unmarshal(iam.Data[providerconfig.SeaweedConfigKey], &database) != nil {
		t.Fatal("actual IAM database")
	}
	name, _ := providerconfig.SeaweedPrincipalName(contracts.SeaweedPrincipalKey{Purpose: "initial-audit", ScopeID: original.installation})
	matched := 0
	for _, identity := range database.Identities {
		if identity.Name == name && len(identity.Credentials) == 1 && identity.Credentials[0].Access == original.credential.AccessKeyID && identity.Credentials[0].Secret == original.credential.SecretAccessKey {
			matched++
		}
	}
	if matched != 1 {
		t.Fatal("provider did not bind the exact original stored generated credential")
	}
	b.iamUID, b.iamVersion, b.iamData = iam.UID, iam.ResourceVersion, bytes.Clone(iam.Data[providerconfig.SeaweedConfigKey])
	binding, err := api.CoreV1().ConfigMaps(b.plan.Namespace).Get(ctx, b.plan.ServiceName()+"-binding", meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var receipt contracts.SmallSeaweedBinding
	if json.Unmarshal([]byte(binding.Data[contracts.SmallSeaweedBindingFile]), &receipt) != nil || receipt.Initialization.Pending || receipt.Initialization.InstallationID != original.installation || receipt.RequestID != original.request {
		t.Fatal("original bucket readiness binding")
	}
	b.bindingUID, b.bindingVersion, b.bindingData = binding.UID, binding.ResourceVersion, binding.Data[contracts.SmallSeaweedBindingFile]
	pvc, err := api.CoreV1().PersistentVolumeClaims(b.plan.Namespace).Get(ctx, b.plan.DataPVCName(), meta.GetOptions{})
	if err != nil || pvc.Status.Phase != core.ClaimBound || pvc.Spec.VolumeName != b.plan.Namespace+"-objectstore" {
		t.Fatal("actual chart PVC did not bind owned local PV", err)
	}
	service, err := api.CoreV1().Services(b.plan.Namespace).Create(ctx, &core.Service{ObjectMeta: meta.ObjectMeta{Name: b.plan.ServiceName() + "-inspection"}, Spec: core.ServiceSpec{Type: core.ServiceTypeNodePort, Selector: map[string]string{"asservat.io/objectstore": b.plan.ServiceName()}, Ports: []core.ServicePort{{Port: 8333}}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal("owned independent S3 inspection route", err)
	}
	address := ""
	for _, entry := range node.Status.Addresses {
		if entry.Type == core.NodeInternalIP {
			address = net.JoinHostPort(entry.Address, strconv.Itoa(int(service.Spec.Ports[0].NodePort)))
		}
	}
	if address == "" {
		t.Fatal("owned inspection node address")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(state.Data["ca.crt"]) {
		t.Fatal("actual backend roots")
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}, DialContext: func(call context.Context, network, target string) (net.Conn, error) {
		if target != b.plan.Host()+":8333" {
			return nil, errors.New("foreign inspection destination")
		}
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(call, network, address)
	}}
	t.Cleanup(transport.CloseIdleConnections)
	client := s3.New(s3.Options{Region: desired.AuditStore.Region, BaseEndpoint: aws.String(b.plan.Endpoint()), UsePathStyle: true, Credentials: credentials.NewStaticCredentialsProvider(original.credential.AccessKeyID, original.credential.SecretAccessKey, ""), HTTPClient: &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}})
	return desired, client
}

func (b *helmBundledObjectStore) VerifyReplay(t *testing.T, ctx context.Context, api kubernetes.Interface) {
	t.Helper()
	state, e := api.CoreV1().Secrets(b.plan.Namespace).Get(ctx, b.plan.StateSecretName(), meta.GetOptions{})
	if e != nil || state.UID != b.stateUID {
		t.Fatal("replay replaced original object-store state", e)
	}
	for _, v := range state.Data {
		clear(v)
	}
	iam, e := api.CoreV1().Secrets(b.plan.Namespace).Get(ctx, b.plan.IAMSecretName(), meta.GetOptions{})
	if e != nil || iam.UID != b.iamUID || iam.ResourceVersion != b.iamVersion || !bytes.Equal(iam.Data[providerconfig.SeaweedConfigKey], b.iamData) {
		t.Fatal("replay regenerated original provider credentials", e)
	}
	for _, v := range iam.Data {
		clear(v)
	}
	binding, e := api.CoreV1().ConfigMaps(b.plan.Namespace).Get(ctx, b.plan.ServiceName()+"-binding", meta.GetOptions{})
	if e != nil || binding.UID != b.bindingUID || binding.ResourceVersion != b.bindingVersion || binding.Data[contracts.SmallSeaweedBindingFile] != b.bindingData {
		t.Fatal("replay changed original bucket binding", e)
	}
}
