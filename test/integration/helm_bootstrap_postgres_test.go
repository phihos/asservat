package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
	"github.com/jackc/pgx/v5/pgxpool"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
)

type helmBundledPostgres struct {
	plan       contracts.SmallPostgresPlan
	image      string
	state      *core.Secret
	pvcs       map[string]types.UID
	postmaster time.Time
}

// Two empty local PVs belong only to the fresh owned Kind node. The product's
// prepare hook creates its original material before Helm creates either PVC.
func newHelmBundledPostgres(t *testing.T, ctx context.Context, api kubernetes.Interface, d contracts.InitialBootstrap, x helmBootstrapFixture) *helmBundledPostgres {
	t.Helper()
	if x.PostgresImage == "" || !strings.Contains(x.PostgresImage, "@sha256:") {
		t.Fatal("resolved qualified PostgreSQL image unavailable")
	}
	p := contracts.SmallPostgresPlan{Format: contracts.SmallPostgresFormat, Namespace: d.BootstrapNamespace, Name: d.Name}
	node, err := api.CoreV1().Nodes().Get(ctx, x.NodeA, meta.GetOptions{})
	if err != nil || string(node.UID) != x.NodeAUID || node.Labels[core.LabelHostname] == "" {
		t.Fatal("owned PostgreSQL PV node changed")
	}
	for _, kind := range []string{"data", "backup"} {
		directory := "/var/local/asservat-bundled-postgres/" + p.Namespace + "/" + p.Name + "/" + kind
		if err := exec.CommandContext(ctx, "docker", "exec", x.NodeA, "test", "!", "-e", directory).Run(); err != nil {
			t.Fatal("owned PostgreSQL backing was not empty original absence")
		}
		if out, err := exec.CommandContext(ctx, "docker", "exec", x.NodeA, "install", "-d", "-m", "0700", "-o", "999", "-g", "999", directory).CombinedOutput(); err != nil {
			t.Fatalf("owned PostgreSQL backing creation: %v %s", err, out)
		}
		claim := p.DataPVCName()
		if kind == "backup" {
			claim = p.BackupPVCName()
		}
		pv, err := api.CoreV1().PersistentVolumes().Create(ctx, &core.PersistentVolume{ObjectMeta: meta.ObjectMeta{Name: p.Namespace + "-postgres-" + kind, Labels: map[string]string{"asservat.test.owner": p.Namespace}}, Spec: core.PersistentVolumeSpec{Capacity: core.ResourceList{core.ResourceStorage: resource.MustParse("64Gi")}, AccessModes: []core.PersistentVolumeAccessMode{core.ReadWriteOnce}, PersistentVolumeReclaimPolicy: core.PersistentVolumeReclaimRetain, StorageClassName: "asservat-owned-local", ClaimRef: &core.ObjectReference{Namespace: p.Namespace, Name: claim}, PersistentVolumeSource: core.PersistentVolumeSource{Local: &core.LocalVolumeSource{Path: directory}}, NodeAffinity: &core.VolumeNodeAffinity{Required: &core.NodeSelector{NodeSelectorTerms: []core.NodeSelectorTerm{{MatchExpressions: []core.NodeSelectorRequirement{{Key: core.LabelHostname, Operator: core.NodeSelectorOpIn, Values: []string{node.Labels[core.LabelHostname]}}}}}}}}}, meta.CreateOptions{})
		if err != nil {
			t.Fatal("owned PostgreSQL local PV", err)
		}
		t.Cleanup(func() {
			if keepFailedFixture(t) {
				return
			}
			cleanup, end := context.WithTimeout(context.Background(), 60*time.Second)
			defer end()
			got, err := api.CoreV1().PersistentVolumes().Get(cleanup, pv.Name, meta.GetOptions{})
			if apierrors.IsNotFound(err) {
				return
			}
			if err != nil || got.UID != pv.UID || got.Labels["asservat.test.owner"] != p.Namespace {
				t.Error("PostgreSQL PV cleanup identity", err)
				return
			}
			if err := api.CoreV1().PersistentVolumes().Delete(cleanup, pv.Name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &pv.UID}}); err != nil && !apierrors.IsNotFound(err) {
				t.Error("owned PostgreSQL PV cleanup", err)
			}
		})
	}
	return &helmBundledPostgres{plan: p, image: x.PostgresImage, pvcs: map[string]types.UID{}}
}
func (p *helmBundledPostgres) Values(values map[string]any) {
	services, ok := values["services"].(map[string]any)
	if !ok {
		services = map[string]any{}
		values["services"] = services
	}
	services["postgres"] = map[string]any{"provider": "bundled", "bundled": map[string]any{"image": p.image, "storageClass": "asservat-owned-local", "dataSize": "64Gi", "backupSize": "64Gi"}}
}

// Only fixture readback receives the actual retained generated administrator.
// Product inputs use the chart's selected PG-state projections, never f.Postgres.
// A temporary NodePort changes the transport address, while TLS verifies the
// original Service DNS identity and actual generated public CA.
func (p *helmBundledPostgres) Resolve(t *testing.T, ctx context.Context, api kubernetes.Interface, input *contracts.InitialBootstrapInput, node *core.Node, kubeconfig string) *pgxpool.Pool {
	t.Helper()
	state, err := api.CoreV1().Secrets(p.plan.Namespace).Get(ctx, p.plan.StateSecretName(), meta.GetOptions{})
	if err != nil || state.Immutable == nil || !*state.Immutable || kube.ValidateSmallPostgresMaterial(p.plan, state.Data, time.Now()) != nil {
		t.Fatal("actual original generated PostgreSQL state unavailable")
	}
	p.state = state.DeepCopy()
	t.Cleanup(func() {
		for _, raw := range p.state.Data {
			clear(raw)
		}
	})
	input.Postgres = contracts.InitialBootstrapPostgresInput{Host: p.plan.Host(), Port: 5432, Database: "asservat", MaxConnections: 2, RootsPEM: string(state.Data["ca.crt"])}
	c, err := contracts.DecodeOwnerSQLCredential(bytes.NewReader(state.Data["postgres-administrator.json"]))
	if err != nil || c.Username != "asservat_admin" {
		t.Fatal("actual generated PostgreSQL administrator malformed")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(state.Data["ca.crt"]) {
		t.Fatal("actual PostgreSQL roots malformed")
	}
	for _, raw := range state.Data {
		clear(raw)
	}
	service, err := api.CoreV1().Services(p.plan.Namespace).Create(ctx, &core.Service{ObjectMeta: meta.ObjectMeta{Name: p.plan.ServiceName() + "-inspection", Labels: map[string]string{"asservat.test.owner": p.plan.Namespace}}, Spec: core.ServiceSpec{Type: core.ServiceTypeNodePort, Selector: map[string]string{"asservat.io/postgres": p.plan.ServiceName()}, Ports: []core.ServicePort{{Name: "postgres", Port: 5432, TargetPort: intstr.FromInt32(5432)}}}}, meta.CreateOptions{})
	if err != nil || len(service.Spec.Ports) != 1 || service.Spec.Ports[0].NodePort == 0 {
		t.Fatal("owned PostgreSQL inspection transport unavailable")
	}
	address := ""
	for _, a := range node.Status.Addresses {
		if a.Type == core.NodeInternalIP {
			address = a.Address
		}
	}
	if address == "" {
		t.Fatal("owned PostgreSQL inspection node address unavailable")
	}
	config, err := pgxpool.ParseConfig("host=" + address + " port=" + strconv.Itoa(int(service.Spec.Ports[0].NodePort)) + " dbname=asservat user=asservat_admin sslmode=require")
	if err != nil {
		t.Fatal("generated PostgreSQL readback config")
	}
	config.ConnConfig.Password = c.Password
	config.ConnConfig.TLSConfig = &tls.Config{RootCAs: roots, ServerName: p.plan.Host(), MinVersion: tls.VersionTLS13}
	config.ConnConfig.Fallbacks = nil
	config.MaxConns = 1
	admin, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal("actual bundled PostgreSQL readback pool")
	}
	t.Cleanup(admin.Close)
	var user, database, version, maximum string
	var superuser, createRole bool
	if err = admin.QueryRow(ctx, "SELECT current_user,current_database(),current_setting('server_version'),current_setting('max_connections'),pg_postmaster_start_time(),rolsuper,rolcreaterole FROM pg_roles WHERE rolname=current_user").Scan(&user, &database, &version, &maximum, &p.postmaster, &superuser, &createRole); err != nil || user != "asservat_admin" || database != "asservat" || !strings.HasPrefix(version, "18.6") || maximum != "117" || !superuser || !createRole {
		t.Fatal("actual bundled PostgreSQL identity/version/budget mismatch")
	}
	pod, err := api.CoreV1().Pods(p.plan.Namespace).Get(ctx, p.plan.ServiceName()+"-0", meta.GetOptions{})
	if err != nil || pod.Spec.NodeName != node.Name || pod.Status.Phase != core.PodRunning || len(pod.Spec.Containers) != 2 {
		t.Fatal("actual chart PostgreSQL Pod unavailable")
	}
	for _, container := range pod.Spec.Containers {
		if container.Image != p.image {
			t.Fatal("PostgreSQL chart used another image")
		}
	}
	output, err := exec.CommandContext(ctx, "kubectl", "--kubeconfig", kubeconfig, "--request-timeout=15s", "-n", p.plan.Namespace, "exec", pod.Name, "-c", "backup", "--", "pgbackrest", "--config=/run/asservat/postgres/pgbackrest.conf", "--stanza=asservat", "--output=json", "info").CombinedOutput()
	if err != nil {
		t.Fatal("actual bundled encrypted backup metadata unavailable")
	}
	var info []struct {
		Name   string `json:"name"`
		Cipher string `json:"cipher"`
		Status struct {
			Code int `json:"code"`
		} `json:"status"`
		Backups []struct {
			Type string `json:"type"`
		} `json:"backup"`
	}
	if json.Unmarshal(output, &info) != nil || len(info) != 1 || info[0].Name != "asservat" || info[0].Cipher != "aes-256-cbc" || info[0].Status.Code != 0 || len(info[0].Backups) < 1 || info[0].Backups[0].Type != "full" {
		t.Fatal("first encrypted pgBackRest full backup was not acknowledged")
	}
	p.VerifyRetention(t, ctx, api)
	return admin
}
func (p *helmBundledPostgres) VerifyReplay(t *testing.T, ctx context.Context, api kubernetes.Interface, admin *pgxpool.Pool) {
	t.Helper()
	p.VerifyRetention(t, ctx, api)
	var started time.Time
	if err := admin.QueryRow(ctx, "SELECT pg_postmaster_start_time()").Scan(&started); err != nil || !started.Equal(p.postmaster) {
		t.Fatal("hook replay changed PostgreSQL incarnation")
	}
}
func (p *helmBundledPostgres) VerifyRetention(t *testing.T, ctx context.Context, api kubernetes.Interface) {
	t.Helper()
	state, err := api.CoreV1().Secrets(p.plan.Namespace).Get(ctx, p.plan.StateSecretName(), meta.GetOptions{})
	if err != nil || p.state == nil || state.UID != p.state.UID || state.ResourceVersion != p.state.ResourceVersion || !reflect.DeepEqual(state.Data, p.state.Data) {
		t.Fatal("replay/uninstall changed generated PostgreSQL credentials")
	}
	for _, raw := range state.Data {
		clear(raw)
	}
	for _, name := range []string{p.plan.DataPVCName(), p.plan.BackupPVCName()} {
		pvc, err := api.CoreV1().PersistentVolumeClaims(p.plan.Namespace).Get(ctx, name, meta.GetOptions{})
		if err != nil || pvc.Status.Phase != core.ClaimBound || pvc.Spec.VolumeName == "" || pvc.Annotations["helm.sh/resource-policy"] != "keep" {
			t.Fatal("retained PostgreSQL data/backup PVC missing")
		}
		if old, known := p.pvcs[name]; known && old != pvc.UID {
			t.Fatal("PostgreSQL PVC replaced on replay")
		}
		p.pvcs[name] = pvc.UID
	}
}

func (p *helmBundledPostgres) VerifySchema(t *testing.T, ctx context.Context, admin *pgxpool.Pool, schema contracts.InitialPreparationSchema) {
	t.Helper()
	var database, owner uint32
	var ddl string
	var super, createRole bool
	if err := admin.QueryRow(ctx, `SELECT d.oid,d.datdba,r.rolname,r.rolsuper,r.rolcreaterole FROM pg_database d JOIN pg_roles r ON r.oid=d.datdba WHERE d.datname=current_database()`).Scan(&database, &owner, &ddl, &super, &createRole); err != nil || database != schema.DatabaseOID || owner != schema.DDLRole.OID || ddl != "asservat_ddl" || schema.DDLRole.Name != ddl || schema.DDLRole.OID == schema.Manager.OID || super || createRole || !schema.PostmasterAt.Equal(p.postmaster) {
		t.Fatal("actual schema was not initialized by the separate generated non-superuser DDL role in original database incarnation")
	}
}
